'use strict';

const os = require('os');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const MessageHandler = require('wildduck/lib/message-handler');
const UserHandler = require('wildduck/lib/user-handler');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const SRS = require('srs.js');

module.exports.title = 'Wild Duck MSA';
module.exports.init = function(app, done) {
    const users = new WeakMap();

    const redisClient = app.db.redis;
    const database = app.db.database;
    const usersdb = app.db.users;
    const gridfsdb = app.db.gridfs;

    const ttlcounter = counters(redisClient).ttlcounter;

    const srsRewriter = new SRS({
        secret: app.config.secret || '?'
    });

    const messageHandler = new MessageHandler({
        database,
        redis: redisClient,
        users: usersdb,
        gridfs: gridfsdb,
        attachments: app.config.attachments || {
            type: 'gridstore',
            bucket: 'attachments'
        }
    });

    const userHandler = new UserHandler({
        database,
        redis: redisClient,
        gridfs: gridfsdb,
        users: usersdb,
        authlogExpireDays: app.config.authlogExpireDays
    });

    const interfaces = [].concat(app.config.interfaces || '*');
    const allInterfaces = interfaces.includes('*');

    // handle user authentication
    app.addHook('smtp:auth', (auth, session, next) => {
        if (!checkInterface(session.interface)) {
            return next();
        }

        userHandler.authenticate(
            auth.username,
            auth.password,
            'smtp',
            {
                protocol: 'SMTP',
                ip: session.remoteAddress
            },
            (err, result) => {
                if (err) {
                    return next(err);
                }
                if (!result || (result.scope === 'master' && result.require2fa)) {
                    let message = 'Authentication failed';
                    if (result) {
                        message = 'You need to use an application specific password';
                    }
                    err = new Error(message);
                    err.responseCode = 535;
                    err.name = 'SMTPResponse'; // do not throw
                    return next(err);
                }

                auth.username = result.username;
                next();
            }
        );
    });

    // Check if an user is allowed to use specific address, if not then override using the default
    app.addHook('message:headers', (envelope, messageInfo, next) => {
        if (!checkInterface(envelope.interface)) {
            return next();
        }

        // Check From: value. Add if missing or rewrite if needed
        let headerFrom = envelope.headers.getFirst('from');
        let headerFromList;
        let headerFromObj;

        if (headerFrom) {
            headerFromList = addressparser(headerFrom);
            if (headerFromList.length) {
                headerFromObj = headerFromList[0] || {};
                if (headerFromObj.group) {
                    headerFromObj = {};
                }
            }
        }

        getUser(envelope, (err, userData) => {
            if (err) {
                return next(err);
            }

            let normalizedAddress;

            normalizedAddress = tools.normalizeAddress(envelope.from);
            normalizedAddress =
                normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') + normalizedAddress.substr(normalizedAddress.indexOf('@'));

            usersdb.collection('addresses').findOne(
                {
                    $or: [{ addrview: normalizedAddress }, { addrview: '*' + normalizedAddress.substr(normalizedAddress.indexOf('@')) }],
                    user: userData._id
                },
                (err, addressData) => {
                    if (err) {
                        return next(err);
                    }

                    if (!addressData) {
                        // replace MAIL FROM address
                        app.logger.info(
                            'Rewrite',
                            '%s RWENVELOPE User %s tries to use "%s" as Return Path address, replacing with "%s"',
                            envelope.id,
                            userData.username,
                            envelope.from + (envelope.from === normalizedAddress ? '' : '[' + normalizedAddress + ']'),
                            userData.address
                        );
                        envelope.from = userData.address;
                    }

                    if (!headerFromObj) {
                        return next();
                    }

                    normalizedAddress = tools.normalizeAddress(Buffer.from(headerFromObj.address, 'binary').toString());
                    normalizedAddress =
                        normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') +
                        normalizedAddress.substr(normalizedAddress.indexOf('@'));

                    if (addressData && addressData.addrview === normalizedAddress) {
                        // same address
                        return next();
                    }

                    usersdb.collection('addresses').findOne(
                        {
                            $or: [{ addrview: normalizedAddress }, { addrview: '*' + normalizedAddress.substr(normalizedAddress.indexOf('@')) }],
                            user: userData._id
                        },
                        (err, addressData) => {
                            if (err) {
                                return next(err);
                            }

                            if (addressData) {
                                // can send mail as this user
                                return next();
                            }

                            app.logger.info(
                                'Rewrite',
                                '%s RWFROM User %s tries to use "%s" as From address, replacing with "%s"',
                                envelope.id,
                                userData.username,
                                headerFromObj.address + (headerFromObj.address === normalizedAddress ? '' : '[' + normalizedAddress + ']'),
                                envelope.from
                            );

                            headerFromObj.address = envelope.from;

                            let rootNode = new MimeNode();
                            let newHeaderFrom = rootNode._convertAddresses([headerFromObj]);

                            envelope.headers.update('From', newHeaderFrom);
                            envelope.headers.update('X-WildDuck-Original-From', headerFrom);

                            next();
                        }
                    );
                }
            );
        });
    });

    // Check if the user can send to yet another recipient
    app.addHook('smtp:rcpt_to', (address, session, next) => {
        if (!checkInterface(session.interface)) {
            return next();
        }
        getUser(session, (err, userData) => {
            if (err) {
                return next(err);
            }

            if (!userData.recipients) {
                return next();
            }

            ttlcounter('wdr:' + userData._id.toString(), 1, userData.recipients, false, (err, result) => {
                if (err) {
                    return next(err);
                }

                let success = result.success;
                let sent = result.value;
                let ttl = result.ttl;

                let ttlHuman = false;
                if (ttl) {
                    if (ttl < 60) {
                        ttlHuman = ttl + ' seconds';
                    } else if (ttl < 3600) {
                        ttlHuman = Math.round(ttl / 60) + ' minutes';
                    } else {
                        ttlHuman = Math.round(ttl / 3600) + ' hours';
                    }
                }

                if (!success) {
                    app.logger.info(
                        'Sender',
                        '%s RCPTDENY denied %s sent=%s allowed=%s expires=%ss.',
                        session.envelopeId,
                        address.address,
                        sent,
                        userData.recipients,
                        ttl
                    );
                    let err = new Error('You reached a daily sending limit for your account' + (ttl ? '. Limit expires in ' + ttlHuman : ''));
                    err.responseCode = 550;
                    err.name = 'SMTPResponse';
                    return setImmediate(() => next(err));
                }

                app.logger.info('Sender', '%s RCPTACCEPT accepted %s sent=%s allowed=%s', session.envelopeId, address.address, sent, userData.recipients);
                next();
            });
        });
    });

    // Check if an user is allowed to use specific address, if not then override using the default
    app.addHook('message:queue', (envelope, messageInfo, next) => {
        if (!checkInterface(envelope.interface)) {
            return next();
        }

        getUser(envelope, (err, userData) => {
            if (err) {
                return next(err);
            }

            if (userData.quota && userData.storageUsed > userData.quota) {
                // skip upload, not enough storage
                app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=over quota', envelope.id, envelope.user);
                return next();
            }

            let chunks = [
                Buffer.from('Return-Path: ' + envelope.from + '\r\n' + generateReceivedHeader(envelope, app.config.hostname || os.hostname()) + '\r\n'),
                envelope.headers.build()
            ];
            let chunklen = chunks[0].length + chunks[1].length;

            let body = app.manager.queue.gridstore.openDownloadStreamByName('message ' + envelope.id);
            body.on('readable', () => {
                let chunk;
                while ((chunk = body.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });
            body.once('error', err => next(err));
            body.once('end', () => {
                // Next we try to upload the message to Sent Mail folder
                // It doesn't really matter if it succeeds or not so we are not waiting until it's done
                setImmediate(next);

                let raw = Buffer.concat(chunks, chunklen);

                // Checks if the message needs to be encrypted before storing it
                messageHandler.encryptMessage(userData.encryptMessages ? userData.pubKey : false, raw, (err, encrypted) => {
                    if (!err && encrypted) {
                        // message was encrypted, so use the result instead of raw
                        raw = encrypted;
                    }

                    messageHandler.add(
                        {
                            user: userData._id,
                            specialUse: '\\Sent',

                            outbound: envelope.id,

                            meta: {
                                source: 'SMTP',
                                from: envelope.from,
                                to: envelope.to,
                                origin: envelope.origin,
                                originhost: envelope.originhost,
                                transhost: envelope.transhost,
                                transtype: envelope.transtype,
                                time: new Date()
                            },

                            date: false,
                            flags: ['\\Seen'],
                            raw,

                            // if similar message exists, then skip
                            skipExisting: true
                        },
                        (err, success, info) => {
                            if (err) {
                                app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message);
                            } else if (info) {
                                app.logger.info('Rewrite', '%s MSAUPLSUCC user=%s uid=%s', envelope.id, envelope.user, info.uid);
                            } else {
                                app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=already exists', envelope.id, envelope.user);
                            }
                        }
                    );
                });
            });
        });
    });

    // rewrite MAIL FROM: for messages forwarded by user filter
    app.addHook('sender:headers', (delivery, connection, next) => {
        if (!app.config.forwardedSRS || !delivery.envelope.from || delivery.interface !== 'forwarder' || delivery.skipSRS) {
            return next();
        }

        let from = delivery.envelope.from || '';

        let normalizedAddress = tools.normalizeAddress(from);
        normalizedAddress =
            normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') + normalizedAddress.substr(normalizedAddress.indexOf('@'));

        usersdb.collection('addresses').findOne(
            {
                addrview: normalizedAddress
            },
            (err, addressData) => {
                if (err) {
                    return next(err);
                }

                if (!addressData) {
                    // sender is not a local address, so use SRS rewriting
                    let fromDomain = from.substr(from.lastIndexOf('@') + 1).toLowerCase();
                    let srsDomain = app.config.rewriteDomain;
                    try {
                        delivery.envelope.from = srsRewriter.rewrite(from.substr(0, from.lastIndexOf('@')), fromDomain) + '@' + srsDomain;
                        delivery.headers.add('X-Original-Sender', from, Infinity);
                    } catch (E) {
                        // failed rewriting address, keep as is
                        app.logger.error('SRS', '%s.%s SRSFAIL Failed rewriting "%s". %s', delivery.id, delivery.seq, from, E.message);
                    }
                }

                delivery.headers.add('X-Zone-Forwarded-For', from, Infinity);
                delivery.headers.add('X-Zone-Forwarded-To', delivery.envelope.to, Infinity);

                next();
            }
        );
    });

    app.addHook('log:entry', (entry, next) => {
        entry.created = new Date();
        database.collection('messagelog').insertOne(entry, () => next());
    });

    function checkInterface(iface) {
        if (allInterfaces || interfaces.includes(iface)) {
            return true;
        }
        return false;
    }

    function getUser(envelope, callback) {
        let query = false;

        if (users.has(envelope)) {
            // user data is already cached
            return callback(null, users.get(envelope));
        }

        if (envelope.user) {
            query = {
                username: envelope.user
            };
        }

        if (!query) {
            let err = new Error('Insufficient user info');
            err.responseCode = 550;
            err.name = 'SMTPResponse'; // do not throw
            return callback(err);
        }

        usersdb.collection('users').findOne(
            query,
            {
                fields: {
                    username: true,
                    address: true,
                    quota: true,
                    storageUsed: true,
                    recipients: true,
                    encryptMessages: true,
                    pubKey: true
                }
            },
            (err, user) => {
                if (err) {
                    return callback(err);
                }

                if (!user) {
                    let err = new Error('User "' + query.username + '" was not found');
                    err.responseCode = 550;
                    err.name = 'SMTPResponse'; // do not throw
                    return callback(err);
                }

                users.set(envelope, user);

                return callback(null, user);
            }
        );
    }

    if (app.config.localMx) {
        app.addHook('sender:fetch', (delivery, next) => {
            let normalizedAddress;

            normalizedAddress = tools.normalizeAddress(delivery.envelope.to);
            normalizedAddress =
                normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') + normalizedAddress.substr(normalizedAddress.indexOf('@'));

            usersdb.collection('addresses').findOne(
                {
                    addrview: normalizedAddress
                },
                (err, addressData) => {
                    if (err) {
                        return next(err);
                    }
                    if (!addressData) {
                        // remote recipient
                        return next();
                    }
                    // local recipient

                    delivery.mx = [].concat(app.config.localMx || []);
                    delivery.mxPort = app.config.localMxPort;
                    delivery.useLMTP = app.config.localLmtp;
                    delivery.zoneAddress = app.config.localZoneAddress;
                    next();
                }
            );
        });
    }

    done();
};

function generateReceivedHeader(envelope, hostname) {
    let key = 'Received';
    let origin = envelope.origin ? '[' + envelope.origin + ']' : '';
    let originhost = envelope.originhost && envelope.originhost.charAt(0) !== '[' ? envelope.originhost : false;
    origin = [].concat(origin || []).concat(originhost || []);

    if (origin.length > 1) {
        origin = '(' + origin.join(' ') + ')';
    } else {
        origin = origin.join(' ').trim() || 'localhost';
    }

    let value =
        '' +
        // from ehlokeyword
        'from' +
        (envelope.transhost ? ' ' + envelope.transhost : '') +
        // [1.2.3.4]
        ' ' +
        origin +
        (originhost ? '\r\n' : '') +
        // (Authenticated sender: username)
        (envelope.user ? ' (Authenticated sender: ' + envelope.user + ')\r\n' : !originhost ? '\r\n' : '') +
        // by smtphost
        ' by ' +
        hostname +
        // with ESMTP
        ' with ' +
        envelope.transtype +
        // id 12345678
        ' id ' +
        envelope.id +
        // for <receiver@example.com>
        (envelope.to.length === 1 ? '\r\n for <' + envelope.to[0] + '>' : '') +
        // (version=TLSv1/SSLv3 cipher=ECDHE-RSA-AES128-GCM-SHA256)
        (envelope.tls ? '\r\n (version=' + envelope.tls.version + ' cipher=' + envelope.tls.name + ')' : '') +
        ';' +
        '\r\n' +
        // Wed, 03 Aug 2016 11:32:07 +0000
        ' ' +
        new Date(envelope.time).toUTCString().replace(/GMT/, '+0000');
    return key + ': ' + value;
}

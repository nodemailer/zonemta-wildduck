'use strict';

const os = require('os');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const MessageHandler = require('wildduck/lib/message-handler');
const UserHandler = require('wildduck/lib/user-handler');
const DkimHandler = require('wildduck/lib/dkim-handler');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const SRS = require('srs.js');
const Gelf = require('gelf');

module.exports.title = 'WildDuck MSA';
module.exports.init = function(app, done) {
    const users = new WeakMap();

    const redisClient = app.db.redis;
    const database = app.db.database;
    const usersdb = app.db.users;
    const gridfsdb = app.db.gridfs;

    const component = ((app.config.gelf && app.config.gelf.component) || 'mta').toUpperCase();
    const hostname = app.config.hostname || os.hostname();
    const gelf =
        app.config.gelf && app.config.gelf.enabled
            ? new Gelf(app.config.gelf.options)
            : {
                  // placeholder
                  emit: () => false
              };

    const loggelf = message => {
        if (typeof message === 'string') {
            message = {
                short_message: message
            };
        }
        message = message || {};
        message.facility = app.config.gelf.component || 'mta'; // facility is deprecated but set by the driver if not provided
        message.host = hostname;
        message.timestamp = Date.now() / 1000;
        message._component = app.config.gelf.component || 'mta';
        Object.keys(message).forEach(key => {
            if (!message[key]) {
                delete message[key];
            }
        });
        gelf.emit('gelf.log', message);
    };

    const dkimHandler = new DkimHandler({
        cipher: app.config.dkim && app.config.dkim.cipher,
        secret: app.config.dkim && app.config.dkim.secret,
        database: app.db.database,
        loggelf: message => loggelf(message)
    });

    const ttlcounter = counters(redisClient).ttlcounter;

    const srsRewriter = new SRS({
        secret: (app.config.srs && app.config.srs.secret) || '?'
    });

    const messageHandler = new MessageHandler({
        database,
        redis: redisClient,
        users: usersdb,
        gridfs: gridfsdb,
        attachments: app.config.attachments || {
            type: 'gridstore',
            bucket: 'attachments'
        },
        loggelf: message => loggelf(message)
    });

    const userHandler = new UserHandler({
        database,
        redis: redisClient,
        gridfs: gridfsdb,
        users: usersdb,
        authlogExpireDays: app.config.authlogExpireDays,
        loggelf: message => loggelf(message)
    });

    const interfaces = [].concat(app.config.interfaces || '*');
    const allInterfaces = interfaces.includes('*');

    // handle user authentication
    app.addHook('smtp:auth', (auth, session, next) => {
        if (!checkInterface(session.interface)) {
            return next();
        }

        if (auth.method === 'XCLIENT') {
            // special proxied connection where authentication is handled upstream
            // XCLIENT is only available if smtp server has useXClient option set to true
            return userHandler.get(auth.username, { username: true }, (err, userData) => {
                if (err) {
                    return next(err);
                }
                if (!userData) {
                    let message = 'Authentication failed';
                    err = new Error(message);
                    err.responseCode = 535;
                    err.name = 'SMTPResponse'; // do not throw

                    loggelf({
                        short_message: component + ' SMTP [AUTH FAIL:' + auth.username + '] ' + session.id,

                        _auth_fail: 'yes',
                        _mail_action: 'auth',
                        _username: auth.username,
                        _xclient: 'yes',

                        _session_id: session.id,
                        _ip: session.remoteAddress
                    });

                    return next(err);
                }

                auth.username = userData.username;
                next();
            });
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

                    loggelf({
                        short_message: component + ' SMTP [AUTH FAIL:' + auth.username + '] ' + session.id,

                        _auth_fail: 'yes',
                        _mail_action: 'auth',
                        _username: auth.username,
                        _require_asp: result ? 'yes' : '',

                        _session_id: session.id,
                        _ip: session.remoteAddress
                    });

                    return next(err);
                }

                loggelf({
                    short_message: component + ' SMTP [AUTH OK:' + auth.username + '] ' + session.id,

                    _auth_ok: 'yes',
                    _mail_action: 'auth',
                    _username: auth.username,
                    _scope: result.scope,

                    _session_id: session.id,
                    _ip: session.remoteAddress
                });

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

            let checkAddress = (address, done) => {
                userHandler.resolveAddress(address, { wildcard: true }, (err, addressData) => {
                    if (err) {
                        return done(err);
                    }

                    if (!addressData) {
                        return done(null, false);
                    }

                    if (addressData.user) {
                        if (addressData.user.toString() === userData._id.toString()) {
                            return done(null, addressData);
                        } else {
                            return done(null, false);
                        }
                    }

                    if (addressData.targets) {
                        if (addressData.targets.find(target => target.user && target.user.toString() === userData._id.toString())) {
                            return done(null, addressData);
                        } else {
                            return done(null, false);
                        }
                    }
                    return done(null, false);
                });
            };

            checkAddress(envelope.from, (err, addressData) => {
                if (err) {
                    return next(err);
                }

                if (!addressData) {
                    loggelf({
                        short_message: component + ' [RWENVELOPE] ' + envelope.id,
                        _mail_action: 'headers',
                        _rw_envelope_from: 'yes',
                        _queue_id: envelope.id,
                        _envelope_from: envelope.from,
                        _rewrite_from: userData.address
                    });

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
                    normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') + normalizedAddress.substr(normalizedAddress.indexOf('@'));

                if (addressData && addressData.addrview === normalizedAddress) {
                    // same address
                    return next();
                }

                checkAddress(Buffer.from(headerFromObj.address, 'binary').toString(), (err, addressData) => {
                    if (err) {
                        return next(err);
                    }

                    if (addressData) {
                        // can send mail as this user
                        return next();
                    }

                    loggelf({
                        short_message: component + ' [RWFROM] ' + envelope.id,
                        _mail_action: 'headers',
                        _rw_header_from: 'yes',
                        _queue_id: envelope.id,
                        _header_from: headerFromObj.address,
                        _rewrite_from: envelope.from
                    });

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
                });
            });
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
                    loggelf({
                        short_message: component + ' [RCPT TO:' + address.address + '] ' + session.id,
                        _to: address.address,
                        _mail_action: 'rcpt_to',
                        _daily: 'yes',
                        _rate_limit: 'yes',
                        _error: 'daily sending limit reached'
                    });

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

                loggelf({
                    short_message: component + ' [RCPT TO:' + address.address + '] ' + session.id,
                    _user: userData._id.toString(),
                    _from: session.envelope.mailFrom && session.envelope.mailFrom.address,
                    _to: address.address,
                    _mail_action: 'rcpt_to',
                    _allowed: 'yes'
                });

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

            if (!userData.uploadSentMessages) {
                return next();
            }

            if (userData.quota && userData.storageUsed > userData.quota) {
                // skip upload, not enough storage
                app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=over quota', envelope.id, envelope.user);
                return next();
            }

            let chunks = [
                Buffer.from('Return-Path: ' + envelope.from + '\r\n' + generateReceivedHeader(envelope, hostname) + '\r\n'),
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

                // from now on use `return;` to end sequence as next() is already called

                if (app.config.disableUploads) {
                    return; // do not upload messages to Sent Mail folder
                }

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
        if (!app.config.srs || !app.config.srs.enabled || !delivery.envelope.from || delivery.interface !== 'forwarder' || delivery.skipSRS) {
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
                    let srsDomain = app.config.srs && app.config.srs.rewriteDomain;
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

    app.addHook('sender:connect', (delivery, options, next) => {
        if (!delivery.dkim.keys) {
            delivery.dkim.keys = [];
        }

        let from = delivery.envelope.from || '';
        let fromDomain = from.substr(from.lastIndexOf('@') + 1);

        let getKey = (domain, done) => {
            dkimHandler.get({ domain }, true, (err, keyData) => {
                if (err) {
                    return done(err);
                }
                if (keyData) {
                    return done(null, keyData);
                }
                dkimHandler.get({ domain: '*' }, true, (err, keyData) => {
                    if (err) {
                        return done(err);
                    }
                    if (keyData) {
                        return done(null, keyData);
                    }
                    return done();
                });
            });
        };

        getKey(fromDomain, (err, keyData) => {
            if (err && err.code !== 'DkimNotFound') {
                app.logger.error('DKIM', '%s.%s DBFAIL Failed loading DKIM key "%s". %s', delivery.id, delivery.seq, fromDomain, err.message);
                return next();
            }

            if (keyData) {
                delivery.dkim.keys.push({
                    domainName: tools.normalizeDomain(fromDomain),
                    keySelector: keyData.selector,
                    privateKey: keyData.privateKey
                });
            }

            if (!app.config.signTransportDomain || delivery.dkim.keys.find(key => key.domainName === delivery.zoneAddress.name)) {
                return next();
            }

            getKey(delivery.zoneAddress.name, (err, keyData) => {
                if (!err && keyData) {
                    delivery.dkim.keys.push({
                        domainName: tools.normalizeDomain(delivery.zoneAddress.name),
                        keySelector: keyData.selector,
                        privateKey: keyData.privateKey
                    });
                }
                return next();
            });
        });
    });

    app.addHook('log:entry', (entry, next) => {
        entry.created = new Date();

        let message = {
            _queue_id: (entry.id || '').toString(),
            _queue_id_seq: (entry.seq || '').toString()
        };

        switch (entry.action) {
            case 'QUEUED':
                message.short_message = component + ' SMTP [QUEUED] ' + entry.id;
                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._queued = 'yes';
                message._message_id = (entry['message-id'] || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');
                message._ip = entry.src;
                message._body_size = entry.body;
                message._spam_score = Number(entry.score) || '';
                message._interface = entry.interface;
                message._proto = entry.transtype;
                break;

            case 'ACCEPTED':
                message.short_message = component + ' SMTP [ACCEPTED] ' + entry.id + '.' + entry.seq;
                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._accepted = 'yes';
                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;
                message._response = entry.response;
                break;

            case 'DEFERRED':
                message.short_message = component + ' SMTP [DEFERRED] ' + entry.id + '.' + entry.seq;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._deferred = 'yes';
                message._zone = entry.zone;

                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;
                break;

            case 'REJECTED':
                message.short_message = component + ' SMTP [REJECTED] ' + entry.id + '.' + entry.seq;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._bounced = 'yes';
                message._zone = entry.zone;

                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;
                break;

            case 'NOQUEUE':
                message.short_message = component + ' SMTP [NOQUEUE] ' + entry.id + '.' + entry.seq;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._dropped = 'yes';
                message._message_id = (entry['message-id'] || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');
                message._ip = entry.src;
                message._body_size = entry.body;
                message._spam_score = Number(entry.score) || '';
                message._interface = entry.interface;
                message._proto = entry.transtype;

                message._response = entry.responseText;
                break;

            case 'DELETED':
                message.short_message = component + ' SMTP [DELETED] ' + entry.id + '.' + entry.seq;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._deleted = 'yes';

                message._response = entry.reason;
                break;

            case 'DROP':
                message.short_message = component + ' SMTP [DROP] ' + entry.id + '.' + entry.seq;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._dropped = 'yes';

                message._response = entry.reason;
                break;
        }

        if (message.short_message) {
            loggelf(message);
        }

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
                projection: {
                    username: true,
                    address: true,
                    quota: true,
                    storageUsed: true,
                    recipients: true,
                    encryptMessages: true,
                    pubKey: true,
                    uploadSentMessages: true
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

'use strict';

const punycode = require('punycode');
const bcrypt = require('bcryptjs');
const os = require('os');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const mongodb = require('mongodb');
const MessageHandler = require('wildduck/lib/message-handler');
const tools = require('wildduck/lib/tools');
const redis = require('redis');
const MongoClient = mongodb.MongoClient;

module.exports.title = 'Wild Duck MSA';
module.exports.init = function (app, done) {

    const users = new WeakMap();
    const redisClient = redis.createClient(tools.redisConfig(app.config.redis));

    const recipientsCounter = `
local increment = tonumber(ARGV[1]) or 0;
local limit = tonumber(ARGV[2]) or 0;
local current = tonumber(redis.call("GET", KEYS[1])) or 0;

if current + increment > limit then
    local ttl = tonumber(redis.call("TTL", KEYS[1])) or 0;
    return {0, current, ttl};
end;

local updated = tonumber(redis.call("INCRBY", KEYS[1], increment));
if current == 0 then
    redis.call("EXPIRE", KEYS[1], 86400);
end;

return {1, updated};
`;

    MongoClient.connect(app.config.mongo, (err, database) => {
        if (err) {
            return done(err);
        }

        const messageHandler = new MessageHandler(database);
        const interfaces = [].concat(app.config.interfaces || '*');
        const allInterfaces = interfaces.includes('*');

        // handle user authentication
        app.addHook('smtp:auth', (auth, session, next) => {
            if (!checkInterface(session.interface)) {
                return next();
            }
            let username = (auth.username || '').toString().toLowerCase().trim();
            let password = auth.password || '';

            database.collection('users').findOne({
                username
            }, {
                fields: {
                    username: true,
                    password: true,
                    recipients: true
                }
            }, (err, user) => {
                if (err) {
                    return next(err);
                }
                if (!user || !bcrypt.compareSync(password, user.password)) {
                    err = new Error('Authentication failed');
                    err.responseCode = 535;
                    return next(err);
                }

                users.set(session, user);

                // consider the authentication as succeeded as we did not get an error
                auth.username = username;
                next();
            });
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

            getUser(envelope, (err, user) => {
                if (err) {
                    return next(err);
                }

                database.collection('addresses').findOne({
                    address: normalizeAddress(envelope.from),
                    user: user._id
                }, (err, addressData) => {

                    if (err) {
                        return next(err);
                    }

                    if (!addressData) {
                        // replace MAIL FROM address
                        app.logger.info('Rewrite', '%s RWENVELOPE User %s tries to use "%s" as Return Path address, replacing with "%s"', envelope.id, user.username, envelope.from, user.address);
                        envelope.from = user.address;
                    }

                    if (!headerFromObj) {
                        return next();
                    }

                    database.collection('addresses').findOne({
                        address: normalizeAddress(headerFromObj.address),
                        user: user._id
                    }, (err, addressData) => {
                        if (err) {
                            return next(err);
                        }

                        if (addressData) {
                            // can send mail as this user
                            return next();
                        }

                        app.logger.info('Rewrite', '%s RWFROM User %s tries to use "%s" as From address, replacing with "%s"', envelope.id, user.username, headerFromObj.address, envelope.from);

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
            if (!checkInterface(session.interface) || !users.has(session)) {
                return next();
            }
            let user = users.get(session);

            if (!user.recipients) {
                return next();
            }

            redisClient.eval(recipientsCounter, 1, 'wdr:' + user._id.toString(), 1, user.recipients, (err, res) => {
                if (err) {
                    return next(err);
                }

                let success = !!(res && res[0] || 0);
                let sent = res && res[1] || 0;
                let ttl = res && res[2] || 0;
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
                    app.logger.info('Sender', '%s RCPTDENY denied %s sent=%s allowed=%s expires=%ss.', session.envelopeId, address.address, sent, user.recipients, ttl);
                    let err = new Error('You reached a daily sending limit for your account' + (ttl ? '. Limit expires in ' + ttlHuman : ''));
                    err.responseCode = 550;
                    err.name = 'SMTPResponse';
                    return setImmediate(() => next(err));
                }

                app.logger.info('Sender', '%s RCPTACCEPT accepted %s sent=%s allowed=%s', session.envelopeId, address.address, sent, user.recipients);
                next();
            });
        });

        // Check if an user is allowed to use specific address, if not then override using the default
        app.addHook('message:queue', (envelope, messageInfo, next) => {
            if (!checkInterface(envelope.interface)) {
                return next();
            }

            getUser(envelope, (err, user) => {
                if (err) {
                    return next(err);
                }

                if (user.quota && user.storageUsed > user.quota) {
                    // skip upload, not enough storage
                    app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=over quota', envelope.id, envelope.user);
                    return next();
                }

                let chunks = [
                    Buffer.from('Return-Path: ' + envelope.from + '\r\n' + generateReceivedHeader(envelope, app.config.hostname || os.hostname()) + '\r\n'),
                    envelope.headers.build()
                ];
                let chunklen = chunks[0].length + chunks[1].length;

                let body = app.manager.queue.gridstore.createReadStream('message ' + envelope.id);
                body.on('readable', () => {
                    let chunk;
                    while ((chunk = body.read()) !== null) {
                        chunks.push(chunk);
                        chunklen += chunk.length;
                    }
                });
                body.once('error', err => next(err));
                body.once('end', () => {
                    setImmediate(next);
                    messageHandler.add({
                        user: user._id,
                        specialUse: '\\Sent',

                        meta: {
                            source: 'SMTP',
                            from: envelope.from,
                            to: envelope.to,
                            origin: envelope.remoteAddress,
                            originhost: envelope.clientHostname,
                            transhost: envelope.hostNameAppearsAs,
                            transtype: envelope.transmissionType,
                            time: Date.now()
                        },

                        date: false,
                        flags: ['\\Seen'],
                        raw: Buffer.concat(chunks, chunklen),

                        // if similar message exists, then skip
                        skipExisting: true
                    }, (err, success, info) => {
                        if (err) {
                            app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message);
                        } else if (info) {
                            app.logger.info('Rewrite', '%s MSAUPLSUCC user=%s uid=%s', envelope.id, envelope.user, info.uid);
                        } else {
                            app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=already exists', envelope.id, envelope.user);
                        }
                    });
                });
            });
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
                return callback(null, users.get(envelope));
            }
            if (envelope.user) {
                query = {
                    username: envelope.user
                };
            }

            if (!query) {
                return callback(new Error('Insufficient user info'));
            }

            database.collection('users').findOne(query, {
                fields: {
                    username: true,
                    address: true,
                    quota: true,
                    storageUsed: true,
                    recipients: true
                }
            }, (err, user) => {
                if (err) {
                    return callback(err);
                }

                if (!user) {
                    return callback(new Error('User "' + query.username + '" was not found'));
                }

                users.set(envelope, user);

                return callback(null, user);
            });
        }

        if (app.config.mx) {
            app.addHook('sender:fetch', (delivery, next) => {
                if (!checkInterface(delivery.interface)) {
                    return next();
                }

                database.collection('addresses').findOne({
                    address: normalizeAddress(delivery.envelope.to)
                }, (err, addressData) => {
                    if (err) {
                        return next(err);
                    }
                    if (!addressData) {
                        // remote recipient
                        return next();
                    }
                    // local recipient

                    delivery.mx = [].concat(app.config.mx || []);
                    delivery.mxPort = app.config.mxPort;
                    delivery.useLMTP = true;
                    next();
                });

            });
        }

        done();
    });
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

    let value = '' +
        // from ehlokeyword
        'from' + (envelope.transhost ? ' ' + envelope.transhost : '') +
        // [1.2.3.4]
        ' ' + origin +
        (originhost ? '\r\n' : '') +

        // (Authenticated sender: username)
        (envelope.user ? ' (Authenticated sender: ' + envelope.user + ')\r\n' : (!originhost ? '\r\n' : '')) +

        // by smtphost
        ' by ' + hostname +
        // with ESMTP
        ' with ' + envelope.transtype +
        // id 12345678
        ' id ' + envelope.id +

        // for <receiver@example.com>
        (envelope.to.length === 1 ? '\r\n for <' + envelope.to[0] + '>' : '') +

        // (version=TLSv1/SSLv3 cipher=ECDHE-RSA-AES128-GCM-SHA256)
        (envelope.tls ? '\r\n (version=' + envelope.tls.version + ' cipher=' + envelope.tls.name + ')' : '') +

        ';' +
        '\r\n' +

        // Wed, 03 Aug 2016 11:32:07 +0000
        ' ' + new Date(envelope.time).toUTCString().replace(/GMT/, '+0000');
    return key + ': ' + value;
}

function normalizeAddress(address, withNames) {
    if (typeof address === 'string') {
        address = {
            address
        };
    }
    if (!address || !address.address) {
        return '';
    }
    let user = address.address.substr(0, address.address.lastIndexOf('@')).
    normalize('NFC').
    replace(/\+.*$/, '').
    toLowerCase().trim();

    let domain = address.address.substr(address.address.lastIndexOf('@') + 1).toLowerCase().trim();
    let addr = user + '@' + punycode.toUnicode(domain);

    if (withNames) {
        return {
            name: address.name || '',
            address: addr
        };
    }

    return addr;
}

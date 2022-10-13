'use strict';

const os = require('os');
const punycode = require('punycode/');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const MessageHandler = require('wildduck/lib/message-handler');
const UserHandler = require('wildduck/lib/user-handler');
const DkimHandler = require('wildduck/lib/dkim-handler');
const AuditHandler = require('wildduck/lib/audit-handler');
const wdErrors = require('wildduck/lib/errors');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const CertHandler = require('wildduck/lib/cert-handler');
const { SettingsHandler } = require('wildduck/lib/settings-handler');
const SRS = require('srs.js');
const Gelf = require('gelf');
const util = require('util');
const libmime = require('libmime');
const dns = require('dns');

module.exports.title = 'WildDuck MSA';
module.exports.init = function (app, done) {
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
                  emit: (ev, entry) => app.logger.info('GELF', JSON.stringify(entry)),
              };
    wdErrors.setGelf(gelf);

    const loggelf = (message) => {
        if (!message) {
            return false;
        }

        if (typeof message === 'string') {
            message = {
                short_message: message,
            };
        }
        message = message || {};

        if (!message.short_message || message.short_message.indexOf(component.toUpperCase()) !== 0) {
            message.short_message = component.toUpperCase() + ' ' + (message.short_message || '');
        }

        message.facility = (app.config.gelf && app.config.gelf.component) || 'mta'; // facility is deprecated but set by the driver if not provided
        message.host = hostname;
        message.timestamp = Date.now() / 1000;
        message._component = (app.config.gelf && app.config.gelf.component) || 'mta';
        Object.keys(message).forEach((key) => {
            if (!message[key]) {
                delete message[key];
            }
        });
        gelf.emit('gelf.log', message);
    };

    const dkimHandler = new DkimHandler({
        cipher: app.config.dkim && app.config.dkim.cipher,
        secret: app.config.dkim && app.config.dkim.secret,
        database,
        loggelf: (message) => loggelf(message),
    });

    const certHandler = new CertHandler({
        cipher: app.config.certs && app.config.certs.cipher,
        secret: app.config.certs && app.config.certs.secret,
        database,
        redis: redisClient,
    });

    const settingsHandler = new SettingsHandler({
        db: database,
    });

    const ttlcounter = counters(redisClient).ttlcounter;

    const srsRewriter = new SRS({
        secret: (app.config.srs && app.config.srs.secret) || '?',
    });

    const messageHandler = new MessageHandler({
        database,
        redis: redisClient,
        users: usersdb,
        gridfs: gridfsdb,
        attachments: app.config.attachments || {
            type: 'gridstore',
            bucket: 'attachments',
        },
        loggelf: (message) => loggelf(message),
    });

    const userHandler = new UserHandler({
        database,
        redis: redisClient,
        gridfs: gridfsdb,
        users: usersdb,
        loggelf: (message) => loggelf(message),
    });

    const auditHandler = new AuditHandler({
        database,
        gridfs: gridfsdb,
        users: usersdb,
        bucket: 'audit',
        loggelf: (message) => loggelf(message),
    });

    const encryptMessage = util.promisify(messageHandler.encryptMessage.bind(messageHandler));
    const prepareMessage = util.promisify(messageHandler.prepareMessage.bind(messageHandler));

    const addMessage = util.promisify((...args) => {
        let callback = args.pop();
        messageHandler.add(...args, (err, status, data) => {
            if (err) {
                return callback(err);
            }
            return callback(null, { status, data });
        });
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
            return userHandler.get(auth.username, { username: true, address: true }, (err, userData) => {
                if (err) {
                    return next(err);
                }
                if (!userData) {
                    let message = 'Authentication failed';
                    err = new Error(message);
                    err.responseCode = 535;
                    err.name = 'SMTPResponse'; // do not throw

                    loggelf({
                        short_message: '[AUTH FAIL:' + auth.username + '] ' + session.id,

                        _auth_fail: 'yes',
                        _mail_action: 'auth',
                        _username: auth.username,
                        _xclient: 'yes',

                        _session_id: session.id,
                        _ip: session.remoteAddress,
                    });

                    return next(err);
                }

                let username = auth.username;
                if (auth.username.indexOf('@') >= 0) {
                    let parts = auth.username.split('@');
                    if (parts.length === 2 && parts[0] && parts[1] && /[\x80-\xff]/.test(parts[1])) {
                        try {
                            username = parts[0] + '@' + punycode.toASCII(parts[1]);
                        } catch (err) {
                            // ignore?
                        }
                    }
                }

                auth.username = userData.username !== username ? userData.username + '[' + username + ']' : userData.username;
                next();
            });
        }

        userHandler.authenticate(
            auth.username,
            auth.password,
            'smtp',
            {
                protocol: 'SMTP',
                ip: session.remoteAddress,
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
                        short_message: '[AUTH FAIL:' + auth.username + '] ' + session.id,

                        _auth_fail: 'yes',
                        _mail_action: 'auth',
                        _username: auth.username,
                        _require_asp: result ? 'yes' : '',

                        _session_id: session.id,
                        _ip: session.remoteAddress,
                    });

                    return next(err);
                }

                let username = auth.username;
                if (auth.username.indexOf('@') >= 0) {
                    let parts = auth.username.split('@');
                    if (parts.length === 2 && parts[0] && parts[1] && /[\x80-\xff]/.test(parts[1])) {
                        try {
                            username = parts[0] + '@' + punycode.toASCII(parts[1]);
                        } catch (err) {
                            // ignore?
                        }
                    }
                }

                loggelf({
                    short_message: '[AUTH OK:' + username + '] ' + session.id,

                    _auth_ok: 'yes',
                    _mail_action: 'auth',
                    _username: auth.username,
                    _scope: result.scope,

                    _session_id: session.id,
                    _ip: session.remoteAddress,
                });

                auth.username = result.username !== username ? result.username + '[' + username + ']' : result.username;
                next();
            }
        );
    });

    // use SNI cert if available
    app.addHook('smtp:sni', (servername, data, next) => {
        if (!servername) {
            return next();
        }

        certHandler
            .getContextForServername(
                servername,
                Object.assign({}, (app.config.certs && app.config.certs.tlsOptions) || {}),
                {
                    source: 'smtp',
                },
                {
                    loggelf: (message) => loggelf(message),
                }
            )
            .then((ctx) => {
                data.secureContext = ctx;
                next(null);
            })
            .catch((err) => next(err));
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
        let headerFromName;

        if (headerFrom) {
            headerFromList = addressparser(headerFrom);
            if (headerFromList.length) {
                headerFromObj = headerFromList[0] || {};
                if (headerFromObj.group) {
                    headerFromObj = {};
                }
                if (headerFromObj.name) {
                    try {
                        headerFromName = libmime.decodeWords(headerFromObj.name).trim();
                    } catch (err) {
                        headerFromName = headerFromObj.name;
                    }
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
                if (userData.fromWhitelist && userData.fromWhitelist.length) {
                    let nAddr = tools.normalizeAddress(address, false, {
                        removeLabel: true,
                        removeDots: true,
                    });

                    if (
                        userData.fromWhitelist.some((addr) => {
                            addr = tools.normalizeAddress(addr, false, {
                                removeLabel: true,
                                removeDots: true,
                            });

                            if (addr === nAddr) {
                                return true;
                            }

                            if (addr.charAt(0) === '*' && nAddr.indexOf(addr.substr(1)) >= 0) {
                                return true;
                            }

                            if (addr.charAt(addr.length - 1) === '*' && nAddr.indexOf(addr.substr(0, addr.length - 1)) === 0) {
                                return true;
                            }

                            return false;
                        })
                    ) {
                        // generate address object for whitelisted address
                        let normalizedAddress = tools.normalizeAddress(address);
                        normalizedAddress =
                            normalizedAddress.substr(0, normalizedAddress.indexOf('@')).replace(/\./g, '') +
                            normalizedAddress.substr(normalizedAddress.indexOf('@'));

                        return done(null, {
                            address,
                            addrview: normalizedAddress,
                        });
                    }
                }

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
                        if (addressData.targets.find((target) => target.user && target.user.toString() === userData._id.toString())) {
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
                        short_message: '[RWENVELOPE] ' + envelope.id,
                        _mail_action: 'rw_envelope_from',
                        _queue_id: envelope.id,
                        _envelope_from: envelope.from,
                        _rewrite_from: userData.address,
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
                    envelope.from = messageInfo.rwRcptFrom = userData.address;
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
                        short_message: '[RWFROM] ' + envelope.id,
                        _mail_action: 'rw_header_from',
                        _queue_id: envelope.id,
                        _header_from: tools.normalizeAddress(headerFromObj.address),
                        _header_from_value: headerFrom,
                        _header_from_name: headerFromName,
                        _rewrite_from: envelope.from,
                    });

                    app.logger.info(
                        'Rewrite',
                        '%s RWFROM User %s tries to use "%s" as From address, replacing with "%s"',
                        envelope.id,
                        userData.username,
                        headerFromObj.address + (headerFromObj.address === normalizedAddress ? '' : '[' + normalizedAddress + ']'),
                        envelope.from
                    );

                    headerFromObj.address = messageInfo.rwHeaderFrom = envelope.from;

                    let rootNode = new MimeNode();
                    let newHeaderFrom = rootNode._convertAddresses([headerFromObj]);

                    envelope.headers.update('From', newHeaderFrom);
                    envelope.headers.update('X-WildDuck-Original-From', headerFrom);

                    next();
                });
            });
        });
    });

    app.addHook('queue:route', async (envelope, routing) => {
        console.log('HOOK queue:route', envelope, routing);

        let { recipient, deliveryZone } = routing;

        if (deliveryZone !== 'default') {
            return;
        }

        let domain =
            recipient &&
            recipient
                .substring(recipient.indexOf('@') + 1)
                .toLowerCase()
                .trim();
        if (!domain) {
            return;
        }

        try {
            domain = punycode.toASCII(domain);
        } catch (err) {
            // ignore
        }

        try {
            let exchanges = dns.promises.resolveMx(domain);
            if (!exchanges || !exchanges.length) {
                return;
            }

            let mx = exchanges.sort((a, b) => a.priority - b.priority)[0];

            console.log('RECIPIENT DOMAIN', domain, mx);
        } catch (err) {
            // ignore?
        }
    });

    // Check if the user can send to yet another recipient
    app.addHook('smtp:mail_from', (address, session, next) => {
        if (!checkInterface(session.interface)) {
            return next();
        }
        getUser(session, (err, userData) => {
            if (err) {
                return next(err);
            }

            if (!userData.recipients) {
                // no limits, nothing to check for
                return next();
            }

            ttlcounter('wdr:' + userData._id.toString(), 0, userData.recipients, false, (err, result) => {
                if (err) {
                    return next(err);
                }
                session.rcptCounter = result;
                next();
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
                // no limits
                return next();
            }

            let success = session.rcptCounter.success;
            let sent = session.rcptCounter.value + ((session.envelope.rcptTo && session.envelope.rcptTo.length) || 0);
            let ttl = session.rcptCounter.ttl;

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

            if (!success || sent >= userData.recipients) {
                loggelf({
                    short_message: '[RCPT TO:' + address.address + '] ' + session.id,
                    _to: address.address,
                    _mail_action: 'rcpt_to',
                    _allowed: 'no',
                    _daily: 'yes',
                    _rate_limit: 'yes',
                    _error: 'daily sending limit reached',
                    _error_message: 'You reached a daily sending limit for your account' + (ttl ? '. Limit expires in ' + ttlHuman : ''),
                    _user: userData._id.toString(),
                    _from: session.envelope.mailFrom && session.envelope.mailFrom.address,
                    _queue_id: session.envelopeId,
                    _limit_sent: sent,
                    _limit_allowed: userData.recipients,
                    _sess: session.id,
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
                short_message: '[RCPT TO:' + address.address + '] ' + session.id,
                _user: userData._id.toString(),
                _from: session.envelope.mailFrom && session.envelope.mailFrom.address,
                _to: address.address,
                _mail_action: 'rcpt_to',
                _allowed: 'yes',
                _queue_id: session.envelopeId,
                _limit_sent: sent,
                _limit_allowed: userData.recipients,
                _sess: session.id,
            });

            app.logger.info('Sender', '%s RCPTACCEPT accepted %s sent=%s allowed=%s', session.envelopeId, address.address, sent, userData.recipients);
            next();
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

            ttlcounter('wdr:' + userData._id.toString(), envelope.to.length, userData.recipients, false, (/*err, result*/) => {
                // at his point we only update the counter but do not care about the result as message is already queued for delivery

                database
                    .collection('audits')
                    .find({ user: userData._id })
                    .toArray((err, audits) => {
                        if (err) {
                            // ignore
                            audits = [];
                        }

                        let now = new Date();
                        audits = audits.filter((auditData) => {
                            if (auditData.start && auditData.start > now) {
                                return false;
                            }
                            if (auditData.end && auditData.end < now) {
                                return false;
                            }
                            return true;
                        });

                        let overQuota = userData.quota && userData.storageUsed > userData.quota;
                        let addToSent = userData.uploadSentMessages && !overQuota && !app.config.disableUploads;

                        if (overQuota) {
                            // not enough storage
                            app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=over quota', envelope.id, envelope.user);
                            if (!audits.length) {
                                return next();
                            }
                        }

                        if (!addToSent && !audits.length) {
                            // nothing to do here
                            return next();
                        }

                        let chunks = [
                            Buffer.from('Return-Path: ' + envelope.from + '\r\n' + generateReceivedHeader(envelope, hostname) + '\r\n'),
                            envelope.headers.build(),
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
                        body.once('error', (err) => next(err));
                        body.once('end', () => {
                            // Next we try to upload the message to Sent Mail folder
                            // It doesn't really matter if it succeeds or not so we are not waiting until it's done
                            setImmediate(next);

                            // from now on use `return;` to end sequence as next() is already called

                            let raw = Buffer.concat(chunks, chunklen);

                            let storeSentMessage = async () => {
                                // Checks if the message needs to be encrypted before storing it
                                let messageSource = raw;

                                if (userData.encryptMessages && userData.pubKey) {
                                    try {
                                        let encrypted = await encryptMessage(userData.pubKey, raw);
                                        if (encrypted) {
                                            messageSource = encrypted;
                                        }
                                    } catch (err) {
                                        // ignore
                                    }
                                }
                                try {
                                    let { data } = await addMessage({
                                        user: userData._id,
                                        specialUse: '\\Sent',

                                        outbound: envelope.id,

                                        meta: {
                                            source: 'SMTP',
                                            queueId: envelope.id,
                                            from: envelope.from,
                                            to: envelope.to,
                                            origin: envelope.origin,
                                            originhost: envelope.originhost,
                                            transhost: envelope.transhost,
                                            transtype: envelope.transtype,
                                            time: new Date(),
                                        },

                                        date: false,
                                        flags: ['\\Seen'],
                                        raw: messageSource,

                                        // if similar message exists, then skip
                                        skipExisting: true,
                                    });
                                    if (data) {
                                        app.logger.info('Rewrite', '%s MSAUPLSUCC user=%s uid=%s', envelope.id, envelope.user, data.uid);
                                    } else {
                                        app.logger.info('Rewrite', '%s MSAUPLSKIP user=%s message=already exists', envelope.id, envelope.user);
                                    }
                                } catch (err) {
                                    app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message);
                                }
                            };

                            let processAudits = async () => {
                                const messageData = await prepareMessage({
                                    raw,
                                });

                                if (messageData.attachments && messageData.attachments.length) {
                                    messageData.ha = messageData.attachments.some((a) => !a.related);
                                } else {
                                    messageData.ha = false;
                                }

                                for (let auditData of audits) {
                                    const auditMessage = await auditHandler.store(auditData._id, raw, {
                                        date: now,
                                        msgid: messageData.msgid,
                                        header: messageData.mimeTree && messageData.mimeTree.parsedHeader,
                                        ha: messageData.ha,
                                        info: {
                                            source: 'SMTP',
                                            queueId: envelope.id,
                                            from: envelope.from,
                                            to: envelope.to,
                                            origin: envelope.origin,
                                            originhost: envelope.originhost,
                                            transhost: envelope.transhost,
                                            transtype: envelope.transtype,
                                            time: new Date(),
                                        },
                                    });
                                    app.logger.verbose(
                                        'Rewrite',
                                        '%s AUDITUPL user=%s coll=%s message=%s msgid=%s dst=%s',
                                        envelope.id,
                                        envelope.user,
                                        'Stored message to audit base',
                                        messageData.msgid,
                                        auditMessage
                                    );
                                }
                            };

                            if (addToSent) {
                                // addMessage also calls audit methods
                                storeSentMessage().catch((err) =>
                                    app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message)
                                );
                            } else {
                                processAudits().catch((err) =>
                                    app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message)
                                );
                            }
                        });
                    });
            });
        });
    });

    // rewrite MAIL FROM: for messages forwarded by user filter
    app.addHook('sender:headers', (delivery, connection, next) => {
        // Forwarded header if present
        if (delivery.forwardedFor) {
            delivery.headers.addFormatted('X-Forwarded-For', delivery.forwardedFor, 0);
        }

        if (!app.config.srs || !app.config.srs.enabled || !delivery.envelope.from || delivery.interface !== 'forwarder' || delivery.skipSRS) {
            return next();
        }

        let from = delivery.envelope.from || '';

        let fromDomain = from.substr(from.lastIndexOf('@') + 1).toLowerCase();
        let srsDomain = app.config.srs && app.config.srs.rewriteDomain;
        try {
            delivery.envelope.from = srsRewriter.rewrite(from.substr(0, from.lastIndexOf('@')), fromDomain) + '@' + srsDomain;
            delivery.headers.add('X-Original-Sender', from, Infinity);
        } catch (E) {
            // failed rewriting address, keep as is
            app.logger.error('SRS', '%s.%s SRSFAIL Failed rewriting "%s". %s', delivery.id, delivery.seq, from, E.message);
        }

        delivery.headers.add('X-Zone-Forwarded-For', from, Infinity);
        delivery.headers.add('X-Zone-Forwarded-To', delivery.envelope.to, Infinity);

        next();
    });

    const dkimMarker = new WeakSet();
    const connectionHandler = (delivery, next) => {
        if (dkimMarker.has(delivery)) {
            // do not process DKIM multiple times for the same message
            return next();
        }
        dkimMarker.add(delivery);

        if (!delivery.dkim.keys) {
            delivery.dkim.keys = [];
        }

        let from = (delivery.envelope.from || (delivery.parsedEnvelope && delivery.parsedEnvelope.from) || '').toString();
        let fromDomain = from.substr(from.lastIndexOf('@') + 1);

        let getKey = async (domain) => {
            let keyData;
            try {
                keyData = await dkimHandler.get({ domain }, true);
            } catch (err) {
                if (err.code !== 'DkimNotFound') {
                    throw err;
                }
            }
            if (keyData) {
                return keyData;
            }

            try {
                keyData = await dkimHandler.get({ domain: '*' }, true);
            } catch (err) {
                if (err.code !== 'DkimNotFound') {
                    throw err;
                }
            }

            if (keyData) {
                return keyData;
            }

            return;
        };

        getKey(fromDomain)
            .then((keyData) => {
                if (keyData) {
                    delivery.dkim.keys.push({
                        domainName: tools.normalizeDomain(fromDomain),
                        keySelector: keyData.selector,
                        privateKey: keyData.privateKey,
                    });
                }

                if (!app.config.signTransportDomain || delivery.dkim.keys.find((key) => key.domainName === delivery.zoneAddress.name)) {
                    return next();
                }

                getKey(delivery.zoneAddress.name)
                    .then((keyData) => {
                        if (keyData) {
                            delivery.dkim.keys.push({
                                domainName: tools.normalizeDomain(delivery.zoneAddress.name),
                                keySelector: keyData.selector,
                                privateKey: keyData.privateKey,
                            });
                        }
                        next();
                    })
                    .catch((err) => {
                        app.logger.error(
                            'DKIM',
                            '%s.%s DBFAIL Failed loading DKIM key "%s". %s',
                            delivery.id,
                            delivery.seq,
                            delivery.zoneAddress.name,
                            err.message
                        );
                        next();
                    });
            })
            .catch((err) => {
                app.logger.error('DKIM', '%s.%s DBFAIL Failed loading DKIM key "%s". %s', delivery.id, delivery.seq, fromDomain, err.message);
                next();
            });
    };

    // "old" connection handler called when a connection to MX is being
    app.addHook('sender:connect', (delivery, options, next) => connectionHandler(delivery, next));
    app.addHook('sender:connection', (delivery, connection, next) => connectionHandler(delivery, next));

    app.addHook('log:entry', (entry, next) => {
        entry.created = new Date();

        let message = {
            _queue_id: (entry.id || '').toString(),
            _queue_id_seq: (entry.seq || '').toString(),
        };

        if (entry.rwRcptFrom) {
            message._rewrite_rcpt_from = entry.rwRcptFrom;
        }

        if (entry.rwHeaderFrom) {
            message._rewrite_header_from = entry.rwHeaderFrom;
        }

        if (entry.protocol) {
            message._delivery_protocol = entry.protocol;
        }

        if (entry.httpUrl) {
            message._http_url = entry.httpUrl;
        }

        if (entry.httpResponse && Number(entry.httpResponse)) {
            message._http_response = entry.httpResponse;
        }

        let headerFrom = entry.headerFrom;
        let headerFromList;
        let headerFromObj;
        let headerFromName;

        if (headerFrom) {
            message._header_from_value = headerFrom;
            headerFromList = addressparser(headerFrom);
            if (headerFromList.length) {
                headerFromObj = headerFromList[0] || {};
                if (headerFromObj.group) {
                    headerFromObj = {};
                }
                if (headerFromObj.name) {
                    try {
                        headerFromName = libmime.decodeWords(headerFromObj.name).trim();
                    } catch (err) {
                        headerFromName = headerFromObj.name;
                    }
                    message._header_from_name = headerFromName;
                }
                message._header_from = tools.normalizeAddress(headerFromObj.address);
            }
        }

        let updateAudited = (status, info) => {
            auditHandler
                .updateDeliveryStatus(entry.id, entry.seq, status, info)
                .catch((err) => app.logger.error('Rewrite', '%s.%s LOGERR %s', entry.id, entry.seq, err.message));
        };

        switch (entry.action) {
            case 'QUEUED':
                {
                    let username = (entry.user || entry.auth || '').toString();
                    let match = username.match(/\[([^\]]+)]/);
                    if (match && match[1]) {
                        username = match[1];
                    }
                    message.short_message = `[QUEUED] ${entry.id}`;
                    message._from = (entry.from || '').toString();
                    message._to = (entry.to || '').toString();
                    message._mail_action = 'queued';
                    message._message_id = (entry['message-id'] || entry.messageId || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');
                    message._ip = entry.src;
                    message._body_size = entry.body;
                    message._spam_score = Number(entry.score) || '';
                    message._interface = entry.interface;
                    message._proto = entry.transtype;
                    message._subject = entry.subject;

                    message._authenticated_sender = username;
                }
                break;

            case 'ACCEPTED':
                message.short_message = `[ACCEPTED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;
                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._mail_action = 'accepted';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');
                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('accepted', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip,
                });
                break;

            case 'DEFERRED':
                message.short_message = `[DEFERRED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._mail_action = 'deferred';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');

                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('deferred', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip,
                });
                break;

            case 'REJECTED':
                message.short_message = `[REJECTED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._mail_action = 'bounced';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');

                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('rejected', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip,
                });
                break;

            case 'NOQUEUE':
                message.short_message = `[NOQUEUE] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._mail_action = 'dropped';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().replace(/^[\s<]+|[\s>]+$/g, '');
                message._ip = entry.src;
                message._body_size = entry.body;
                message._spam_score = Number(entry.score) || '';
                message._interface = entry.interface;
                message._proto = entry.transtype;

                message._response = entry.responseText;
                break;

            case 'DELETED':
                message.short_message = `[DELETED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._mail_action = 'dropped';

                message._header_from = headerFromObj.address;
                message._header_from_value = headerFrom;

                message._response = entry.reason;
                break;

            case 'DROP':
                message.short_message = `[DROP] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                for (let key of ['description', 'message-id', 'user', 'score', 'tests']) {
                    if (entry[key]) {
                        let logKey;
                        switch (key) {
                            case 'tests':
                                logKey = 'spam_tests';
                                break;
                            case 'score':
                                logKey = 'spam_score';
                                break;
                            default:
                                logKey = key.replace(/-/g, '_');
                        }

                        message[`_${logKey}`] = entry[key];
                    }
                }

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._mail_action = 'dropped';

                message._response = entry.reason;
                break;
        }

        if (message.short_message) {
            loggelf(message);
        }

        return next();
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
                username: envelope.user.split('[').shift(),
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
                    uploadSentMessages: true,
                    disabled: true,
                    suspended: true,
                    fromWhitelist: true,
                },
            },
            (err, userData) => {
                if (err) {
                    return callback(err);
                }

                if (!userData) {
                    let err = new Error('User "' + query.username + '" was not found');
                    err.responseCode = 550;
                    err.name = 'SMTPResponse'; // do not throw
                    return callback(err);
                }

                if (userData.disabled || userData.suspended) {
                    let err = new Error('User "' + query.username + '" is currently disabled');
                    err.responseCode = 550;
                    err.name = 'SMTPResponse'; // do not throw
                    return callback(err);
                }

                settingsHandler
                    .get('const:max:recipients')
                    .then((maxRecipients) => {
                        userData.recipients = Number(userData.recipients) || app.config.maxRecipients || maxRecipients;

                        users.set(envelope, userData);

                        return callback(null, userData);
                    })
                    .catch((err) => callback(err));
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

    let username = (envelope.user || '').toString();
    let match = username.match(/\[([^\]]+)]/);
    if (match && match[1]) {
        username = match[1];
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
        (envelope.user ? ' (Authenticated sender: ' + username + ')\r\n' : !originhost ? '\r\n' : '') +
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

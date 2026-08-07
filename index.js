'use strict';

const os = require('os');
const punycode = require('punycode.js');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const MessageHandler = require('@zone-eu/wildduck/lib/message-handler');
const UserHandler = require('@zone-eu/wildduck/lib/user-handler');
const DkimHandler = require('@zone-eu/wildduck/lib/dkim-handler');
const AuditHandler = require('@zone-eu/wildduck/lib/audit-handler');
const wdErrors = require('@zone-eu/wildduck/lib/errors');
const counters = require('@zone-eu/wildduck/lib/counters');
const tools = require('@zone-eu/wildduck/lib/tools');
const CertHandler = require('@zone-eu/wildduck/lib/cert-handler');
const { SettingsHandler } = require('@zone-eu/wildduck/lib/settings-handler');
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

    const maxSubjectLineLogLengthBytes = (app.config.gelf && app.config.gelf.subjectLength) || 32766 - 1; // 32766 is max gelf default, do -1 for good measure

    const hostname = app.config.hostname || os.hostname();
    const gelf =
        app.config.gelf && app.config.gelf.enabled
            ? new Gelf(app.config.gelf.options)
            : {
                  // placeholder
                  emit: (ev, entry) => app.logger.info('GELF', JSON.stringify(entry))
              };
    wdErrors.setGelf(gelf);

    const loggelf = message => {
        if (!message) {
            return false;
        }

        if (typeof message === 'string') {
            message = {
                short_message: message
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
        database,
        loggelf: message => loggelf(message)
    });

    const certHandler = new CertHandler({
        cipher: app.config.certs && app.config.certs.cipher,
        secret: app.config.certs && app.config.certs.secret,
        database,
        redis: redisClient,
        users: usersdb,
        acmeConfig: app.config.acme,
        loggelf: message => loggelf(message)
    });

    const settingsHandler = new SettingsHandler({
        db: database
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
        loggelf: message => loggelf(message)
    });

    const auditHandler = new AuditHandler({
        database,
        gridfs: gridfsdb,
        users: usersdb,
        bucket: 'audit',
        loggelf: message => loggelf(message)
    });

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

    const timedRunner = (promise, time) =>
        new Promise((resolve, reject) => {
            let timer = setTimeout(() => {
                let error = new Error('Timeout');
                error.code = 'ETIMEDOUT';
                reject(error);
            }, time);
            promise
                .then(result => {
                    clearTimeout(timer);
                    resolve(result);
                })
                .catch(err => {
                    clearTimeout(timer);
                    reject(err);
                });
        });

    const mxCache = new Map();
    const resolveMx = async domain => {
        if (mxCache.has(domain)) {
            let cached = mxCache.get(domain);
            if (cached.error && cached.updated >= Date.now() - 60 * 60 * 1000) {
                throw cached.error;
            }
            if (cached.value && cached.updated >= Date.now() - 8 * 60 * 60 * 1000) {
                return cached.value;
            }
        }

        try {
            let value = await dns.promises.resolveMx(domain);
            mxCache.set(domain, { value, updated: Date.now() });
            return value;
        } catch (err) {
            mxCache.set(domain, { error: err, updated: Date.now() });
            throw err;
        }
    };

    const regexCache = new Map();

    const comparePattern = (pattern, input) => {
        let regex;
        if (regexCache.has(pattern)) {
            regex = regexCache.get(pattern);
        }

        if (!regex) {
            let escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
            regex = new RegExp(`^${escaped}$`);
            regexCache.set(pattern, regex);
        }

        return regex.test(input);
    };

    const matcher = (patterns, input) => {
        for (let pattern of patterns) {
            if (comparePattern(pattern, input)) {
                return true;
            }
        }

        return false;
    };

    const interfaces = [].concat(app.config.interfaces || '*');
    const allInterfaces = interfaces.includes('*');

    app.addHook('smtp:init', async server => {
        let maxRcptTo = await settingsHandler.get('const:max:rcpt_to');
        if (maxRcptTo) {
            server.options.maxRecipients = maxRcptTo;
        }
    });

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
                        _ip: session.remoteAddress
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
                ip: session.remoteAddress
            },
            (err, result) => {
                if (err) {
                    return next(err);
                }

                if (result && result.asp) {
                    auth.passwordType = 'asp';
                } else {
                    auth.passwordType = 'master';
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
                        _ip: session.remoteAddress
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
                    _ip: session.remoteAddress
                });

                auth.username = result.username !== username ? result.username + '[' + username + ']' : result.username;
                next();
            }
        );
    });

    // Use SNI cert if available
    app.addHook('smtp:sni', (servername, data, next) => {
        if (!servername) {
            return next();
        }

        certHandler
            .getContextForServername(
                servername,
                Object.assign({}, (app.config.certs && app.config.certs.tlsOptions) || {}),
                {
                    source: 'smtp'
                },
                {
                    loggelf: message => loggelf(message)
                }
            )
            .then(ctx => {
                data.secureContext = ctx;
                next(null);
            })
            .catch(err => next(err));
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
                        removeDots: true
                    });

                    if (
                        userData.fromWhitelist.some(addr => {
                            addr = tools.normalizeAddress(addr, false, {
                                removeLabel: true,
                                removeDots: true
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
                            addrview: normalizedAddress
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
                        short_message: '[RWENVELOPE] ' + envelope.id,
                        _mail_action: 'rw_envelope_from',
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
        let { recipient, deliveryZone } = routing;

        // Check for outbound MTA relay
        await new Promise(resolve => {
            getUser(envelope, (err, userData) => {
                if (err) {
                    // no user data, just continue
                    return resolve();
                }

                if (userData.mtaRelay?.value) {
                    let relayData = userData.mtaRelay.value;
                    if (typeof relayData === 'string') {
                        relayData = tools.getRelayData(relayData);
                    }

                    const mxData = {};
                    mxData.mx = relayData.mx;
                    mxData.mxPort = relayData.mxPort;
                    mxData.mxAuth = relayData.mxAuth;
                    mxData.mxSecure = relayData.mxSecure;
                    mxData.skipSRS = true;
                    mxData.skipSTS = true;

                    routing.mxData = mxData;
                }

                return resolve();
            });
        });

        function domainToASCII(domain) {
            if (!domain) {
                return '';
            }
            const normalized = domain.toLowerCase().trim();
            try {
                return punycode.toASCII(normalized);
            } catch (err) {
                return normalized;
            }
        }

        // Check for local delivery bypass
        // This prevents mail loops when using a hybrid setup (e.g., Google Workspace + local WildDuck)
        // where the MX points to an external service that forwards back to us
        if (!routing.mxData && recipient && app.config.localDelivery && app.config.localDelivery.enabled) {
            const domain = domainToASCII(recipient.substring(recipient.indexOf('@') + 1));
            const localDomains = [].concat(app.config.localDelivery.domains || []).map(domainToASCII);

            if (localDomains.includes(domain)) {
                const isLocal = await new Promise((resolve, reject) => {
                    userHandler.resolveAddress(recipient, { wildcard: true }, (err, addressData) => {
                        if (err) {
                            err.responseCode = 451;
                            return reject(err);
                        }
                        resolve(!!(addressData && (addressData.user || (addressData.targets && addressData.targets.length))));
                    });
                });

                if (isLocal) {
                    const localZone = app.config.localDelivery.deliveryZone;
                    routing.mxData = { skipSTS: true };

                    if (localZone) {
                        routing.deliveryZone = localZone;
                    } else {
                        const targetHost = app.config.localDelivery.targetHost || '127.0.0.1';
                        const targetPort = app.config.localDelivery.targetPort;
                        routing.mxData.mx = [{ priority: 0, exchange: targetHost, localDelivery: true }];
                        if (targetPort) {
                            routing.mxData.mxPort = targetPort;
                        }
                    }

                    app.logger.info(
                        'LocalDelivery',
                        '%s LOCALDELIVERY recipient=%s domain=%s route=%s',
                        envelope.id,
                        recipient,
                        domain,
                        localZone || routing.mxData.mx[0].exchange + (routing.mxData.mxPort ? ':' + routing.mxData.mxPort : '')
                    );
                    return;
                }
            }
        }

        if (deliveryZone !== 'default' || !app.config.mxRoutes) {
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
            let exchanges = await timedRunner(resolveMx(domain), 1000);
            if (!exchanges || !exchanges.length) {
                return;
            }

            let mx = exchanges
                .sort((a, b) => a.priority - b.priority)[0]
                .exchange.toLowerCase()
                .trim();

            let routes = Object.keys(app.config.mxRoutes);
            for (let route of routes) {
                if (matcher([route], mx)) {
                    // MX routing match found!
                    routing.deliveryZone = app.config.mxRoutes[route];
                    app.logger.info('Main', '%s MXROUTEMATCH recipient=%s mx=%s zone=%s', envelope.id, recipient, mx, app.config.mxRoutes[route]);
                    return;
                }
            }
        } catch (err) {
            // ignore?
            app.logger.error('Main', '%s MXROUTEERR recipient=%s error=%s', envelope.id, recipient, err.message);
        }
    });

    // ZoneMTA's default connection pool key uses the recipient domain, which is
    // shared by local and external recipients in a hybrid setup. Use the tagged
    // local MX target in the key so that these connections can not be mixed.
    app.addHook('sender:fetch', async delivery => {
        const localMx = delivery.mx && delivery.mx.find(mx => mx && mx.localDelivery);
        if (localMx) {
            const source = [delivery.zoneAddress, delivery.zoneAddressIPv4, delivery.zoneAddressIPv6]
                .map(entry => entry && entry.address)
                .filter(Boolean)
                .join(',');
            delivery.connectionKey = ['local-delivery', source, localMx.exchange, delivery.mxPort || 'default'].join(':');
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

            ttlcounter(`wdr:${tools.redisHashTag(redisClient, userData._id)}`, 0, userData.recipients, false, (err, result) => {
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
                    _sess: session.id
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
                _sess: session.id
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

            ttlcounter(`wdr:${tools.redisHashTag(redisClient, userData._id)}`, envelope.to.length, userData.recipients, false, (/*err, result*/) => {
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
                        audits = audits.filter(auditData => {
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

                            let raw = Buffer.concat(chunks, chunklen);

                            let storeSentMessage = async () => {
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
                                            time: new Date()
                                        },

                                        date: false,
                                        flags: ['\\Seen'],
                                        raw,

                                        // if similar message exists, then skip
                                        skipExisting: true
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
                                    raw
                                });

                                if (messageData.attachments && messageData.attachments.length) {
                                    messageData.ha = messageData.attachments.some(a => !a.related);
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
                                            time: new Date()
                                        }
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
                                storeSentMessage().catch(err =>
                                    app.logger.error('Rewrite', '%s MSAUPLFAIL user=%s error=%s', envelope.id, envelope.user, err.message)
                                );
                            } else {
                                processAudits().catch(err =>
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

        let getKey = async domain => {
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
            .then(keyData => {
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

                getKey(delivery.zoneAddress.name)
                    .then(keyData => {
                        if (keyData) {
                            delivery.dkim.keys.push({
                                domainName: tools.normalizeDomain(delivery.zoneAddress.name),
                                keySelector: keyData.selector,
                                privateKey: keyData.privateKey
                            });
                        }
                        next();
                    })
                    .catch(err => {
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
            .catch(err => {
                app.logger.error('DKIM', '%s.%s DBFAIL Failed loading DKIM key "%s". %s', delivery.id, delivery.seq, fromDomain, err.message);
                next();
            });
    };

    // "old" connection handler called when a connection to MX is being
    app.addHook('sender:connect', (delivery, options, next) => connectionHandler(delivery, next));
    app.addHook('sender:connection', (delivery, connection, next) => connectionHandler(delivery, next));

    app.addHook('log:entry', (entry, next) => {
        entry = entry && typeof entry === 'object' ? entry : {};
        entry.created = new Date();

        let message = {
            _queue_id: (entry.id || '').toString(),
            _queue_id_seq: (entry.seq || '').toString()
        };

        const boolFields = [
            ['secure', '_secure'],
            ['tls', '_tls'],
            ['tlsAuthorized', '_tls_authorized']
        ];

        const passthroughFields = [
            ['rwRcptFrom', '_rewrite_rcpt_from'],
            ['rwHeaderFrom', '_rewrite_header_from'],
            ['protocol', '_delivery_protocol'],
            ['httpUrl', '_http_url'],
            ['tlsVersion', '_tls_version'],
            ['tlsCipher', '_tls_cipher'],
            ['tlsAuthorizationError', '_tls_authorization_error']
        ];

        for (const [src, dest] of boolFields) {
            if (typeof entry[src] === 'boolean') {
                message[dest] = entry[src] ? 'yes' : 'no';
            }
        }

        for (const [src, dest] of passthroughFields) {
            if (entry[src]) {
                message[dest] = entry[src];
            }
        }

        if (entry.httpResponse && Number(entry.httpResponse)) {
            message._http_response = entry.httpResponse;
        }

        let headerFrom = entry.headerFrom;
        let headerFromList;
        let headerFromObj = {};
        let headerFromName;

        if (headerFrom) {
            message._header_from_value = headerFrom;
            headerFromList = addressparser(headerFrom);
            if (headerFromList && headerFromList.length) {
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
                .catch(err => app.logger.error('Rewrite', '%s.%s LOGERR %s', entry.id, entry.seq, err.message));
        };

        switch (entry.action) {
            case 'QUEUED':
                {
                    let username = (entry.user || entry.auth || '').toString();
                    let subject = (entry.subject || '').toString();
                    let match = username.match(/\[([^\]]+)]/);
                    if (match && match[1]) {
                        username = match[1];
                    }
                    message.short_message = `[QUEUED] ${entry.id}`;
                    message._from = (entry.from || '').toString();
                    message._to = (entry.to || '').toString();
                    message._mail_action = 'queued';
                    message._message_id = (entry['message-id'] || entry.messageId || '').toString().trim();
                    message._ip = entry.src;
                    message._body_size = entry.body;
                    message._spam_score = Number(entry.score) || '';
                    message._interface = entry.interface;
                    message._proto = entry.transtype;
                    message._subject =
                        Buffer.byteLength(subject, 'utf8') > maxSubjectLineLogLengthBytes
                            ? subject.substring(0, maxSubjectLineLogLengthBytes / 4) // divide by 4 to account for max utf-8 char size
                            : subject;

                    message._authenticated_sender = username;
                }
                break;

            case 'ACCEPTED':
                message.short_message = `[ACCEPTED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;
                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._mail_action = 'accepted';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().trim();
                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('accepted', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip
                });
                break;

            case 'DEFERRED':
                message.short_message = `[DEFERRED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._mail_action = 'deferred';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().trim();

                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('deferred', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip
                });
                break;

            case 'REJECTED':
                message.short_message = `[REJECTED] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();
                message._bounce_category = entry.category;
                message._bounce_count = entry.defcount;

                message._mail_action = 'bounced';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().trim();

                message._zone = entry.zone;
                message._mx = entry.mx;
                message._mx_host = entry.host;
                message._local_ip = entry.ip;

                message._response = entry.response;

                updateAudited('rejected', {
                    to: (entry.to || '').toString(),
                    response: entry.response,
                    mx: entry.mx,
                    local_ip: entry.ip
                });
                break;

            case 'NOQUEUE':
                message.short_message = `[NOQUEUE] ${entry.id}${entry.seq ? `.${entry.seq}` : ''}`;

                message._from = (entry.from || '').toString();
                message._to = (entry.to || '').toString();

                message._mail_action = 'dropped';
                message._message_id = (entry['message-id'] || entry.messageId || '').toString().trim();
                message._ip = entry.src;
                message._body_size = entry.body;
                message._spam_score = Number(entry.score) || '';
                message._interface = entry.interface;
                message._proto = entry.transtype;

                if (entry.user) {
                    message._user = entry.user;
                }

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

            case 'QUEUE_POLL':
                message.short_message = `[QUEUE_POLL] ${entry.query?.sendingZone}`;
                message._mail_action = 'queue_poll';
                message._queue_poll_zone = (entry.query?.sendingZone || '').toString();
                message._queue_poll_lte = entry.query?.queued?.$lte?.toISOString();
                message._queue_poll_instance = entry.query?.$or?.at(-1)?.assigned;
                message._queue_poll_skip_domains = entry.query?.domain?.$nin?.join(', ');
                message._queue_poll_match = entry.match ? 'yes' : 'no';
                message._error = entry.error;
                break;

            case 'QUEUE_BOUNCE':
                message.short_message = `[QUEUE_BOUNCE] ${entry.bounceType}`;
                message._mail_action = 'queue_bounce';
                message._queue_bounce_queued = (entry.queued || '').toString();
                message._queue_bounce_type = entry.bounceType;
                message._queue_bounce_id = entry.bounceId;
                message._error = entry.error;
                break;
        }

        if (message.short_message) {
            loggelf(message);
        }

        return next();
    });

    app.addHook('sender:responseError', async delivery => {
        let deferTimesStr = await settingsHandler.get('const:sender:defer_times');
        if (deferTimesStr) {
            const deferTimes = deferTimesStr
                .split(',')
                .map(v => {
                    let m = v.match(/\s*(\d+)\s*([^\d\s]+)?\s*/);
                    if (!m) {
                        return false;
                    }
                    const n = Number(m[1]);
                    const l = (m[2] || '').toLowerCase();

                    switch (l) {
                        case 's':
                        case 'sec':
                        case 'second':
                        case 'seconds':
                            return n * 1000;

                        case 'm':
                        case 'min':
                            return n * 60 * 1000;

                        case 'h':
                        case 'hour':
                            return n * 60 * 60 * 1000;

                        case 'd':
                        case 'day':
                        case 'days':
                            return n * 24 * 60 * 60 * 1000;

                        default:
                            return n;
                    }
                })
                .filter(v => v);
            if (deferTimes && deferTimes.length) {
                delivery.deferTimes = deferTimes;
            }
        }
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
                username: envelope.user.split('[').shift()
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
                    mtaRelay: true
                }
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
                    .then(maxRecipients => {
                        userData.recipients = Number(userData.recipients) || app.config.maxRecipients || maxRecipients;

                        users.set(envelope, userData);

                        return callback(null, userData);
                    })
                    .catch(err => callback(err));
            }
        );
    }

    const localDeliveryEnabled = !!(app.config.localDelivery && app.config.localDelivery.enabled);
    const localDeliveryDomains =
        localDeliveryEnabled && app.config.localDelivery.domains ? [].concat(app.config.localDelivery.domains).join(',') : 'none';
    const srsEnabled = !!(app.config.srs && app.config.srs.enabled);
    const dkimEnabled = !!(app.config.dkim && app.config.dkim.signTransportDomain);
    const acmeEnabled = !!(app.config.acme && app.config.acme.autogenerate && app.config.acme.autogenerate.enabled);
    const mxRoutesCount = app.config.mxRoutes ? Object.keys(app.config.mxRoutes).length : 0;

    app.logger.info(
        'WildDuck',
        'Initialized hostname=%s interfaces=%s localDelivery=%s(localDomains=%s) srs=%s dkim=%s acme=%s mxRoutes=%s maxRecipients=%s uploads=%s',
        app.config.hostname || 'default',
        [].concat(app.config.interfaces || '*').join(','),
        localDeliveryEnabled ? 'enabled' : 'disabled',
        localDeliveryDomains,
        srsEnabled ? 'enabled' : 'disabled',
        dkimEnabled ? 'enabled' : 'disabled',
        acmeEnabled ? 'enabled' : 'disabled',
        mxRoutesCount,
        app.config.maxRecipients || 'default',
        app.config.disableUploads ? 'disabled' : app.config.uploadAll ? 'all' : 'filtered'
    );

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

    let username = '';
    if (envelope.user) {
        try {
            username = tools.normalizeAddress(envelope.user);
        } catch (err) {
            username = envelope.user;
        }
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

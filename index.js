'use strict';

const punycode = require('punycode');
const bcrypt = require('bcryptjs');
const addressparser = require('nodemailer/lib/addressparser');
const MimeNode = require('nodemailer/lib/mime-node');
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;

module.exports.title = 'Wild Duck MSA';
module.exports.init = function (app, done) {

    MongoClient.connect(app.config.mongo, (err, database) => {
        if (err) {
            return done(err);
        }

        // handle user authentication
        app.addHook('smtp:auth', (auth, session, next) => {
            let username = (auth.username || '').toString().toLowerCase().trim();
            let password = auth.password || '';

            database.collection('users').findOne({
                username
            }, (err, user) => {
                if (err) {
                    return next(err);
                }
                if (!user || !bcrypt.compareSync(password, user.password)) {
                    err.message = new Error('Authentication failed');
                    err.responseCode = 535;
                    return next(err);
                }

                // consider the authentication as succeeded as we did not get an error
                auth.username = username;
                next();
            });
        });

        // Check if an user is allowed to use specific address, if not then override using the default
        app.addHook('message:headers', (envelope, messageInfo, next) => {
            if (!envelope.user) {
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

            database.collection('users').findOne({
                username: envelope.user
            }, (err, userData) => {
                if (err) {
                    return next(err);
                }

                if (!userData.address) {
                    return next(new Error('User "' + envelope.user + '" does not have a default email address set'));
                }

                database.collection('addresses').findOne({
                    address: normalizeAddress(envelope.from),
                    user: userData._id
                }, (err, addressData) => {

                    if (err) {
                        return next(err);
                    }

                    if (!addressData) {
                        // replace MAIL FROM address
                        app.logger.info('Rewrite', '%s.%s RWENVELOPE User %s tries to use "%s" as Return Path address, replacing with "%s"', envelope.id, envelope.seq, userData.username, envelope.from, userData.address);
                        envelope.from = userData.address;
                    }

                    if (!headerFromObj) {
                        return next();
                    }

                    database.collection('addresses').findOne({
                        address: normalizeAddress(headerFromObj.address),
                        user: userData._id
                    }, (err, addressData) => {
                        if (err) {
                            return next(err);
                        }

                        if (addressData) {
                            // can send mail as this user
                            return next();
                        }

                        app.logger.info('Rewrite', '%s.%s RWFROM User %s tries to use "%s" as From address, replacing with "%s"', envelope.id, envelope.seq, userData.username, headerFromObj.address, envelope.from);

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

        done();
    });
};

function normalizeAddress(address, withNames) {
    if (typeof address === 'string') {
        address = {
            address
        };
    }
    if (!address || !address.address) {
        return '';
    }
    let user = address.address.substr(0, address.address.lastIndexOf('@')).normalize('NFC').toLowerCase().trim();
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

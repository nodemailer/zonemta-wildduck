# zonemta-wildduck

Wild Duck MSA plugin for [ZoneMTA](https://github.com/zone-eu/zone-mta). Install this to send as an user of the Wild Duck IMAP server. This plugin handles authentication and also header rewriting – users are only allowed to send mail from their registered email addresses. If the address in an email does not match then it is overriden with an allowed address. This is similar to the behavior of Gmail SMTP.

Wild Duck actions apply only interfaces that require authentication.

## Features

* **authentication** – if authentication is enabled for the smtp interface then authentication data is checked against Wild Duck user accounts
* **From rewriting** – if the message has a From: address in the header that is not registered as one of the aliases for this user then the address part (but not the name) is rewritten with the default address for this user
* **Upload to Sent Mail folder** – sent message is automatically appended to the *Sent Mail* folder of the user
* **Reciepient limiting** – limit RCPT TO calls for 24 hour period based on the *recipients* user value
* **Local delivery** – messages that are handled current Wild Duck installation are routed directly to LMTP bypassing MX steps

## Setup

Add this as a dependency for your ZoneMTA app

```
npm install zonemta-wildduck --save
```

Add a configuration entry in the "plugins" section of your ZoneMTA app

First enable authentication for the SMTP interface

```toml
# interfaces.toml
[feeder]
authentication=true
port=587
```

Then set up configuration for this plugin

```toml
# plugins/wildduck.toml
["modules/zonemta-wildduck"]
enabled=["receiver", "sender"]

# which interfaces this plugin applies to
interfaces=["feeder"]

# optional hostname to be used in headers
# defaults to os.hostname()
hostname="example.com"

# How long to keep auth records in log
authlogExpireDays=30

# SRS settings for forwarded emails

# Handle rewriting of forwarded emails
forwardedSRS=true
# SRS secret value. Must be the same as in the MX side
secret="secret value"
# SRS domain, must resolve back to MX
rewriteDomain="example.com"

# Delivery settings for local messages
# do not set these values if you do not want to use local delivery

# Use LMTP instead of SMTP
localLmtp=true
localMxPort=24
# SMTP/LMTP server for local delivery
[["modules/zonemta-wildduck".localMx]]
    priority=0
    # hostname is for logging only, IP is actually used
    exchange="example.com"
    A=["127.0.0.1"]
    AAAA=[]
# Interface to be used for local delivery
# Make sure that it can connect to the localMX IP
["modules/zonemta-wildduck".localZoneAddress]
    address="127.0.0.1"
    name="example.com"
```

Local deliveries are deliveries to addresses that are handled by active Wild Duck installation. In case of these addresses MX step is ignored and messages are delivered directly to LMTP.

## License

European Union Public License 1.1 ([details](http://ec.europa.eu/idabc/eupl.html))

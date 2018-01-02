# zonemta-wildduck

WildDuck MSA plugin for [ZoneMTA](https://github.com/zone-eu/zone-mta). Install this to send as an user of the WildDuck IMAP server. This plugin handles authentication and also header rewriting – users are only allowed to send mail from their registered email addresses. If the address in an email does not match then it is overriden with an allowed address. This is similar to the behavior of Gmail SMTP.

WildDuck actions apply only interfaces that require authentication.

## Features

* **authentication** – if authentication is enabled for the smtp interface then authentication data is checked against WildDuck user accounts
* **From rewriting** – if the message has a From: address in the header that is not registered as one of the aliases for this user then the address part (but not the name) is rewritten with the default address for this user
* **Upload to Sent Mail folder** – sent message is automatically appended to the _Sent Mail_ folder of the user
* **Reciepient limiting** – limit RCPT TO calls for 24 hour period based on the _recipients_ user value
* **Local delivery** – messages that are handled current WildDuck installation are routed directly to LMTP bypassing MX steps

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

Then set up configuration for this plugin, see the [example config](./config.example.toml) file for details.

## License

European Union Public License 1.1 ([details](http://ec.europa.eu/idabc/eupl.html)) or later.

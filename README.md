# zonemta-wildduck

Wild Duck MSA plugin for [ZoneMTA](https://github.com/zone-eu/zone-mta). Install this to send as an user of the Wild Duck IMAP server. This plugin handles authentication and also header rewriting – users are only allowed to send mail from their registered email addresses. If the address in an email does not match then it is overriden with an allowed address. This is similar to the behavior of Gmail SMTP.

Wild Duck actions apply only interfaces that require authentication.

## Setup

Add this as a dependency for your ZoneMTA app

```
npm install zonemta-wildduck --save
```

Add a configuration entry in the "plugins" section of your ZoneMTA app

```json
...
  "plugins": {
    "modules/zonemta-wildduck": {
        "enabled": "receiver",
        "mongo": "mongodb://127.0.0.1:27017/wildduck",
        "hostname": "mail.wildduck.email"
    }
  }
...
```

Where

  * **enabled** states which ZoneMTA processes should use this plugin. Should be "receiver"
  * **mongo** is the connection string for the Wild Duck IMAP database
  * **hostname** is the name to use in Received headers for uploaded messages

## License

European Union Public License 1.1 ([details](http://ec.europa.eu/idabc/eupl.html))

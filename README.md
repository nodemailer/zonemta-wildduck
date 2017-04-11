# zonemta-wildduck

Wild Duck MSA plugin for [ZoneMTA](https://github.com/zone-eu/zone-mta). Install this to send as an user of the Wild Duck IMAP server. This plugin handles authentication and also header rewriting – users are only allowed to send mail from their registered email addresses. If the address in an email does not match then it is overriden with an allowed address. This is similar to the behavior of Gmail SMTP.

Wild Duck actions apply only interfaces that require authentication.

## Features

* **authentication** – if authentication is enabled for the smtp interface then authentication data is checked against Wild Duck user accounts
* **From rewriting** – if the message has a From: address in the header that is not registered as one of the aliases for this user then the address part (but not the name) is rewritten with the default address for this user
* **Upload to Sent Mail folder** – sent message is automatically appended to the *Sent Mail* folder of the user

## Setup

Add this as a dependency for your ZoneMTA app

```
npm install zonemta-wildduck --save
```

Add a configuration entry in the "plugins" section of your ZoneMTA app

```json
...
  "smtpInterfaces": {
    "feeder": {
      "authentication": true
      ...
    }
  },
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

Optional arguments:

  * **interfaces** is an array of interface names this plugin applies to (eg. `["feeder"]`). This is needed if you have multiple interfaces set up that have different configuration.

## License

European Union Public License 1.1 ([details](http://ec.europa.eu/idabc/eupl.html))

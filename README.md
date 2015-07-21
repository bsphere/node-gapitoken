node-gapitoken
==============

Node.js module for Google API service account authorization (Server to Server flow).

[![Build Status](https://travis-ci.org/bsphere/node-gapitoken.svg)](https://travis-ci.org/bsphere/node-gapitoken)


Installation
------------

	npm install gapitoken

Usage
-----

    var GAPI = require('gapitoken');

    var gapi = new GAPI({
        iss: 'service account email address from Google API console',
        scope: 'space delimited list of requested scopes',
        keyFile: 'path to private_key.p12'
    }, function(err) {
       if (err) { return console.log(err); }

       gapi.getToken(function(err, token) {
           if (err) { return console.log(err); }
           console.log(token);
       });
    });

Another option is to pass the private key as a string

    var key = "-----BEGIN RSA PRIVATE KEY-----\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
    -----END RSA PRIVATE KEY-----";

    var gapi = new GAPI({
        iss: 'service account email address from Google API console',
        scope: 'space delimited list of requested scopes',
        key: key
    }, function() {
       gapi.getToken(function(err, token) {
           if (err) { return console.log(err); }
           console.log(token);
       });
    });


* for using node-gapitoken to access Google Cloud Storage see https://github.com/bsphere/node-gcs

Creating a Private key file
---------------------------

1) Login to Google API Console, and under "API Access" create a "service account" for your project.

2) Download the .p12 private key file.

3) Reference the file using the `keyFile` property as in the example above or, if you’ve already loaded the file yourself, pass it in via the `key` property as a base64-encoded string.

*A short note on .p12 and .pem files:* the .p12 file is an encoded format for storing your key. If you’d like to pre-decode it, you can convert it to a .pem file on the command line:

```shell
> openssl pkcs12 -in key.p12 -out key.pem -nocerts

# Note: you’ll have to set a passphrase for the file. To remove it:
> openssl rsa -in key.pem -out key.pem
```

The resulting file can then be used for the `keyFile` or `key` properties just like the .p12 file.

(In older versions of this library, this step was required. P12 support is now built-in.)

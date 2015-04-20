'use strict';

var jws = require('jws');
var fs = require('fs');
var request = require('request');
var p12ToPem = require('p12-to-pem');

var GAPI = function(options, callback) {
	this.token = null;
	this.token_expires = null;

	this.iss = options.iss;
	this.scope = options.scope;
	this.sub = options.sub;
	this.prn = options.prn;

    if (options.keyFile) {
        var self = this;
        process.nextTick(function() {
            fs.readFile(options.keyFile, function(err, res) {
                if (err) { return callback(err); }
                self.key = decodeKey(res);
                callback();
            });
        });
    } else if (options.key) {
        this.key = decodeKey(options.key);
        process.nextTick(callback);
    } else {
        callback(new Error("Missing key, key or keyFile option must be provided!"));
    }
};

GAPI.prototype.getToken = function(callback) {
	if (this.token && this.token_expires && (new Date()).getTime() < this.token_expires * 1000) {
        callback(null, this.token);
    } else {
        this.getAccessToken(callback);
    }
};

GAPI.prototype.getAccessToken = function(callback) {
    var self = this;
    var iat = Math.floor(new Date().getTime() / 1000);

    var payload = {
        iss: this.iss,
        scope: this.scope,
        aud: 'https://accounts.google.com/o/oauth2/token',
        exp: iat + 3600,
        iat: iat
    };

	if(this.sub)
		payload.sub = this.sub;

	if(this.prn)
		payload.prn = this.prn;

    var signedJWT = jws.sign({
        header: {alg: 'RS256', typ: 'JWT'},
        payload: payload,
        secret: this.key
    });

    var post_options = {
        url: 'https://accounts.google.com/o/oauth2/token',
        method: 'POST',
        strictSSL: false,
        form: {
          'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'assertion': signedJWT
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
    };

    request(post_options, function(error, response, body) {
      if(error){
        self.token = null;
        self.token_expires = null;
        callback(error, null);
      } else {
        try {
          var d = JSON.parse(body);
          if (d.error) {
            self.token = null;
            self.token_expires = null;
            callback(d.error, null);
          } else {
            self.token = d.access_token;
            self.token_expires = iat + 3600;
            callback(null, self.token);
          }
        } catch (e) {
          callback(e, null);
        }
      }
    });
};

// Takes either a raw, unprotected key or a password-protected PKCS12 file
// containing a private key and returns the key.
function decodeKey(key) {
    var keyString = key.toString();
    var maybeP12 = keyString.indexOf("PRIVATE KEY-----") === -1;
    if (maybeP12) {
        // Google's PKCS12 files use the password "notasecret"
        return p12ToPem(key, "notasecret");
    }
    else {
        return keyString;
    }
}

module.exports = GAPI;

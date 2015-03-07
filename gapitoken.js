var https = require('https');
var jws = require('jws');
var fs = require('fs');
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

    var post_data = 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + signedJWT;
    var post_options = {
        host: 'accounts.google.com',
        path: '/o/oauth2/token',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    };

    var self = this;
    var post_req = https.request(post_options, function(res) {
        var d = '';
        res.setEncoding('utf8');
        res.on('data', function(chunk) {
            d += chunk;
        });

        res.on('end', function() {
            try {
                d = JSON.parse(d);
                if (d.error) {
                    self.token = null;
                    self.token_expires = null;
                    callback(d, null);
                } else {
                    self.token = d.access_token;
                    self.token_expires = iat + 3600;
                    callback(null, self.token);
                }
            } catch (e) {
                callback(new Error(d), null);
            }
        });
    }).on('error', function(err) {
            self.token = null;
            self.token_expires = null;
            callback(err, null);
    });

    post_req.write(post_data);
    post_req.end();	
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

'use strict';

var https = require('https');
var jws = require('jws');
var fs = require('fs');
var qs = require('qs');

var GAPI = function GAPI(options, callback) {
    this.token = null;
    this.token_expires = null;

    this.iss = options.iss;
    this.scope = options.scope;
    this.sub = options.sub;
    this.prn = options.prn;
    this.kid = options.kid;

    if (options.keyFile) {
        var self = this;
        fs.readFile(options.keyFile, function(err, res) {
            if (err) { return callback(err); }
            self.key = res;
            callback();
        });
    } else if (options.key) {
        this.key = options.key;
        process.nextTick(callback);
    } else {
        process.nextTick(function() {
            callback(new Error('Missing key, key or keyFile option must be provided!'));
        });
    }
};

GAPI.prototype.getToken = function getToken(callback) {
    if (this.token && this.token_expires && (new Date()).getTime() < this.token_expires * 1000) {
        process.nextTick(function() {
            callback(null, this.token);
        });
    } else {
        this.getAccessToken(callback);
    }
};

GAPI.prototype.getAccessToken = function getAccessToken(callback) {
    var iat = Math.floor(new Date().getTime() / 1000);

    var header = {
        alg: 'RS256',
        typ: 'JWT'
    };

    var payload = {
        iss: this.iss,
        scope: this.scope,
        aud: 'https://accounts.google.com/o/oauth2/token',
        exp: iat + 3600,
        iat: iat
    };

    if (this.kid)
        header.kid = this.kid;

    if (this.sub)
        payload.sub = this.sub;

    if (this.prn)
        payload.prn = this.prn;

    var signedJWT = jws.sign({
        header: header,
        payload: payload,
        secret: this.key
    });

    var post_data = qs.encode({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: signedJWT
    });
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

module.exports = GAPI;

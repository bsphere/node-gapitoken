var fs = require('fs');
var path = require('path');
var assert = require('assert');
var GAPI = require('../gapitoken.js');

var keyPath = path.join(__dirname, 'test-key');

describe('Authenticating with Google', function() {
  it('should work with a .pem file', function(done) {
    var gapi = new GAPI({
        iss: '985952909795-p560igbg1r2hjaagrpeust4sqca9vhi8@developer.gserviceaccount.com',
        scope: 'https://www.googleapis.com/auth/bigquery',
        keyFile: keyPath + '.pem'
    }, function(error) {
        if (error) { return done(error); }

        gapi.getToken(function(error, token) {
            assert.ok(token, 'Got a token');
            done(error);
        });
    });
  });

  it('should work with an RSA string', function(done) {
    var gapi = new GAPI({
        iss: '985952909795-p560igbg1r2hjaagrpeust4sqca9vhi8@developer.gserviceaccount.com',
        scope: 'https://www.googleapis.com/auth/bigquery',
        key: fs.readFileSync(keyPath + '.pem')
    }, function(error) {
        if (error) { return done(error); }

        gapi.getToken(function(error, token) {
            assert.ok(token, 'Got a token');
            done(error);
        });
    });
  });

  it('should work with a .p12 file', function(done) {
    var gapi = new GAPI({
        iss: '985952909795-p560igbg1r2hjaagrpeust4sqca9vhi8@developer.gserviceaccount.com',
        scope: 'https://www.googleapis.com/auth/bigquery',
        keyFile: keyPath + '.p12'
    }, function(error) {
        if (error) { return done(error); }

        gapi.getToken(function(error, token) {
            assert.ok(token, 'Got a token');
            done(error);
        });
    });
  });

  it('should work with an base64-encoded p12 string', function(done) {
    var gapi = new GAPI({
        iss: '985952909795-p560igbg1r2hjaagrpeust4sqca9vhi8@developer.gserviceaccount.com',
        scope: 'https://www.googleapis.com/auth/bigquery',
        key: fs.readFileSync(keyPath + '.p12').toString("base64")
    }, function(error) {
        if (error) { return done(error); }

        gapi.getToken(function(error, token) {
            assert.ok(token, 'Got a token');
            done(error);
        });
    });
  });
});

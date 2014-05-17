var as = require('chai').assert;
var https = require('https');
var fs = require('fs');
var pfx = fs.readFileSync('certs/server.pfx');

var port = 4444;

function getPort() {
  return port++;
}

require('ssl-root-cas/latest').inject().addFile('certs/ca.crt');

describe('HTTPS/SSL Server Tests with Root CA Module', function() {

  it('will connect securely to ssl site with public ca', function(done) {
    // Shows that the ssl-root-cas module at least knows about google's
    // cert. Also shows that it slows your app startup time :)
    var clientOptions = {
      host: 'www.google.com',
      port: 443,
      path: '/'
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        //console.log(data.toString());
      });
      res.on('end', function() {
        as(res.client.authorized && res.client.encrypted);
        done();
      });
    }).end();
  });

  it('will NOT connect to public site if you specify your own CA',
    function(done) {
      // Shows that specifying the ca array means you have to include all
      // CAs. It doesn't add to the ones that it already knows about.
      var clientOptions = {
        host: 'www.google.com',
        port: 443,
        path: '/',
        ca: [fs.readFileSync('certs/ca.crt')]
      };
      https.request(clientOptions, function(res) {
        res.on('end', function() {
          done(new Error('should never get here'));
        });
      })
        .on('error', function(err) {
          as(err.message = 'CERT_UNTRUSTED');
          done();
        });
    });

  it('will work with added ca.', function(done) {
    // Shows that you can add your custom ca using the ssl-root-cas module
    // instead of adding the ca client option.
    var port = getPort();
    var serverOptions = {
      pfx: pfx
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      }
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

});

// These tests show how you can use SSL public/private key pairs for client
// authentication. Simply configure your server to ask the client for a cert
// and optionally reject clients that don't send one or don't send a valid one.
// Either way you can
// test for req.client.authorized to see if the client is who they say they are.

var as = require('chai').assert;

var fs = require('fs');
var https = require('https');

var serverPfx = fs.readFileSync('certs/server.pfx');
var clientPfx = fs.readFileSync('certs/client.pfx');
var unknownPfx = fs.readFileSync('certs/unknown.pfx');

var ca = fs.readFileSync('certs/ca.crt');

var port = 1111;

function getPort() {
  return port++;
}

describe('HTTPS/SSL Client Tests', function() {

  it('will authorize the client with SSL.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: serverPfx,
      // This ca validates that the client cert or pfx is ok.
      ca: ca,
      // requestCert says I want the client to send me a cert (or pfx).
      requestCert: true,
      // rejectUnauthorized says I will reject any clients that don't send
      // a valid cert (or pfx).
      rejectUnauthorized: true
    };
    https.createServer(serverOptions, function(req, res) {
      // req.client.authorized tells whether the client sent a valid cert (or pfx).
      // if rejectUnauthorized is false this will be false in the case of
      // clients that don't send a cert or don't send a valid one.
      as(req.client.authorized);
      res.end('Howdy');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      // This ca validates that the server cert or pfx is ok.
      // Both CAs happen to be the same because we used the same one to sign
      // the client and server certs, but generally they will be different.
      // Actually, in real life we should not have to specify a CA here because
      // the server should be using a cert from a trusted certificate authority.
      ca: ca,
      pfx: clientPfx
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('will reject clients that dont send a cert.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: serverPfx,
      ca: ca,
      requestCert: true,
      rejectUnauthorized: true
    };
    https.createServer(serverOptions, function(req, res) {
      as(false, 'should not get here');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      ca: ca
    };
    https.request(clientOptions, function(res) {})
      .on('error', function(err) {
        as('ECONNRESET' === err.code);
        done();
      }).end();
  });

  it('will reject clients that dont send a known cert.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: serverPfx,
      ca: ca,
      requestCert: true,
      rejectUnauthorized: true
    };
    https.createServer(serverOptions, function(req, res) {
      as(false, 'should not get here');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      ca: ca,
      pfx: unknownPfx
    };
    https.request(clientOptions, function(res) {})
      .on('error', function(err) {
        as('ECONNRESET' === err.code);
        done();
      }).end();
  });

  it('will allow unauthorized clients if rejectUnauthorized: false.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: serverPfx,
      ca: ca,
      requestCert: true,
      rejectUnauthorized: false
    };
    https.createServer(serverOptions, function(req, res) {
      as(!req.client.authorized);
      res.end('Howdy');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      ca: ca
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('will allow authorized clients if rejectUnauthorized: false.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: serverPfx,
      ca: ca,
      requestCert: true,
      rejectUnauthorized: false
    };
    https.createServer(serverOptions, function(req, res) {
      as(req.client.authorized);
      res.end('Howdy');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      ca: ca,
      pfx: clientPfx
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

});

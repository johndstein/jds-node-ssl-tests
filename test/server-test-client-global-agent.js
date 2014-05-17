var as = require('chai').assert;

var fs = require('fs');
var https = require('https');

var pfx = fs.readFileSync('certs/server.pfx');

var ca = fs.readFileSync('certs/ca.crt');

var port = 2222;

function getPort() {
  return port++;
}

describe('HTTPS/SSL Server Tests with Global Agent', function() {

  it('will work with globalAgent.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: pfx
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);
    https.globalAgent = new https.Agent({
      ca: [ca]
    });
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

  it('will "work" with globalAgent rejectUnauthorized = false.', function(done) {
    var port = getPort();
    var serverOptions = {
      pfx: pfx
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);
    https.globalAgent = new https.Agent({
      rejectUnauthorized: false
    });
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
var as = require('chai').assert;

var fs = require('fs');
var http = require('http');
var https = require('https');

var pfx = fs.readFileSync('certs/server.pfx');
var key = fs.readFileSync('certs/server.key');
var cert = fs.readFileSync('certs/server.crt');

var ca = fs.readFileSync('certs/ca.crt');

// Various examples of connecting to a server over SSL. These all use a self-signed
// cert and specify the certificate authority directly in the client options.
//
// See test/server-ssl-root-cas.js for example of how to simply add your
// custom CA to the list of public trusted CAs.

var port = 3333;

function getPort() {
  return port++;
}

describe('HTTPS/SSL Server Tests', function() {

  it('#1 will successfully use a self-signed cert.', function(done) {

    // Here is one way to make secure requests to a server that uses a self
    // signed cert. The most succinct way is test #5.

    var port = getPort();

    var serverOptions = {
      pfx: pfx
      // You can use the pfx OR key and cert. Don't need all three.
      // key: key,
      // cert: cert
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);

    var agent = new https.Agent({
      // The ca is the certificate authority that was used to sign the server
      // cert and pfx. The CA tells this client whether or not we can trust
      // the server certificate.
      // You need either a ca or rejectUnauthorized: false.
      // Of course rejectUnauthorized: false should only be used for testing since
      // you lose most of the benefit of SSL.
      ca: [ca]
      // rejectUnauthorized: false
    });
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        // host header must match the CN of the server certificate.
        // see certs/server.cnf
        host: 'foo.bar.com'
      },
      agent: agent
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        // I guess authorized and encrypted just means you are using SSL
        // Not sure what the difference is.
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();

  });

  it('#2 will not be authorized or encrypted if not HTTPS.', function(done) {
    var port = getPort();
    http.createServer(function(req, res) {
      res.end('Howdy');
    }).listen(port);
    var clientOptions = {
      host: 'localhost',
      port: port,
    };
    http.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(!res.client.authorized);
        as(!res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('#3 will work with server key and cert instead of pfx.', function(done) {
    var port = getPort();
    var serverOptions = {
      key: key,
      cert: cert
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);
    var agent = new https.Agent({
      ca: [ca]
    });
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      agent: agent
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('#4 will "work" with rejectUnauthorized: false instead of ca.', function(
    done) {
    var port = getPort();
    var serverOptions = {
      pfx: pfx
    };
    https.createServer(serverOptions, function(req, res) {
      res.end('Howdy');
    }).listen(port);
    var agent = new https.Agent({
      rejectUnauthorized: false
    });
    var clientOptions = {
      host: 'localhost',
      port: port,
      headers: {
        host: 'foo.bar.com'
      },
      agent: agent
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('#5 will work with ca in clientOptions and no agent.', function(done) {
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
      },
      ca: ca
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('#6 will work with just rejectUnauthorized and no agent.', function(done) {
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
      },
      rejectUnauthorized: false
    };
    https.request(clientOptions, function(res) {
      res.on('data', function(data) {
        as(res.client.authorized && res.client.encrypted);
        as(data.toString() === 'Howdy');
        done();
      });
    }).end();
  });

  it('#7 will throw error if host header is not correct.', function(done) {
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
        host: 'x.y.com'
      }
    };
    https.request(clientOptions, function(res) {
      res.on('end', function(data) {
        done(new Error('should never get here'));
      });
    })
      .on('error', function(err) {
        as("Hostname/IP doesn't match certificate's altnames" === err.message);
        done();
      });
  });


  it('#8 will connect securely to ssl site with public ca', function(done) {
    // This test here shows that node somehow knows about public certificate
    // authorities.
    // TODO not sure where node stores its list of trusted CAs.
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

  it('#9 will NOT connect to public site if you specify your own CA',
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

});

# alexa-verifier
Verify HTTP requests sent to an Alexa skill are sent from Amazon.

This module is framework-agnostic, but since express is currently the most popular choice I'll 
provide an example of that below.


### motivation
Part of the certication process for alexa skills hosted on a generic web service (i.e., not AWS Lambda) is that your skill must validate requests are actually coming from Amazon. This is enforced by checking:

* the timestamp of the request
* the validity of the certificate
* the signature of the the request signed with the aforementioned certificate

This module provides a function which handles this validation.


### api

```javascript
verifier(cert_url, signature, requestRawBody, callback);
```

* `cert_url`  full url of the certificate to verify (from the HTTP request header named `signaturecertchainurl`)
* `signature` signature of the request (from the HTTP request header named `signature`)
* `requestRawBody`  full body string from POST request
* `callback`  completion function. has 1 argument which indicates error. falsey when verification passes


### express example usage

If you're using the ever-popular `body-parser` module to parse request bodies, you'll need some
magic to actually get the raw request body. Much of the following snippet is related to getting at the raw request body.


```javascript
var express  = require('express');
var verifier = require('alexa-verifier');


var app = express();

// the alexa API calls specify an HTTPS certificate that must be validated.
// the validation uses the request's raw POST body which isn't available from
// the body parser module. so we look for any requests that include a
// signaturecertchainurl HTTP request header, parse out the entire body as a
// text string, and set a flag on the request object so other body parser
// middlewares don't try to parse the body again
app.use(function(req, res, next) {
  if (!req.headers.signaturecertchainurl) {
    return next();
  }

  // mark the request body as already having been parsed so it's ignored by
  // other body parser middlewares
  req._body = true;
  req.rawBody = '';
  req.on('data', function(data) {
    return req.rawBody += data;
  });
  req.on('end', function() {
    var cert_url, er, error, requestBody, signature;
    try {
      req.body = JSON.parse(req.rawBody);
    } catch (error) {
      er = error;
      req.body = {};
    }
    cert_url = req.headers.signaturecertchainurl;
    signature = req.headers.signature;
    requestBody = req.rawBody;
    verifier(cert_url, signature, requestBody, function(er) {
      if (er) {
        console.error('error validating the alexa cert:', er);
        res.status(401).json({ status: 'failure', reason: er });
      } else {
        next();
      }
    });
  });
});

// other body parsers, etc. follow ...
```

var crypto    = require('crypto');
var request   = require('request');
var tools     = require('openssl-cert-tools');
var url       = require('url');
var validator = require('validator');

// Default in-memory cache for downloaded certificates,
// used if no cache is explicitely passed.
var globalCache = {};

// global constants
var TIMESTAMP_TOLERANCE = 150;
var VALID_CERT_HOSTNAME = 's3.amazonaws.com';
var VALID_CERT_PATH_START = '/echo.api/';
var VALID_CERT_PORT = '443';
var SIGNATURE_FORMAT = 'base64';


function getCert(cert_url, cache, callback) {
  var cert_uri = url.parse(cert_url);
  var result = validateCertUri(cert_uri);
  if (result !== true) {
    return callback(result);
  }

  fetchCert(cert_uri, cache, function(er, pem_cert) {
    if (er) {
      return callback(er);
    }

    validateCert(pem_cert, function(er) {
      if (er) {
        return callback(er);
      }
      callback(er, pem_cert);
    });
  });
}


function fetchCert(uri, cache, callback) {
  cache = cache || globalCache;
  let cachedResponse = cache[uri.href];
  if (cachedResponse) {
    callback(null, cachedResponse);
    return;
  }

  request.get(uri.href, function(er, response, body) {
    if (response && 200 === response.statusCode) {
      cache[uri.href] = body;
      callback(null, body);
    } else {
      let statusCode = response ? response.statusCode : 0;
      callback("Failed to download certificate at: " + uri.href + ". Response code: " + statusCode + ", error: " + er);
    }
  });
}


function validateCert(pem_cert, callback) {
  return tools.getCertificateInfo(pem_cert, function(er, info) {
    if (er) {
      return callback(er);
    }

    // check that the domain echo-api.amazon.com is present in the Subject
    // Alternative Names (SANs) section of the signing certificate
    if (info.subject.CN.indexOf('echo-api.amazon.com') === -1) {
      return callback('subjectAltName Check Failed');
    }

    // check that the signing certificate has not expired (examine both the Not
    // Before and Not After dates)
    if (info.remainingDays < 1) {
      return callback('certificate expiration check failed');
    }
    callback();
  });
}


// parse a certificate and check it's contents for validity
function validateCertUri(cert_uri) {
  if (cert_uri.protocol !== 'https:') {
    return "Certificate URI MUST be https: " + cert_uri;
  }
  if (cert_uri.port && (cert_uri.port !== VALID_CERT_PORT)) {
    return "Certificate URI port MUST be " + VALID_CERT_PORT + ", was: " + cert_uri.port;
  }
  if (cert_uri.hostname !== VALID_CERT_HOSTNAME) {
    return "Certificate URI hostname must be " + VALID_CERT_HOSTNAME + ": " + cert_uri.hostname;
  }
  if (cert_uri.path.indexOf(VALID_CERT_PATH_START) !== 0) {
    return "Certificate URI path must start with " + VALID_CERT_PATH_START + ": " + cert_uri;
  }
  return true;
}


// returns true if the signature for the request body is valid, false otherwise
function validateSignature(pem_cert, signature, requestBody) {
  var verifier;
  verifier = crypto.createVerify('RSA-SHA1');
  verifier.update(requestBody);
  return verifier.verify(pem_cert, signature, SIGNATURE_FORMAT);
}


// determine if a timestamp is valid for a given request with a tolerance of
// TIMESTAMP_TOLERANCE seconds
// returns null if valid, or an error string otherwise
function validateTimestamp(requestBody) {
  var d, e, error, now, oldestTime, request_json;
  request_json = null;
  try {
    request_json = JSON.parse(requestBody);
  } catch (error) {
    e = error;
    return 'request body invalid json';
  }
  if (!(request_json.request && request_json.request.timestamp)) {
    return 'Timestamp field not present in request';
  }
  d = new Date(request_json.request.timestamp);
  now = new Date();
  oldestTime = now.getTime() - (TIMESTAMP_TOLERANCE * 1000);
  if (d.getTime() < oldestTime) {
    return "Request is from more than " + TIMESTAMP_TOLERANCE + " seconds ago";
  }
  return null;
}


// certificate validator express middleware for amazon echo
var verifier = module.exports = function(cert_url, signature, requestBody, callback, cache) {
  var er;
  if (cert_url == null) {
    cert_url = '';
  }
  if (signature == null) {
    signature = '';
  }
  if (requestBody == null) {
    requestBody = '';
  }
  if (callback == null) {
    callback = function(){};
  }
  if (!validator.isBase64(signature)) {
    return callback('signature is not base64 encoded');
  }
  er = validateTimestamp(requestBody);

  if (er) {
    return callback(er);
  }

  getCert(cert_url, cache, function(er, pem_cert) {
    var success;
    if (er) {
      return callback(er);
    }
    success = validateSignature(pem_cert, signature, requestBody);
    if (success !== true) {
      return callback('certificate verification failed');
    }
    callback();
  });
};

// Export to make unit testing easier:
verifier.validateCertUri = validateCertUri;
verifier.fetchCert = fetchCert;

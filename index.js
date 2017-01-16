var crypto          = require('crypto')
var fetchCert       = require('./fetch-cert')
var request         = require('request')
var tools           = require('openssl-cert-tools')
var url             = require('url')
var validator       = require('validator')
var validateCertUri = require('./validate-cert-uri')


// constants
var TIMESTAMP_TOLERANCE = 150
var SIGNATURE_FORMAT = 'base64'

function getCert(cert_url, callback) {
  var options = { url: url.parse(cert_url) }
  var result = validateCertUri(options.url)
  if (result !== true) {
    return callback(result)
  }

  fetchCert(options, function(er, pem_cert) {
    if (er) {
      return callback(er)
    }

    validateCert(pem_cert, function(er) {
      if (er) {
        return callback(er)
      }
      callback(er, pem_cert)
    })
  })
}


function validateCert(pem_cert, callback) {
  return tools.getCertificateInfo(pem_cert, function(er, info) {
    if (er) {
      return callback(er)
    }

    // check that the domain echo-api.amazon.com is present in the Subject
    // Alternative Names (SANs) section of the signing certificate
    if (info.subject.CN.indexOf('echo-api.amazon.com') === -1) {
      return callback('subjectAltName Check Failed')
    }

    // check that the signing certificate has not expired (examine both the Not
    // Before and Not After dates)
    if (info.remainingDays < 1) {
      return callback('certificate expiration check failed')
    }
    callback()
  })
}


// returns true if the signature for the request body is valid, false otherwise
function validateSignature(pem_cert, signature, requestBody) {
  var verifier
  verifier = crypto.createVerify('RSA-SHA1')
  verifier.update(requestBody)
  return verifier.verify(pem_cert, signature, SIGNATURE_FORMAT)
}


// determine if a timestamp is valid for a given request with a tolerance of
// TIMESTAMP_TOLERANCE seconds
// returns null if valid, or an error string otherwise
function validateTimestamp(requestBody) {
  var d, e, error, now, oldestTime, request_json
  request_json = null
  try {
    request_json = JSON.parse(requestBody)
  } catch (error) {
    e = error
    return 'request body invalid json'
  }
  if (!(request_json.request && request_json.request.timestamp)) {
    return 'Timestamp field not present in request'
  }
  d = new Date(request_json.request.timestamp)
  now = new Date()
  oldestTime = now.getTime() - (TIMESTAMP_TOLERANCE * 1000)
  if (d.getTime() < oldestTime) {
    return "Request is from more than " + TIMESTAMP_TOLERANCE + " seconds ago"
  }
  return null
}


// certificate validator express middleware for amazon echo
module.exports = function verifier(cert_url, signature, requestBody, callback) {
  var er
  if (cert_url == null) {
    cert_url = ''
  }
  if (signature == null) {
    signature = ''
  }
  if (requestBody == null) {
    requestBody = ''
  }
  if (callback == null) {
    callback = function() { }
  }
  if (!validator.isBase64(signature)) {
    return callback('signature is not base64 encoded')
  }
  er = validateTimestamp(requestBody)

  if (er) {
    return callback(er)
  }
  
  getCert(cert_url, function(er, pem_cert) {
    var success
    if (er) {
      return callback(er)
    }
    success = validateSignature(pem_cert, signature, requestBody)
    if (success !== true) {
      return callback('certificate verification failed')
    }
    callback()
  })
}

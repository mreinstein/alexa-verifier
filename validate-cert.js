'use strict'

var pki = require('node-forge').pki


// constants
var VALID_CERT_SAN = 'echo-api.amazon.com'

// @returns an error string if certificate isn't valid, undefined otherwise
module.exports = function validate (pem_cert) {
  try {
    var cert = pki.certificateFromPem(pem_cert)

    // check that cert has a Subject Alternative Names (SANs) section
    var altNameExt = cert.getExtension("subjectAltName")
    if (!altNameExt)
      return 'invalid certificate validity (subjectAltName extension not present)'

    // check that the domain echo-api.amazon.com is present in SANs section
    var domainExists = altNameExt.altNames.some(function(name) {
      return name.value === VALID_CERT_SAN
    })
    if(!domainExists)
      return 'invalid certificate validity (correct domain not found in subject alternative names)'

    var currTime = new Date().getTime()
    var notAfterTime = new Date(cert.validity.notAfter).getTime()
    if (notAfterTime <= currTime)
      return 'invalid certificate validity (past expired date)'

    var notBeforeTime = new Date(cert.validity.notBefore).getTime()
    if (currTime <= notBeforeTime)
      return 'invalid certificate validity (start date is in the future)'

  } catch (e) {
    return e
  }
}

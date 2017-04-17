var pki = require('node-forge').pki


// @returns an error string if certificate isn't valid, undefined otherwise
module.exports = function validate(pem_cert) {
  try {
    var cert = pki.certificateFromPem(pem_cert)

    // check that the domain echo-api.amazon.com is present in the Subject
    // Alternative Names (SANs) section of the signing certificate
    if (cert.subject.getField('CN').value.indexOf('echo-api.amazon.com') === -1) {
      return 'subjectAltName Check Failed'
    }

    // ensure that current time is earlier than cert's "Not After" time
    var currTime = new Date().getTime()
    var notAfterTime = new Date(cert.validity.notAfter).getTime()
    if (notAfterTime <= currTime) {
      return 'certificate Not After check failed'
    }

    // ensure that current time is later than cert's "Not Before" time
    var notBeforeTime = new Date(cert.validity.notBefore).getTime()
    if (currTime <= notBeforeTime) {
      return 'certificate Not Before check failed'
    }
  } catch (e) {
    return e
  }
}

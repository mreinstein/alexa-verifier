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

    // check that the signing certificate has not expired (examine Not After)
    var now = new Date().getTime()
    var notAfter = new Date(cert.validity.notAfter)
    var timeUntilAfter = notAfter.getTime() - now
    if (timeUntilAfter < 1) {
      return 'certificate Not After check failed'
    }

    // check that the signing certificate has not expired (examine Not Before)
    var notBefore = new Date(cert.validity.notBefore)
    var timeSinceBefore = now - notBefore.getTime()
    if (timeSinceBefore < 1) {
      return 'certificate Not Before check failed'
    }
  } catch (e) {
    return e
  }
}

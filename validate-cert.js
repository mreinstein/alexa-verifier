import pkg from 'node-forge'


const { pki } = pkg
const VALID_CERT_SAN = 'echo-api.amazon.com'


// @returns an error string if certificate isn't valid, undefined otherwise
export default function validate (pem_cert) {
    try {
        const cert = pki.certificateFromPem(pem_cert)

        // check that cert has a Subject Alternative Names (SANs) section
        const altNameExt = cert.getExtension('subjectAltName')
        if (!altNameExt)
            return 'invalid certificate validity (subjectAltName extension not present)'

        // check that the domain echo-api.amazon.com is present in SANs section
        const domainExists = altNameExt.altNames.some(function (name) {
            return name.value === VALID_CERT_SAN
        })

        if (!domainExists)
            return 'invalid certificate validity (correct domain not found in subject alternative names)'

        const currTime = new Date().getTime()
        const notAfterTime = new Date(cert.validity.notAfter).getTime()
        if (notAfterTime <= currTime)
            return 'invalid certificate validity (past expired date)'

        const notBeforeTime = new Date(cert.validity.notBefore).getTime()
        if (currTime <= notBeforeTime)
            return 'invalid certificate validity (start date is in the future)'

    } catch (e) {
        return e
    }
}

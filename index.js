import crypto          from 'crypto'
import fetchCert       from './fetch-cert.js'
import url             from 'url'
import validateCert    from './validate-cert.js'
import validateCertUri from './validate-cert-uri.js'
import validator       from 'validator'


const TIMESTAMP_TOLERANCE = 150
const SIGNATURE_FORMAT = 'base64'
const CHARACTER_ENCODING = 'utf8'


function getCert (cert_url, callback) {
    const options = { url: url.parse(cert_url) }
    const result = validateCertUri(options.url)
    if (result !== true)
        return process.nextTick(callback, result)

    fetchCert(options, function (er, pem_cert) {
        
        if (er)
            return callback(er)

        er = validateCert(pem_cert)
        if (er)
            return callback(er)

        callback(er, pem_cert)
    })
}


// returns true if the signature for the request body is valid, false otherwise
function isValidSignature (pem_cert, signature, requestBody) {
    const verifier = crypto.createVerify('RSA-SHA256')
    verifier.update(requestBody, CHARACTER_ENCODING)
    return verifier.verify(pem_cert, signature, SIGNATURE_FORMAT)
}


// determine if a timestamp is valid for a given request with a tolerance of
// TIMESTAMP_TOLERANCE seconds
// returns undefined if valid, or an error string otherwise
function validateTimestamp (requestBody) {
    let e, error, request_json

    try {
        request_json = JSON.parse(requestBody)
    } catch (error) {
        e = error
        return 'request body invalid json'
    }

    if (!(request_json.request && request_json.request.timestamp))
        return 'Timestamp field not present in request'

    const d = new Date(request_json.request.timestamp)
    const now = new Date()
    const oldestTime = now.getTime() - (TIMESTAMP_TOLERANCE * 1000)

    if (d.getTime() < oldestTime)
        return 'Request is from more than ' + TIMESTAMP_TOLERANCE + ' seconds ago'
}


function verifier (cert_url, signature, requestBody, callback) {
    if (!cert_url)
        return process.nextTick(callback, 'missing certificate url')

    if (!signature)
        return process.nextTick(callback, 'missing signature')

    if (!requestBody)
        return process.nextTick(callback, 'missing request (certificate) body')

    if (!validator.isBase64(signature))
        return process.nextTick(callback, 'invalid signature (not base64 encoded)')

    const er = validateTimestamp(requestBody)

    if (er)
        return process.nextTick(callback, er)

    getCert(cert_url, function (er, pem_cert) {
        if (er)
            return callback(er)

        if (!isValidSignature(pem_cert, signature, requestBody))
            return callback('invalid signature')

        callback()
    })
}


// certificate validator for amazon echo
export default function alexaVerifier (cert_url, signature, requestBody, cb) {
    if (cb)
        return verifier(cert_url, signature, requestBody, cb)

    return new Promise(function (resolve, reject) {
        verifier(cert_url, signature, requestBody, function (er) {
            if (er)
                return reject(er)
            resolve()
        })
  })
}

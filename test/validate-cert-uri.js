import { test }        from 'tap'
import unroll          from 'unroll'
import url             from 'url'
import validateCertUri from '../validate-cert-uri.js'


unroll.use(test)

unroll('verifier.validateCertUri should be #valid for #url',
    function (t, testArgs) {
        const cert_uri = url.parse(testArgs['url'])
        const result = validateCertUri(cert_uri)
        const valid = testArgs['valid']
        t.not(valid, undefined)
        if (valid === true) {
            t.equal(result, true)
        } else {
            // I don't need the error message, do negated comparison with 'true'
            t.not(result, true)
        }
        t.end()
    },
    [
        [ 'valid', 'url' ],
        [ true, 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem' ],
        [ true, 'HTTPS://s3.amazonaws.com/echo.api/echo-api-cert.pem' ],
        [ true, 'https://S3.AMAZONAWS.COM/echo.api/echo-api-cert.pem' ],
        [ true, 'https://s3.amazonaws.com:443/echo.api/echo-api-cert.pem' ],
        [ true, 'https://s3.amazonaws.com/echo.api/../echo.api/echo-api-cert.pem' ],
        [ false, 'http://s3.amazonaws.com/echo.api/echo-api-cert.pem' ],  // (invalid protocol)
        [ false, 'https://notamazon.com/echo.api/echo-api-cert.pem' ],  // (invalid hostname)
        [ false, 'https://s3.amazonaws.com/EcHo.aPi/echo-api-cert.pem' ],  // (invalid path)
        [ false, 'https://s3.amazonaws.com/invalid.path/echo-api-cert.pem' ],  // (invalid path)
        [ false, 'https://s3.amazonaws.com:563/echo.api/echo-api-cert.pem' ]  // (invalid port)
    ]
)

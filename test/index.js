import { test } from 'tap'
import crypto   from 'crypto'
import esmock   from 'esmock'
import fs       from 'fs'
import url      from 'url'
import verifier from '../index.js'
import sinon    from 'sinon'
import { dirname }       from 'path'
import { fileURLToPath } from 'url'


const __dirname = dirname(fileURLToPath(import.meta.url))

const cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert-12.pem' // latest valid cert

const rsaSha256Key = fs.readFileSync(`${__dirname}/mocks/rsa_sha256`).toString()
const validPem = fs.readFileSync(`${__dirname}/mocks/rsa_sha256_pub`).toString()


test('handle missing cert_url parameter', function (t) {
    const signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime()
        }
    }
    verifier(undefined, signature, JSON.stringify(body), function (er) {
        t.equal(er, 'missing certificate url')
        t.end()
    })
})


test('handle invalid cert_url parameter', function (t) {
    const signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime()
        }
    }

    verifier('http://someinsecureurl', signature, JSON.stringify(body), function (er) {
        t.equal(er.indexOf('Certificate URI MUST be https'), 0)
        t.end()
    })
})


test('handle invalid body json', function (t) {
    const signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
    verifier(cert_url, signature, '', function (er) {
        t.equal(er, 'missing request (certificate) body')
        t.end()
    })
})


test('handle missing timestamp field', function (t) {
    const signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
    verifier(cert_url, signature, '{}', function (er) {
        t.equal(er, 'Timestamp field not present in request')
        t.end()
    })
})


test('handle outdated timestamp field', function (t) {
    const signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime() - 200000
        }
    }
    verifier(cert_url, signature, JSON.stringify(body), function (er) {
        t.equal(er, 'Request is from more than 150 seconds ago')
        t.end()
    })
})


test('handle missing signature parameter', function (t) {
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime()
        }
    }
    verifier(cert_url, undefined, JSON.stringify(body), function (er) {
        t.equal(er, 'missing signature')
        t.end()
    })
})


test('handle invalid signature parameter', function (t) {
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime()
        }
    }
    verifier(cert_url, '....$#%@$se', JSON.stringify(body), function (er) {
        t.equal(er, 'invalid signature (not base64 encoded)')
        t.end()
    })
})


test('handle invalid base64-encoded signature parameter', function (t) {
    const now = new Date()
    const body = {
        request: {
            timestamp: now.getTime()
        }
    }
    verifier(cert_url, 'aGVsbG8NCg==', JSON.stringify(body), function (er) {
        t.equal(er, 'invalid signature')
        t.end()
    })
})


test('handle valid signature', async function (t) {

    const verifier = await esmock('../index.js', {
        '../fetch-cert.js': {
            default: function fetchCert (options, callback) {
                callback(undefined, validPem)
            }
        },
        '../validate-cert.js': {
            default: function validateCert (pem_cert) {
                // we're using our mocked sha256 pub/private keypair, so skip all the validation unrelated to
                // signature checking.
            }
        },
    })


    const ts = '2019-09-01T07:27:59Z'
    const now = new Date(ts)
    const clock = sinon.useFakeTimers(now.getTime())
    
    const body = {
        "version": "1.0",
        "session": {
            "new": true,
            "sessionId": "SessionId.7745e45d-3042-45eb-8e86-cab2cf285daf",
            "application": {
                "applicationId": "amzn1.ask.skill.75c997b8-610f-4eb4-bf2e-95810e15fba2"
            },
            "attributes": {},
            "user": {
                "userId": "amzn1.ask.account.AF6Z7574YHBQCNNTJK45QROUSCUJEHIYAHZRP35FVU673VDGDKV4PH2M52PX4XWGCSYDM66B6SKEEFJN6RYWN7EME3FKASDIG7DPNGFFFNTN4ZT6B64IIZKSNTXQXEMVBXMA7J3FN3ERT2A4EDYFUYMGM4NSQU4RTAQOZWDD2J7JH6P2ROP2A6QEGLNLZDXNZU2DL7BKGCVLMNA"
            }
        },
        "request": {
            "type": "IntentRequest",
            "requestId": "EdwRequestId.fa7428b7-75d0-44c8-aebb-4c222ed48ebe",
            "timestamp": ts,
            "locale": "en-US",
            "intent": {
                "name": "HelloWorld"
            },
            "inDialog": false
        }
    }

    const requestEnvelope = JSON.stringify(body)
    const signer = crypto.createSign('RSA-SHA256')
    signer.update(requestEnvelope)
    const signature = signer.sign(rsaSha256Key, 'base64');

    verifier(cert_url, signature, requestEnvelope, function (er) {
        t.equal(er, undefined)
        clock.restore()
    })
})


test('handle valid signature with double byte utf8 encodings', async function (t) {
    const verifier = await esmock('../index.js', {
        '../fetch-cert.js': {
            default: function fetchCert (options, callback) {
                callback(undefined, validPem)
            }
        },
        '../validate-cert.js': {
            default: function validateCert (pem_cert) {
                // we're using our mocked sha256 pub/private keypair, so skip all the validation unrelated to
                // signature checking.
            }
        },
    })

    const ts = '2017-04-05T12:02:36Z'
    const now = new Date(ts)
    const clock = sinon.useFakeTimers(now.getTime())
    
    const body = {
        "version":"1.0",
        "session": {
            "new":true,
            "sessionId":"SessionId.07e59233-1f59-43f9-bfc1-ac3ae3b843c6",
            "application": {
                "applicationId":"amzn1.ask.skill.5535124f-0d41-472a-be31-589b1d3d04bf"
            },
            "attributes": {

            },
            "user": {
                "userId":"amzn1.ask.account.AGDZF2M6WHR5KHCXH5ODUYS6VUFUKNI2TABAZSUABKCMIEILVW5ZVME7OI2IOPPV4V7DAYVHMU2CMABL4HTCF7R33N2D6OH7QBEVTSGJUCYZPFX4EQO56TRHEHYUME3BSSDETEJUFFGB4JZBB6OCNQ2A7EKQHW6JQL5YK2HMIDH4ADCCQRJ24SFWBMENZUDPXWN2UNLP42EA4FQ"
            }
        },
        "request": {
            "type":"IntentRequest",
            "requestId":"EdwRequestId.5581fcba-e41a-4059-a9d7-eb7b46f2a543",
            "timestamp":"2017-04-05T12:02:36Z",
            "locale":"en-US",
            "intent":{
                "name":"Ask_term_info",
                "slots":{
                    "termslot":{
                        "name":"termslot",
                        "value":"Pokémon"
                    }
                }
            }
        }
    }

    const requestEnvelope = JSON.stringify(body)
    const signer = crypto.createSign('RSA-SHA256')
    signer.update(requestEnvelope)
    const signature = signer.sign(rsaSha256Key, 'base64');

    verifier(cert_url, signature, JSON.stringify(body), function (er) {
        t.equal(er, undefined)
        clock.restore()
        t.end()
    })
})


test('invocation', function (t) {
    const ts = '2017-04-05T12:02:36Z'
    const signature = ''
    const body = {
        "version": "1.0",
        "session": {
            "new": true,
            "sessionId": "SessionId.7745e45d-3042-45eb-8e86-cab2cf285daf",
            "application": {
                "applicationId": "amzn1.ask.skill.75c997b8-610f-4eb4-bf2e-95810e15fba2"
            },
            "attributes": {},
            "user": {
                "userId": "amzn1.ask.account.AF6Z7574YHBQCNNTJK45QROUSCUJEHIYAHZRP35FVU673VDGDKV4PH2M52PX4XWGCSYDM66B6SKEEFJN6RYWN7EME3FKASDIG7DPNGFFFNTN4ZT6B64IIZKSNTXQXEMVBXMA7J3FN3ERT2A4EDYFUYMGM4NSQU4RTAQOZWDD2J7JH6P2ROP2A6QEGLNLZDXNZU2DL7BKGCVLMNA"
            }
        },
        "request": {
            "type": "IntentRequest",
            "requestId": "EdwRequestId.fa7428b7-75d0-44c8-aebb-4c222ed48ebe",
            "timestamp": ts,
            "locale": "en-US",
            "intent": {
                "name": "HelloWorld"
            },
            "inDialog": false
        }
    }

    const result = verifier(cert_url, signature, JSON.stringify(body))
    result.catch(function (er) { })
    t.ok(result instanceof Promise, 'omitting callback returns a promise')

    const callbackResult = verifier(cert_url, signature, JSON.stringify(body), function (er) { })

    t.equal(callbackResult, undefined, 'including callback does not return a promise')

    t.end()
})

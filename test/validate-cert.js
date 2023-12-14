import fs                from 'fs'
import pkg               from 'node-forge'
import { test }          from 'tap'
import url               from 'url'
import validate          from '../validate-cert.js'
import { dirname }       from 'path'
import { fileURLToPath } from 'url'


const __dirname = dirname(fileURLToPath(import.meta.url))
const { pki } = pkg


function createInvalidCert () {
    const keys = pki.rsa.generateKeyPair(512)
    const cert = pki.createCertificate()
    cert.publicKey = keys.publicKey
    // alternatively set public key from a csr
    //cert.publicKey = csr.publicKey
    cert.serialNumber = '01'
    cert.validity.notBefore = new Date()
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
    const attrs = [
        {
            name: 'commonName',
            value: 'example.org'
        },
        {
            name: 'countryName',
            value: 'US'
        },
        {
            shortName: 'ST',
            value: 'Virginia'
        },
        {
            name: 'localityName',
            value: 'Blacksburg'
        },
        {
            name: 'organizationName',
            value: 'Test'
        },
        {
            shortName: 'OU',
            value: 'Test'
        }
    ]

    cert.setSubject(attrs)
    // alternatively set subject from a csr
    //cert.setSubject(csr.subject.attributes)
    cert.setIssuer(attrs)
    cert.setExtensions([
        {
            name: 'basicConstraints',
            cA: true
        },
        {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        },
        {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        },
        {
            name: 'nsCertType',
            client: true,
            server: true,
            email: true,
            objsign: true,
            sslCA: true,
            emailCA: true,
            objCA: true
        },
        {
            name: 'subjectAltName',
            altNames: [{
                type: 6, // URI
                value: 'http://example.org/webid#me'
            },
            {
                type: 7, // IP
                ip: '127.0.0.1'
            }]
        },
        {
            name: 'subjectKeyIdentifier'
        }
    ])

    // self-sign certificate
    cert.sign(keys.privateKey)

    return pki.certificateToPem(cert)
}


test('fails on invalid pem cert parameter', function (t) {
    t.ok(validate(undefined) !== undefined, 'Error should have been thrown')
    t.end()
})

test('fails on non amazon subject alt name', function (t) {
    const pem = createInvalidCert()
    t.ok(validate(pem) === 'invalid certificate validity (correct domain not found in subject alternative names)', 'Certificate must be from amazon')
    t.end()
})

test('fails on expired certificate (Not After)', function (t) {
    const pem = fs.readFileSync(__dirname + '/mocks/cert-expired.pem')
    t.ok(validate(pem) === 'invalid certificate validity (past expired date)')
    t.end()
})

test('approves valid certifcate', function (t) {
    const pem = fs.readFileSync(__dirname + '/mocks/echo-api-cert-12.cer')
    t.ok(validate(pem) === undefined, 'Certificate should be valid')
    t.end()
})

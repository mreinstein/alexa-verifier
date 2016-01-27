crypto  = require 'crypto'
fs      = require 'fs'
os      = require 'os'
request = require 'request'
tools   = require 'openssl-cert-tools'
url     = require 'url'


# certificate validator express middleware for amazon echo

# global constants
TIMESTAMP_TOLERANCE = 150
VALID_CERT_HOSTNAME = 's3.amazonaws.com'
VALID_CERT_PATH_START = '/echo.api/'
VALID_CERT_PORT = 443
SIGNATURE_FORMAT = 'base64'


md5 = (input) -> crypto.createHash('sha1').update(input).digest 'hex'


getCert = (cert_url, callback) ->
  tmpdir = '/tmp' # os.tmpdir()
  cert_filepath = tmpdir + '/' + md5(cert_url) + '.pem'

  fs.stat cert_filepath, (er, stat) ->
    if stat
      fs.readFile cert_filepath, 'utf8', callback
    else
      cert_uri = url.parse cert_url
      result = validateCertUri cert_uri
      if result isnt true
        return callback(result)

      fetchCert cert_uri, (er, pem_cert) ->
        if er
          return callback(er)
        validateCert pem_cert, (er) ->
          if er
            return callback(er)
          fs.writeFile cert_filepath, pem_cert, 'utf8', (er) ->
            callback er, pem_cert


fetchCert = (uri, callback) ->
  cert_url = "https://#{uri.host}:#{uri.port or ''}/#{uri.path}"
  request.get cert_url, (er, response, body) ->
    if body
      callback null, body
    else
      callback "Failed to download certificate at: #{cert_url}. Response code: #{response.code}, error: #{body}"


# parse a certificate and check it's contents for validity
validateCert = (pem_cert, callback) ->
  tools.getCertificateInfo pem_cert, (er, info) ->
    if er
      return callback(er)

    # check that the domain echo-api.amazon.com is present in the Subject Alternative Names (SANs) section of the signing certificate
    if info.subject.CN.indexOf('echo-api.amazon.com') is -1
      return callback('subjectAltName Check Failed')

    # check that the signing certificate has not expired (examine both the Not Before and Not After dates)
    if info.remainingDays < 1
      return callback('certificate expiration check failed')
    callback()


validateCertUri = (cert_uri) ->
  if cert_uri.protocol isnt 'https:'
    return "Certificate URI MUST be https: #{cert_uri}"

  if cert_uri.port and (cert_uri.port isnt VALID_CERT_PORT)
    return "Certificate URI port MUST be #{VALID_CERT_PORT}, was: #{cert_uri.port}"

  if cert_uri.host isnt VALID_CERT_HOSTNAME
    return "Certificate URI hostname must be #{VALID_CERT_HOSTNAME}: #{cert_uri}"

  if cert_uri.path.indexOf(VALID_CERT_PATH_START) isnt 0
    return "Certificate URI path must start with #{VALID_CERT_PATH_START}: #{cert_uri}"
  true


# returns true if the signature for the request body is valid, false otherwise
validateSignature = (pem_cert, signature, requestBody) ->
  verifier = crypto.createVerify 'RSA-SHA1'
  verifier.update requestBody
  verifier.verify pem_cert, signature, SIGNATURE_FORMAT


# determine if a timestamp is valid for a given request with a tolerance of
# TIMESTAMP_TOLERANCE seconds
# returns null if valid, or an error string otherwise
validateTimestamp = (requestBody) ->
  request_json = JSON.parse requestBody
  if not (request_json.request and request_json.request.timestamp)
    return 'Timestamp field not present in request'

  d = new Date request_json.request.timestamp
  now = new Date()
  oldestTime = now.getTime() - (TIMESTAMP_TOLERANCE * 1000)
  if d.getTime() < oldestTime
    return "Request is from more than #{TIMESTAMP_TOLERANCE} seconds ago"
  null


module.exports = (cert_url, signature, requestBody, callback) ->
  er = validateTimestamp requestBody
  if er
    return callback(er)

  getCert cert_url, (er, pem_cert) ->
    if er
      return callback(er)
    success = validateSignature pem_cert, signature, requestBody
    if success isnt true
      return callback('certificate verification failed')
    callback()

'use strict'

var https = require('https')


var globalCache = {} // default in-memory cache for downloaded certificates

module.exports = function fetchCert(options, callback) {
  var cache = options.cache || globalCache
  var cachedResponse = cache[options.request.href]
  var servedFromCache = false
  if (cachedResponse) {
    servedFromCache = true
    process.nextTick(callback, undefined, cachedResponse, servedFromCache)
    return
  }

  var body = ''

  https.get(options.request, function(response) {
    var statusCode

    if (!response || 200 !== response.statusCode) {
      statusCode = response ? response.statusCode : 0
      return callback('Failed to download certificate at: ' + options.request.href + '. Response code: ' + statusCode)
    }

    response.setEncoding('utf8')
    response.on('data', function (chunk) {
      body += chunk
    })
    response.on('end', function () {
      cache[options.request.href] = body
      callback(undefined, body, servedFromCache)
    })
  })
  .on('error', function(er) {
    callback('Failed to download certificate at: ' + options.request.href +'. Error: ' + er)
  })
}

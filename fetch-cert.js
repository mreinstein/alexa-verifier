'use strict'

var https = require('https')


var globalCache = {} // default in-memory cache for downloaded certificates

module.exports = function fetchCert (options, callback) {
  var url = options.url
  var cache = options.cache || globalCache
  var cachedResponse = cache[url.href]
  var servedFromCache = false
  if (cachedResponse) {
    servedFromCache = true
    process.nextTick(callback, undefined, cachedResponse, servedFromCache)
    return
  }

  var body = ''

  https.get(url.href, function (response) {
    var statusCode

    if (!response || 200 !== response.statusCode) {
      statusCode = response ? response.statusCode : 0
      return callback('Failed to download certificate at: ' + url.href + '. Response code: ' + statusCode)
    }

    response.setEncoding('utf8')
    response.on('data', function (chunk) {
      body += chunk
    })
    response.on('end', function () {
      cache[url.href] = body
      callback(undefined, body, servedFromCache)
    })
  })
  .on('error', function(er) {
    callback('Failed to download certificate at: ' + url.href +'. Error: ' + er)
  })
}

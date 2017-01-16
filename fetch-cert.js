var request = require('request')


// Default in-memory cache for downloaded certificates,
// used if no cache is explicitely passed.
var globalCache = {}

module.exports = function fetchCert(options, callback) {
  var url = options.url
  var cache = options.cache || globalCache
  var cachedResponse = cache[url.href]
  var servedFromCache = false
  if (cachedResponse) {
    servedFromCache = true
    callback(null, cachedResponse, servedFromCache)
    return
  }

  request.get(url.href, function(er, response, body) {
    var statusCode
    if (response && 200 === response.statusCode) {
      cache[url.href] = body
      callback(null, body, servedFromCache)
    } else {
      statusCode = response ? response.statusCode : 0
      callback('Failed to download certificate at: ' + url.href + '. Response code: ' + statusCode + ', error: ' + er)
    }
  })
}

import https from 'https'


const globalCache = { } // default in-memory cache for downloaded certificates


export default function fetchCert (options, callback) {
    const url = options.url
    const cache = options.cache || globalCache
    const cachedResponse = cache[url.href]
    let servedFromCache = false
    if (cachedResponse) {
        servedFromCache = true
        process.nextTick(callback, undefined, cachedResponse, servedFromCache)
        return
    }

    let body = ''

    https.get(url.href, function (response) {
        if (!response || 200 !== response.statusCode) {
            const statusCode = response ? response.statusCode : 0
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
    .on('error', function (er) {
        callback('Failed to download certificate at: ' + url.href +'. Error: ' + er)
    })
}

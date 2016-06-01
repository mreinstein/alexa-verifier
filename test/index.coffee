test     = require('tap').test
verifier = require '../'


#verifier(cert_url, signature, requestBody, callback)

test 'handle invalid cert_url parameter', (t) ->
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
  now = new Date()
  body = request: timestamp: now.getTime()
  verifier undefined, signature, JSON.stringify(body), (er) ->
    t.equal er.indexOf('Certificate URI MUST be https'), 0
    t.end()


test 'handle invalid body json', (t) ->
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
  
  verifier cert_url, signature, '', (er) ->
    t.equal er, 'request body invalid json'
    t.end()


test 'handle missing timestamp field', (t) ->
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
  
  verifier cert_url, signature, '{}', (er) ->
    t.equal er, 'Timestamp field not present in request'
    t.end()


test 'handle outdated timestamp field', (t) ->
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg=='
  now = new Date()
  body = request: timestamp: (now.getTime() - 200000)

  verifier cert_url, signature, JSON.stringify(body), (er) ->
    t.equal er, 'Request is from more than 150 seconds ago'
    t.end()


test 'handle missing signature parameter', (t) ->
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'
  now = new Date()
  body = request: timestamp: now.getTime()
  verifier cert_url, undefined, JSON.stringify(body), (er) ->
    t.equal er, 'signature is not base64 encoded'
    t.end()


test 'handle invalid signature parameter', (t) ->
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'
  now = new Date()
  body = request: timestamp: now.getTime()
  verifier cert_url, '....$#%@$se', JSON.stringify(body), (er) ->
    t.equal er, 'signature is not base64 encoded'
    t.end()

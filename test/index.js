var test     = require('tap').test;
var verifier = require('../');


test('handle invalid cert_url parameter', function(t) {
  var body, now, signature;
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg==';
  now = new Date();
  body = {
    request: {
      timestamp: now.getTime()
    }
  };
  verifier(void 0, signature, JSON.stringify(body), function(er) {
    t.equal(er.indexOf('Certificate URI MUST be https'), 0);
    t.end();
  });
});


test('handle invalid body json', function(t) {
  var cert_url, signature;
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg==';
  verifier(cert_url, signature, '', function(er) {
    t.equal(er, 'request body invalid json');
    t.end();
  });
});


test('handle missing timestamp field', function(t) {
  var cert_url, signature;
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg==';
  verifier(cert_url, signature, '{}', function(er) {
    t.equal(er, 'Timestamp field not present in request');
    t.end();
  });
});


test('handle outdated timestamp field', function(t) {
  var body, cert_url, now, signature;
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  signature = 'JbWZ4iO5ogpq1NhsOqyqq/QRrvc1/XyDwjcBO9wWSk//c11+gImmtWzMG9tDEW40t0Xwt1cnGU93DwUZQzMyzJ5CMi+09qVQUSIHiSmPekKaQRxS0Ibu7l7cXXuCcOBupbkheD/Dsd897Bm5SQwd1cFKRv+PJlpmGKimgh2QmbivogsEkFl8b9SW48kjKWazwj/XP2SrHY0bTvwMTVu7zvTcp0ZenEGlY2DNr5zSd1n6lmS6rgAt1IPwhBzqI0PVMngaM0DQhB0wUPj3QoIUh0IyMVAQzRFbQpS4UGrA4M9a5a+AGy0jCQKiRCI+Yi9iZYEVYvfafF/lyOUHHYcpOg==';
  now = new Date();
  body = {
    request: {
      timestamp: now.getTime() - 200000
    }
  };
  verifier(cert_url, signature, JSON.stringify(body), function(er) {
    t.equal(er, 'Request is from more than 150 seconds ago');
    t.end();
  });
});


test('handle missing signature parameter', function(t) {
  var body, cert_url, now;
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  now = new Date();
  body = {
    request: {
      timestamp: now.getTime()
    }
  };
  verifier(cert_url, void 0, JSON.stringify(body), function(er) {
    t.equal(er, 'signature is not base64 encoded');
    t.end();
  });
});


test('handle invalid signature parameter', function(t) {
  var body, cert_url, now;
  cert_url = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  now = new Date();
  body = {
    request: {
      timestamp: now.getTime()
    }
  };
  verifier(cert_url, '....$#%@$se', JSON.stringify(body), function(er) {
    t.equal(er, 'signature is not base64 encoded');
    t.end();
  });
});

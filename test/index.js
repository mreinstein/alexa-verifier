var nock     = require('nock');
var test     = require('tap').test;
var unroll   = require('unroll');
unroll.use(test);

var url      = require('url');
var verifier = require('../');

unroll('verifier.validateCertUri should be #valid for #url',
  function(t, testArgs) {
    var cert_uri = url.parse(testArgs['url']);
    var result = verifier.validateCertUri(cert_uri);
    var valid = testArgs['valid'];
    t.notEqual(valid, undefined);
    if (valid === true) {
      t.equal(result, true);
    } else {
      // I don't care too much about the error message, so do negated
      // comparison with 'true':
      t.notEqual(result, true);
    }
    t.end();
  },
  [
    ['valid', 'url'],
    [true, 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem'],
    [true, 'HTTPS://s3.amazonaws.com/echo.api/echo-api-cert.pem'],
    [true, 'https://S3.AMAZONAWS.COM/echo.api/echo-api-cert.pem'],
    [true, 'https://s3.amazonaws.com:443/echo.api/echo-api-cert.pem'],
    [true, 'https://s3.amazonaws.com/echo.api/../echo.api/echo-api-cert.pem'],
    [false, 'http://s3.amazonaws.com/echo.api/echo-api-cert.pem'],  // (invalid protocol)
    [false, 'https://notamazon.com/echo.api/echo-api-cert.pem'],  // (invalid hostname)
    [false, 'https://s3.amazonaws.com/EcHo.aPi/echo-api-cert.pem'],  // (invalid path)
    [false, 'https://s3.amazonaws.com/invalid.path/echo-api-cert.pem'],  // (invalid path)
    [false, 'https://s3.amazonaws.com:563/echo.api/echo-api-cert.pem']  // (invalid port)
  ]
);

let doFetchCertAndAssert = function(
    t, mock_status, mock_resp, expected_pem_cert, cache, cb) {
  let url_string = 'https://s3.amazonaws.com/echo.api/echo-api-cert.pem';
  let cert_url = url.parse(url_string);
  if (mock_status && mock_resp) {
    nock('https://s3.amazonaws.com')
      .get(cert_url.path)
      .reply(mock_status, mock_resp);
  }
  verifier.fetchCert(cert_url, cache, (er, pem_cert) => {
    if (expected_pem_cert) {
      t.equal(er, null);
      t.equal(pem_cert, expected_pem_cert);
    } else {
      t.notEqual(er, null);
      t.equal(pem_cert, undefined);
    }
    if (cb) {
      cb(t);
    } else {
      t.end();
    }
  });
}

test('verifier.fetchCert should ignore response for error HTTP status', (t) => {
  doFetchCertAndAssert(t, 400, 'Bad Request', null);
});

test('verifier.fetchCert should call back with response body for OK HTTP status', (t) => {
  let pem_data = 'mock pem data';
  doFetchCertAndAssert(t, 200, pem_data, pem_data);
});

test('verifier.fetchCert should hit cache for subsequent certificate reqs', (t) => {
  let cache = {};
  let pem_data = 'mock pem data';
  doFetchCertAndAssert(t, 200, pem_data, pem_data, cache, (t) => {
    // pass undefined to avoid setting up nock. If a cache miss would occur,
    // nock would throw an exception.
    doFetchCertAndAssert(t, undefined, undefined, pem_data, cache);
  });
});

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

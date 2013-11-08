#!/usr/bin/python
# TODO: Use tracy (https://github.com/MerlijnWajer/tracy) to see if lwan
#       performs certain system calls. This should speed up the mmap tests
#       considerably and make it possible to perform more low-level tests.

import subprocess
import time
import unittest
import requests
import socket


class LwanTest(unittest.TestCase):
  def setUp(self):
    self.lwan = subprocess.Popen(['./build/lwan/lwan'],
          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    while True:
      try:
        requests.get('http://127.0.0.1:8080/hello')
        return
      except requests.ConnectionError:
        pass

  def tearDown(self):
    self.lwan.poll()
    if self.lwan.returncode is not None:
      self.assertEqual(self.lwan.returncode, 0)
    else:
      self.lwan.kill()


class TestFileServing(LwanTest):
  def test_mime_type_is_correct(self):
    table = (
      ('/', 'text/html'),
      ('/icons/back.png', 'image/png'),
      ('/icons', 'text/html'),
      ('/zero', 'application/octet-stream')
    )

    for path, expected_mime in table:
      r = requests.head('http://127.0.0.1:8080%s' % path)
      self.assertEqual(r.headers['content-type'], expected_mime)


  def test_non_existent_file_yields_404(self):
    r = requests.get('http://127.0.0.1:8080/icons/non-existent-file.png')

    self.assertTrue(r.status_code, 404)
    self.assertTrue(r.headers['content-type'], 'text/html')


  def test_dot_dot_slash_yields_404(self):
    r = requests.get('http://127.0.0.1:8080/../../../../../../../../../etc/passwd')

    self.assertTrue(r.status_code, 404)
    self.assertTrue(r.headers['content-type'], 'text/html')


  def test_slash_slash_slash_does_not_matter_200(self):
    r = requests.get('http://127.0.0.1:8080//////////icons/file.png')

    self.assertEqual(r.status_code, 200)
    self.assertTrue(r.headers['content-type'], 'image/png')


  def test_slash_slash_slash_does_not_matter_404(self):
    r = requests.get('http://127.0.0.1:8080//////////etc/passwd')

    self.assertEqual(r.status_code, 404)
    self.assertTrue(r.headers['content-type'], 'text/html')


  def test_head_request_small_file(self):
    r = requests.head('http://127.0.0.1:8080/100.html',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/html')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '100')

    self.assertEqual(r.text, '')


  def test_head_request_larger_file(self):
    r = requests.head('http://127.0.0.1:8080/zero',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '32768')

    self.assertEqual(r.text, '')


  def test_uncompressed_small_file(self):
    r = requests.get('http://127.0.0.1:8080/100.html',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/html')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '100')

    self.assertEqual(r.text, 'X' * 100)


  def test_compressed_small_file(self):
    encodings = (
      'deflate',
      ' deflate',
      'foo,bar,deflate',
      'foo, bar, deflate',
      'deflote' # This should fail, but won't in our current implementation
    )

    for encoding in encodings:
      r = requests.get('http://127.0.0.1:8080/100.html',
            headers={'Accept-Encoding': encoding})

      self.assertEqual(r.status_code, 200)

      self.assertTrue('content-type' in r.headers)
      self.assertEqual(r.headers['content-type'], 'text/html')

      self.assertTrue('content-length' in r.headers)
      self.assertLess(int(r.headers['content-length']), 100)

      self.assertTrue('content-encoding' in r.headers)
      self.assertEqual(r.headers['content-encoding'], 'deflate')

      self.assertEqual(r.text, 'X' * 100)


  def test_get_larger_file(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '32768')

    self.assertEqual(r.text, '\0' * 32768)


  def test_directory_listing(self):
    r = requests.get('http://127.0.0.1:8080/icons',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/html')

    self.assertTrue('<h1>Index of /icons</h1>' in r.text)

    def assertHasImage(name):
      imgtag = "<a href=\"/icons/%s.png\">%s.png</a>" % (name, name)
      self.assertTrue(imgtag in r.text)

    assertHasImage('back')
    assertHasImage('file')
    assertHasImage('folder')

    self.assertTrue('</html>' in r.text)


  def test_has_lwan_server_header(self):
    r = requests.get('http://127.0.0.1:8080/100.html')
    self.assertTrue('server' in r.headers)
    self.assertEqual(r.headers['server'], 'lwan')


  def test_directory_without_trailing_slash_redirects(self):
    r = requests.get('http://127.0.0.1:8080/icons', allow_redirects=False)

    self.assertEqual(r.status_code, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/icons/')


class TestMalformedRequests(LwanTest):
  def connect(self, host='127.0.0.1', port=8080):
    def _connect(host, port):
      try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.connect((host, port))
      except socket.error:
          return None
      return sock

    sock = _connect(host, port)
    self.assertNotEqual(sock, None)
    return sock


  def assertHttpCode(self, sock, code):
    contents = sock.recv(128)

    self.assertRegexpMatches(contents, r'^HTTP/1\.[01] ' + str(code) + r' ')


  def test_cat_sleeping_on_keyboard(self):
    sock = self.connect()
    sock.send('asldkfjg238045tgqwdcjv1li	2u4ftw dfjkb12345t\r\n\r\n')

    self.assertHttpCode(sock, 405)


  def test_no_http_version_fails(self):
    sock = self.connect()
    sock.send('GET /\r\n\r\n')

    self.assertHttpCode(sock, 400)


  def test_proxy_get_fails(self):
    sock = self.connect()
    sock.send('GET http://example.com HTTP/1.0\r\n\r\n')

    self.assertHttpCode(sock, 400)


  def test_get_not_http(self):
    sock = self.connect()
    sock.send('GET / FROG/1.0\r\n\r\n')

    self.assertHttpCode(sock, 400)


  def test_get_http_not_1_x(self):
    sock = self.connect()
    sock.send('GET / HTTP/2.0\r\n\r\n')

    self.assertHttpCode(sock, 400)


  def test_post_request(self):
    r = requests.post('http://127.0.0.1:8080/hello')

    self.assertEqual(r.status_code, 405)


  def test_request_too_large(self):
    r = requests.get('http://127.0.0.1:8080/' + 'X' * 10000)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/html')

    self.assertEqual(r.status_code, 413)


class TestHelloWorld(LwanTest):
  def test_head_request_hello(self):
    r = requests.head('http://127.0.0.1:8080/hello',
          headers={'Accept-Encoding': 'foobar'})

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/plain')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']), len('Hello, world!'))

    self.assertEqual(r.text, '')


  def test_has_custom_header(self):
    r = requests.get('http://127.0.0.1:8080/hello')

    self.assertTrue('x-the-answer-to-the-universal-question' in r.headers)
    self.assertEqual(r.headers['x-the-answer-to-the-universal-question'], '42')


  def test_no_param(self):
    r = requests.get('http://127.0.0.1:8080/hello')

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/plain')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']), len('Hello, world!'))

    self.assertEqual(r.text, 'Hello, world!')


  def test_with_param(self):
    r = requests.get('http://127.0.0.1:8080/hello?name=testsuite')

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/plain')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']),
          len('Hello, testsuite!'))

    self.assertEqual(r.text, 'Hello, testsuite!')


  def test_with_param_and_fragment(self):
    r = requests.get('http://127.0.0.1:8080/hello?name=testsuite#fragment')

    self.assertEqual(r.status_code, 200)

    self.assertTrue('content-type' in r.headers)
    self.assertEqual(r.headers['content-type'], 'text/plain')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']),
          len('Hello, testsuite!'))

    self.assertEqual(r.text, 'Hello, testsuite!')


class TestCache(LwanTest):
  def mmaps(self, f):
    f = f + '\n'
    return (l.endswith(f) for l in
                file('/proc/%d/maps' % self.lwan.pid))


  def count_mmaps(self, f):
    return sum(self.mmaps(f))


  def is_mmapped(self, f):
    return any(self.mmaps(f))


  def test_cache_munmaps_conn_close(self):
    r = requests.get('http://127.0.0.1:8080/100.html')

    self.assertTrue(self.is_mmapped('/100.html'))
    time.sleep(20)
    self.assertFalse(self.is_mmapped('/100.html'))


  def test_cache_munmaps_conn_keep_alive(self):
    s = requests.Session()
    r = s.get('http://127.0.0.1:8080/100.html')

    self.assertTrue(self.is_mmapped('/100.html'))
    time.sleep(20)
    self.assertFalse(self.is_mmapped('/100.html'))


  def test_cache_does_not_mmap_large_files(self):
    r = requests.get('http://127.0.0.1:8080/zero')
    self.assertFalse(self.is_mmapped('/zero'))


  def test_cache_mmaps_once_conn_keep_alive(self):
    s = requests.Session()

    for request in range(5):
      r = s.get('http://127.0.0.1:8080/100.html')
      self.assertEqual(self.count_mmaps('/100.html'), 1)


  def test_cache_mmaps_once_conn_close(self):
    for request in range(5):
      requests.get('http://127.0.0.1:8080/100.html')
      self.assertEqual(self.count_mmaps('/100.html'), 1)


  def test_cache_mmaps_once_even_after_timeout(self):
    for request in range(5):
      requests.get('http://127.0.0.1:8080/100.html')
      self.assertEqual(self.count_mmaps('/100.html'), 1)

    time.sleep(10)

    requests.get('http://127.0.0.1:8080/100.html')
    self.assertEqual(self.count_mmaps('/100.html'), 1)

if __name__ == '__main__':
  unittest.main()

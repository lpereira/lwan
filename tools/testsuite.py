#!/usr/bin/python
# TODO: Use tracy (https://github.com/MerlijnWajer/tracy) to see if lwan
#       performs certain system calls. This should speed up the mmap tests
#       considerably and make it possible to perform more low-level tests.

import os
import re
import requests
import signal
import socket
import subprocess
import sys
import time
import unittest

LWAN_PATH = './build/testrunner/testrunner'
for arg in sys.argv[1:]:
  if not arg.startswith('-') and os.path.exists(arg):
    LWAN_PATH = arg
    sys.argv.remove(arg)

print('Using', LWAN_PATH, 'for lwan')

class LwanTest(unittest.TestCase):
  def setUp(self):
    for spawn_try in range(20):
      self.lwan=subprocess.Popen(
        [LWAN_PATH],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
      )
      for request_try in range(20):
        try:
          requests.get('http://127.0.0.1:8080/hello')
          return
        except requests.ConnectionError:
          time.sleep(0.1)

      time.sleep(0.1)

    raise Exception('Timeout waiting for lwan')

  def tearDown(self):
    try:
      requests.get('http://127.0.0.1:8080/quit-lwan')
    except requests.exceptions.ConnectionError:
      # Requesting /quit-lwan will make testrunner exit(0), closing the
      # connection without sending a response, raising this exception.
      # That's expected here.
      return
    finally:
      with self.lwan as l:
        l.communicate(timeout=1.0)
        l.kill()

  def assertHttpResponseValid(self, request, status_code, content_type):
    self.assertEqual(request.status_code, status_code)
    self.assertTrue('Content-Type' in request.headers)
    self.assertEqual(request.headers['Content-Type'], content_type)

  def assertResponse404(self, request):
    self.assertHttpResponseValid(request, 404, 'text/html')

  def assertResponseHtml(self, request, status_code=200):
    self.assertHttpResponseValid(request, status_code, 'text/html')

  def assertResponsePlain(self, request, status_code=200):
    self.assertHttpResponseValid(request, status_code, 'text/plain')


class TestPost(LwanTest):
  def test_will_it_blend(self):
    r = requests.post('http://127.0.0.1:8080/post/blend', json={'will-it-blend': True})
    self.assertHttpResponseValid(r, 200, 'application/json')
    self.assertEqual(r.json(), {'did-it-blend': 'oh-hell-yeah'})

  def make_request_with_size(self, size):
    data = "tro" + "lo" * size

    r = requests.post('http://127.0.0.1:8080/post/big', data=data,
      headers={'Content-Type': 'x-test/trololo'})

    self.assertHttpResponseValid(r, 200, 'application/json')
    self.assertEqual(r.json(), {
      'received': len(data),
      'sum': sum(ord(b) for b in data)
    })

  def test_small_request(self): self.make_request_with_size(10)
  def test_medium_request(self): self.make_request_with_size(100)
  def test_large_request(self): self.make_request_with_size(1000)
  def test_huge_request(self): self.make_request_with_size(10000)
  def test_gigantic_request(self): self.make_request_with_size(100000)


class TestFileServing(LwanTest):
  def test_mime_type_is_correct(self):
    table = (
      ('/', 'text/html'),
      ('/icons/back.png', 'image/png'),
      ('/icons', 'text/plain'),
      ('/icons/', 'text/html'),
      ('/zero', 'application/octet-stream')
    )

    for path, expected_mime in table:
      r = requests.head('http://127.0.0.1:8080%s' % path)
      self.assertEqual(r.headers['content-type'], expected_mime)


  def test_non_existent_file_yields_404(self):
    r = requests.get('http://127.0.0.1:8080/icons/non-existent-file.png')

    self.assertResponse404(r)


  def test_dot_dot_slash_yields_404(self):
    r = requests.get('http://127.0.0.1:8080/../../../../../../../../../etc/passwd')

    self.assertResponse404(r)


  def test_slash_slash_slash_does_not_matter_200(self):
    r = requests.get('http://127.0.0.1:8080//////////icons/file.png')

    self.assertHttpResponseValid(r, 200, 'image/png')


  def test_slash_slash_slash_does_not_matter_404(self):
    r = requests.get('http://127.0.0.1:8080//////////etc/passwd')

    self.assertResponse404(r)


  def test_head_request_small_file(self):
    r = requests.head('http://127.0.0.1:8080/100.html',
          headers={'Accept-Encoding': 'foobar'})

    self.assertResponseHtml(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '100')

    self.assertEqual(r.text, '')


  def test_head_request_larger_file(self):
    r = requests.head('http://127.0.0.1:8080/zero',
          headers={'Accept-Encoding': 'foobar'})

    self.assertHttpResponseValid(r, 200, 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '32768')

    self.assertEqual(r.text, '')


  def test_uncompressed_small_file(self):
    r = requests.get('http://127.0.0.1:8080/100.html',
          headers={'Accept-Encoding': 'foobar'})

    self.assertResponseHtml(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '100')

    self.assertEqual(r.text, 'X' * 100)


  def test_get_root(self):
    r = requests.get('http://127.0.0.1:8080/')

    self.assertResponseHtml(r)

    self.assertTrue('It works!' in r.text)


  def test_compressed_small_file(self):
    encodings = (
      'deflate',
      'foo,bar,deflate',
      'foo, bar, deflate',
      'deflote' # This should fail, but won't in our current implementation
    )

    for encoding in encodings:
      r = requests.get('http://127.0.0.1:8080/100.html',
            headers={'Accept-Encoding': encoding})

      self.assertResponseHtml(r)

      self.assertTrue('content-length' in r.headers)
      self.assertLess(int(r.headers['content-length']), 100)

      self.assertTrue('content-encoding' in r.headers)
      self.assertEqual(r.headers['content-encoding'], 'deflate')

      self.assertEqual(r.text, 'X' * 100)


  def test_get_larger_file(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Accept-Encoding': 'foobar'})

    self.assertHttpResponseValid(r, 200, 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '32768')

    self.assertEqual(r.text, '\0' * 32768)


  def test_directory_listing(self):
    r = requests.get('http://127.0.0.1:8080/icons',
          headers={'Accept-Encoding': 'foobar'})

    self.assertResponseHtml(r)

    self.assertTrue('<h1>Index of &#x2f;icons</h1>' in r.text)

    def assertHasImage(name):
      imgtag = "<a href=\"&#x2f;icons/%s.png\">%s.png</a>" % (name, name)
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

    self.assertResponsePlain(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/icons/')

class TestRewrite(LwanTest):
  def test_pattern_redirect_to(self):
    r = requests.get('http://127.0.0.1:8080/pattern/foo/1234x5678', allow_redirects=False)

    self.assertResponseHtml(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/hello?name=prexmiddle5678othermiddle1234post')

  def test_pattern_rewrite_as(self):
    r = requests.get('http://127.0.0.1:8080/pattern/bar/42/test', allow_redirects=False)

    self.assertResponsePlain(r, 200)
    self.assertFalse('location' in r.headers)
    self.assertEqual(r.text, 'Hello, rewritten42!')

  def disabled_test_lua_redirect_to(self):
    r = requests.get('http://127.0.0.1:8080/pattern/lua/redir/6x7', allow_redirects=False)

    self.assertResponseHtml(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/hello?name=redirected42')

  def disabled_test_lua_rewrite_as(self):
    r = requests.get('http://127.0.0.1:8080/pattern/lua/rewrite/7x6', allow_redirects=False)

    self.assertResponsePlain(r, 200)
    self.assertFalse('location' in r.headers)
    self.assertEqual(r.text, 'Hello, rewritten42!')

class SocketTest(LwanTest):
  class WrappedSock:
    def __init__(self, sock):
      self._wrapped_sock = sock

    def send(self, stuff):
      return self._wrapped_sock.send(bytes(stuff, 'UTF-8'))

    def recv(self, n_bytes):
      return str(self._wrapped_sock.recv(n_bytes), 'UTF-8')

    def __enter__(self):
      return self

    def __exit__(self, *args):
      return self._wrapped_sock.close()

    def __getattr__(self, attr):
      if attr in self.__dict__:
        return getattr(self, attr)
      return getattr(self._wrapped_sock, attr)

  def connect(self, host='127.0.0.1', port=8080):
    def _connect(host, port):
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
      except socket.error:
        if sock:
          sock.close()
          del sock

        return None
      finally:
        return sock

    sock = _connect(host, port)
    self.assertNotEqual(sock, None)
    return SocketTest.WrappedSock(sock)

class TestMalformedRequests(SocketTest):
  def assertHttpCode(self, sock, code):
    contents = sock.recv(128)

    self.assertRegex(contents, r'^HTTP/1\.[01] ' + str(code) + r' ')


  def test_cat_sleeping_on_keyboard(self):
    with self.connect() as sock:
      sock.send('asldkfjg238045tgqwdcjv1li	2u4ftw dfjkb12345t\r\n\r\n')

      self.assertHttpCode(sock, 405)


  def test_no_http_version_fails(self):
    with self.connect() as sock:
      sock.send('GET /\r\n\r\n')

      self.assertHttpCode(sock, 400)


  def test_proxy_get_fails(self):
    with self.connect() as sock:
      sock.send('GET http://example.com HTTP/1.0\r\n\r\n')

      self.assertHttpCode(sock, 400)


  def test_get_not_http(self):
    with self.connect() as sock:
      sock.send('GET / FROG/1.0\r\n\r\n')

      self.assertHttpCode(sock, 400)


  def test_get_http_not_1_x(self):
    with self.connect() as sock:
      sock.send('GET / HTTP/2.0\r\n\r\n')

      self.assertHttpCode(sock, 400)


  def test_request_too_large(self):
    r = requests.get('http://127.0.0.1:8080/' + 'X' * 100000)

    self.assertResponseHtml(r, 413)


class TestLua(LwanTest):
  def test_inline(self):
    r = requests.get('http://localhost:8080/inline')
    self.assertResponseHtml(r)
    self.assertEqual(r.text, 'Hello')

  def test_hello(self):
    r = requests.get('http://localhost:8080/lua/hello')
    self.assertResponseHtml(r)
    self.assertEqual(r.text, 'Hello, World!')

  def test_hello_param(self):
    r = requests.get('http://localhost:8080/lua/hello?name=foo')
    self.assertResponseHtml(r)
    self.assertEqual(r.text, 'Hello, foo!')

  def test_cookies(self):
    cookies_to_send = {
        'FOO': 'BAR'
    }
    cookies_to_receive = {
        'SESSION_ID': '1234',
        'LANG': 'pt_BR',
    }
    r = requests.get('http://localhost:8080/lua/cookie', cookies=cookies_to_send)
    self.assertResponseHtml(r)
    self.assertEqual(r.text, 'Cookie FOO has value: BAR')

    for cookie, value in list(cookies_to_receive.items()):
      self.assertTrue(cookie in r.cookies)
      self.assertEqual(r.cookies[cookie], value)


class TestHelloWorld(LwanTest):
  def test_cookies(self):
    c = {
        'SOMECOOKIE': '1c330301-89e4-408a-bf6c-ce107efe8a27',
        'OTHERCOOKIE': 'some cookie value',
        'foo': 'bar'
    }
    r = requests.get('http://127.0.0.1:8080/hello?dump_vars=1', cookies=c)

    self.assertResponsePlain(r)

    self.assertTrue('\n\nCookies\n' in r.text)
    for k, v in list(c.items()):
      self.assertTrue('Key = "%s"; Value = "%s"\n' % (k, v) in r.text)

  def test_head_request_hello(self):
    r = requests.head('http://127.0.0.1:8080/hello',
          headers={'Accept-Encoding': 'foobar'})

    self.assertResponsePlain(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']), len('Hello, world!'))

    self.assertEqual(r.text, '')


  def test_has_custom_header(self):
    r = requests.get('http://127.0.0.1:8080/hello')

    self.assertTrue('x-the-answer-to-the-universal-question' in r.headers)
    self.assertEqual(r.headers['x-the-answer-to-the-universal-question'], '42')


  def test_no_param(self):
    r = requests.get('http://127.0.0.1:8080/hello')

    self.assertResponsePlain(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']), len('Hello, world!'))

    self.assertEqual(r.text, 'Hello, world!')


  def test_with_param(self):
    r = requests.get('http://127.0.0.1:8080/hello?name=testsuite')

    self.assertResponsePlain(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']),
          len('Hello, testsuite!'))

    self.assertEqual(r.text, 'Hello, testsuite!')


  def test_with_param_and_fragment(self):
    r = requests.get('http://127.0.0.1:8080/hello?name=testsuite#fragment')

    self.assertResponsePlain(r)

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(int(r.headers['content-length']),
          len('Hello, testsuite!'))

    self.assertEqual(r.text, 'Hello, testsuite!')


  def test_post_request(self):
    data = {
      'answer': 'fourty-two',
      'foo': 'bar'
    }
    r = requests.post('http://127.0.0.1:8080/hello?dump_vars=1', data=data)

    self.assertResponsePlain(r)

    self.assertTrue('POST data' in r.text)
    for k, v in list(data.items()):
      self.assertTrue('Key = "%s"; Value = "%s"\n' % (k, v) in r.text)


class TestCache(LwanTest):
  def mmaps(self, f):
    with open('/proc/%d/maps' % self.lwan.pid) as map_file:
      f = f + '\n'
      return [l.endswith(f) for l in map_file]


  def count_mmaps(self, f):
    return sum(self.mmaps(f))


  def is_mmapped(self, f):
    return any(self.mmaps(f))


  def wait_munmap(self, f, timeout=20.0):
    while self.is_mmapped(f) and timeout >= 0:
      time.sleep(0.1)
      timeout -= 0.1


  def test_cache_munmaps_conn_close(self):
    r = requests.get('http://127.0.0.1:8080/100.html')

    self.assertTrue(self.is_mmapped('/100.html'))
    self.wait_munmap('/100.html')
    self.assertFalse(self.is_mmapped('/100.html'))


  def test_cache_munmaps_conn_keep_alive(self):
    with requests.Session() as s:
      r = s.get('http://127.0.0.1:8080/100.html')

      self.assertTrue(self.is_mmapped('/100.html'))
      self.wait_munmap('/100.html')
      self.assertFalse(self.is_mmapped('/100.html'))


  def test_cache_does_not_mmap_large_files(self):
    r = requests.get('http://127.0.0.1:8080/zero')
    self.assertFalse(self.is_mmapped('/zero'))


  def test_cache_mmaps_once_conn_keep_alive(self):
    with requests.Session() as s:
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

class TestProxyProtocolRequests(SocketTest):
  def test_proxy_version1(self):
    proxy = "PROXY TCP4 192.168.242.221 192.168.242.242 56324 31337\r\n"
    req = '''GET /proxy HTTP/1.1\r
Connection: keep-alive\r
Host: 192.168.0.11\r\n\r\n'''

    with self.connect() as sock:
      for request in range(5):
        sock.send(proxy + req if request == 0 else req)
        response = sock.recv(4096)
        self.assertTrue(response.startswith('HTTP/1.1 200 OK'), response)
        self.assertTrue('X-Proxy: 192.168.242.221' in response, response)

  def test_proxy_version2(self):
    proxy = (
      "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
      "\x21\x11\x00\x0B"
      "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B"
    )
    req = '''GET /proxy HTTP/1.1\r
Connection: keep-alive\r
Host: 192.168.0.11\r\n\r\n'''

    with self.connect() as sock:
      for request in range(5):
        sock.send(proxy + req if request == 0 else req)
        response = sock.recv(4096)
        self.assertTrue(response.startswith('HTTP/1.1 200 OK'), response)
        self.assertTrue('X-Proxy: 1.2.3.4' in response, response)

class TestPipelinedRequests(SocketTest):
  def test_pipelined_requests(self):
    response_separator = re.compile('\r\n\r\n')
    names = ['name%04x' % x for x in range(16)]
    reqs = '\r\n\r\n'.join('''GET /hello?name=%s HTTP/1.1\r
Host: localhost\r
Connection: keep-alive\r
Accept: text/plain,text/html;q=0.9,application/xhtml+xml;q=0.9,application/xml;q=0.8,*/*;q=0.7''' % name for name in names)
    reqs += '\r\n\r\n'

    with self.connect() as sock:
      sock.send(reqs)

      responses = ''
      while len(response_separator.findall(responses)) != 16:
        response = sock.recv(32)
        if response:
          responses += response
        else:
          break

    for name in names:
      s = 'Hello, %s!' % name
      self.assertTrue(s in responses)
      responses = responses.replace(s, '')

class TestArtificialResponse(LwanTest):
  def test_brew_coffee(self):
    r = requests.get('http://127.0.0.1:8080/brew-coffee')

    self.assertEqual(r.status_code, 418)

if __name__ == '__main__':
  unittest.main()

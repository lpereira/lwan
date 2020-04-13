#!/usr/bin/python
# TODO: Use tracy (https://github.com/MerlijnWajer/tracy) to see if lwan
#       performs certain system calls. This should speed up the mmap tests
#       considerably and make it possible to perform more low-level tests.

import hashlib
import os
import random
import re
import requests
import shutil
import signal
import socket
import string
import subprocess
import sys
import time
import unittest
import logging

BUILD_DIR = './build'
for arg in sys.argv[1:]:
  if not arg.startswith('-') and os.path.exists(arg):
    BUILD_DIR = arg
    sys.argv.remove(arg)

if os.getenv('REQUESTS_DEBUG'):
  logging.basicConfig()
  logging.getLogger().setLevel(logging.DEBUG)
  requests_log = logging.getLogger("urllib3")
  requests_log.setLevel(logging.DEBUG)
  requests_log.propagate = True

class LwanTest(unittest.TestCase):
  harness_paths = {
    'testrunner': os.path.join(BUILD_DIR, 'src/bin/testrunner/testrunner'),
    'techempower': os.path.join(BUILD_DIR, 'src/samples/techempower/techempower'),
  }
  files_to_copy = {
    'testrunner': ('src/bin/testrunner/testrunner.conf',
                   'src/bin/testrunner/test.lua'),
    'techempower': ('src/samples/techempower/techempower.db',
                    'src/samples/techempower/techempower.conf',
                    'src/samples/techempower/json.lua'),
  }

  def ensureHighlander(self):
    def pgrep(process_name):
      try:
        out = subprocess.check_output(('pgrep', process_name), universal_newlines=True)
        return (int(pid) for pid in str(out).rstrip().split('\n'))
      except subprocess.CalledProcessError:
        yield from ()

    for typ in self.harness_paths.keys():
      for pid in pgrep(typ):
        os.kill(pid, 2)

  def setUp(self, env=None, harness='testrunner'):
    self.ensureHighlander()

    self.files_to_remove = []
    for file_to_copy in self.files_to_copy[harness]:
      base = os.path.basename(file_to_copy)
      shutil.copyfile(file_to_copy, base)
      self.files_to_remove.append(base)

    open('htpasswd', 'w').close()
    self.files_to_remove.append('htpasswd')

    for spawn_try in range(20):
      self.lwan = subprocess.Popen([self.harness_paths[harness]], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

      if self.lwan.poll() is not None:
        raise Exception('It seems that %s is not starting up' % harness)

      for request_try in range(20):
        try:
          r = requests.get('http://127.0.0.1:8080/hello')
          self.assertEqual(r.status_code, 200)
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

    self.ensureHighlander()

    for file_to_remove in self.files_to_remove:
      try:
        os.remove(file_to_remove)
      except FileNotFoundError:
        pass

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


class TestTWFB(LwanTest):
  def setUp(self, env=None):
    super().setUp(env, harness='techempower')

  def test_plaintext(self):
    for endpoint in ('lua.plaintext', 'plaintext'):
      r = requests.get('http://127.0.0.1:8080/' + endpoint)

      self.assertResponsePlain(r)
      self.assertEqual(r.text, 'Hello, World!')

  def assertSingleQueryResultIsValid(self, single):
    self.assertTrue(isinstance(single, dict))
    self.assertEqual({'randomNumber', 'id'}, set(single.keys()))
    self.assertEqual(type(single['randomNumber']), type(0))
    self.assertEqual(type(single['id']), type(0))
    self.assertTrue(0 <= single['randomNumber'] <= 9999)
    self.assertTrue(1 <= single['id'] <= 10000)

  def test_fortunes(self):
    r = requests.get('http://127.0.0.1:8080/fortunes')

    self.assertHttpResponseValid(r, 200, 'text/html; charset=UTF-8')
    self.assertEqual(hashlib.md5(bytes(r.text, 'utf-8')).hexdigest(),
                     '352e66abf97b5a07c76a8b3c9e3e6339')

  def test_json(self):
    for endpoint in ('lua.json', 'json'):
      r = requests.get('http://127.0.0.1:8080/' + endpoint)

      self.assertHttpResponseValid(r, 200, 'application/json')
      self.assertEqual(r.json(), {'message': 'Hello, World!'})

  def test_single_query(self):
    r = requests.get('http://127.0.0.1:8080/db')

    self.assertHttpResponseValid(r, 200, 'application/json')
    self.assertSingleQueryResultIsValid(r.json())

  def test_multiple_queries(self):
    def assertMultipleQueriesValid(r, queries):
      self.assertHttpResponseValid(r, 200, 'application/json')
      self.assertTrue(isinstance(r.json(), list))
      self.assertEqual(len(r.json()), min(500, max(queries, 1)))
      for query in r.json():
        self.assertSingleQueryResultIsValid(query)

    for queries in (1, 10, 100, 500, 1000, 0, -1):
      r = requests.get('http://127.0.0.1:8080/queries?queries=%d' % queries)
      assertMultipleQueriesValid(r, queries)

    r = requests.get('http://127.0.0.1:8080/queries')
    assertMultipleQueriesValid(r, 1)

class TestPost(LwanTest):
  def test_will_it_blend(self):
    r = requests.post('http://127.0.0.1:8080/post/blend', json={'will-it-blend': True})
    self.assertHttpResponseValid(r, 200, 'application/json')
    self.assertEqual(r.json(), {'did-it-blend': 'oh-hell-yeah'})

  def make_request_with_size(self, size):
    random.seed(size)

    data = "".join(random.choice(string.printable) for c in range(size * 2))

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

  # These two tests are supposed to fail, with Lwan aborting the connection.
  def test_huge_request(self):
    try:
      self.make_request_with_size(10000)
    except requests.exceptions.ChunkedEncodingError:
      pass
    except requests.exceptions.ConnectionError:
      pass
  def test_gigantic_request(self):
    try:
      self.make_request_with_size(100000)
    except requests.exceptions.ChunkedEncodingError:
      pass
    except requests.exceptions.ConnectionError:
      pass


class TestFileServing(LwanTest):
  def test_mime_type_is_correct(self):
    table = (
      ('/', 'text/html'),
      ('/icons/back.gif', 'image/gif'),
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
    r = requests.get('http://127.0.0.1:8080//////////100.html')

    self.assertHttpResponseValid(r, 200, 'text/html')
    self.assertEqual(r.text, 'X' * 100)


  def test_range_half(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=0-50'})

    self.assertHttpResponseValid(r, 206, 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '50')

    self.assertEqual(r.text, '\0' * 50)

  def test_range_half_inverted(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=50-0'})

    self.assertHttpResponseValid(r, 416, 'text/html')


  def test_range_half_equal(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=50-50'})

    self.assertHttpResponseValid(r, 416, 'text/html')


  def test_range_too_big(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=0-40000'})

    self.assertHttpResponseValid(r, 416, 'text/html')


  def test_range_no_from(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=-100'})

    self.assertHttpResponseValid(r, 206, 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '100')

    self.assertEqual(r.text, '\0' * 100)

  def test_range_no_to(self):
    r = requests.get('http://127.0.0.1:8080/zero',
          headers={'Range': 'bytes=50-'})

    self.assertHttpResponseValid(r, 206, 'application/octet-stream')

    self.assertTrue('content-length' in r.headers)
    self.assertEqual(r.headers['content-length'], '32718')

    self.assertEqual(r.text, '\0' * 32718)


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
      imgtag = "<a href=\"&#x2f;icons/%s.gif\">%s.gif</a>" % (name, name)
      self.assertTrue(imgtag in r.text)

    assertHasImage('back')
    assertHasImage('file')
    assertHasImage('folder')

    with open('wwwroot/icons/README.TXT', 'r') as readme:
      readme = readme.read()
      readme = readme.replace('"', "&quot;")
      readme = readme.replace('/', "&#x2f;")
      readme = readme.replace("'", "&#x27;")

      self.assertTrue(readme in r.text)

    self.assertTrue(r.text.startswith('<html>'))
    self.assertTrue(r.text.endswith('</html>\n'))


  def test_has_lwan_server_header(self):
    r = requests.get('http://127.0.0.1:8080/100.html')
    self.assertTrue('server' in r.headers)
    self.assertEqual(r.headers['server'], 'lwan')


  def test_directory_without_trailing_slash_redirects(self):
    r = requests.get('http://127.0.0.1:8080/icons', allow_redirects=False)

    self.assertResponsePlain(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/icons/')

class TestRedirect(LwanTest):
  def test_redirect_default(self):
    r = requests.get('http://127.0.0.1:8080/elsewhere', allow_redirects=False)

    self.assertResponseHtml(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], 'http://lwan.ws')

  def test_redirect_307(self):
    r = requests.get('http://127.0.0.1:8080/redirect307', allow_redirects=False)

    self.assertResponseHtml(r, 307)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], 'http://lwan.ws')

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

  def test_lua_redirect_to(self):
    r = requests.get('http://127.0.0.1:8080/pattern/lua/redir/6x7', allow_redirects=False)

    self.assertResponseHtml(r, 301)
    self.assertTrue('location' in r.headers)
    self.assertEqual(r.headers['location'], '/hello?name=redirected42')

  def test_lua_rewrite_as(self):
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


class TestMinimalRequests(SocketTest):
  def assertHttpCode(self, sock, code):
    contents = sock.recv(128)

    self.assertRegex(contents, r'^HTTP/1\.[01] ' + str(code) + r' ')

  def test_http1_0_request(self):
    with self.connect() as sock:
      sock.send("GET / HTTP/1.0\r\n\r\n")
      self.assertHttpCode(sock, 200)


  def test_http1_1_request(self):
    with self.connect() as sock:
      sock.send("GET / HTTP/1.1\r\n\r\n")
      self.assertHttpCode(sock, 200)


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
      sock.send('GET /some-long-url-that-is-longer-than-version-string\r\n\r\n')

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
    try:
      r = requests.get('http://127.0.0.1:8080/' + 'X' * 100000)

      self.assertResponseHtml(r, 413)
    except requests.exceptions.ChunkedEncodingError:
      pass
    except requests.exceptions.ConnectionError:
      pass

class TestChunkedEncoding(LwanTest):
  def test_chunked_encoding(self):
    r = requests.get('http://localhost:8080/chunked')
    self.assertResponsePlain(r)
    self.assertFalse('Content-Length' in r.headers)
    self.assertTrue('Transfer-Encoding' in r.headers)
    self.assertTrue(r.headers['Transfer-Encoding'], 'chunked')
    self.assertEqual(r.text,
      'Testing chunked encoding! First chunk\n' +
      ''.join('*This is chunk %d*\n' % i for i in range(11)) +
      'Last chunk\n')

class TestLua(LwanTest):
  def test_brew_coffee(self):
    r = requests.get('http://127.0.0.1:8080/lua/brew_coffee')

    self.assertEqual(r.status_code, 418)

  def test_invalid_Code(self):
    r = requests.get('http://127.0.0.1:8080/lua/invalid_code')

    self.assertEqual(r.status_code, 500)

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


class TestAuthentication(LwanTest):
  class TempHtpasswd:
    def __init__(self, users):
      self._users = users

    def __enter__(self):
      with open('htpasswd', 'w') as f:
        for u, p in self._users.items():
          f.write('%s = %s\n' % (u, p))

    def __exit__(self, type, value, traceback):
      os.remove('htpasswd')

  def test_no_creds(self):
    r = requests.get('http://127.0.0.1:8080/admin')
    self.assertResponseHtml(r, status_code=401)

  def test_unknown_user(self):
    with TestAuthentication.TempHtpasswd({'foo': 'bar', 'foobar': 'test123'}):
      r = requests.get('http://127.0.0.1:8080/admin', auth=requests.auth.HTTPBasicAuth('nosuch', 'user'))
      self.assertResponseHtml(r, status_code=401)

  def test_invalid_creds(self):
    with TestAuthentication.TempHtpasswd({'foo': 'bar', 'foobar': 'test123'}):
      r = requests.get('http://127.0.0.1:8080/admin', auth=requests.auth.HTTPBasicAuth('foo', 'test123'))
      self.assertResponseHtml(r, status_code=401)

  def test_valid_creds(self):
    with TestAuthentication.TempHtpasswd({'foo': 'bar', 'foobar': 'test123'}):
      r = requests.get('http://127.0.0.1:8080/admin', auth=requests.auth.HTTPBasicAuth('foobar', 'test123'))
      self.assertResponsePlain(r)

      self.assertTrue('content-length' in r.headers)
      self.assertEqual(int(r.headers['content-length']), len('Hello, world!'))

      self.assertEqual(r.text, 'Hello, world!')


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

  def test_with_empty_param(self):
    r = requests.get('http://127.0.0.1:8080/hello?key=&otherkey=&name=testsuite&dump_vars=1')

    self.assertResponsePlain(r)

    self.assertTrue('Query String Variables' in r.text)
    self.assertTrue('Key = "key"; Value = ""\n' in r.text)
    self.assertTrue('Key = "otherkey"; Value = ""\n' in r.text)
    self.assertTrue('Key = "dump_vars"; Value = "1"\n' in r.text)
    self.assertTrue('Key = "name"; Value = "testsuite"\n' in r.text)


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


  def test_read_env(self):
    r = requests.get('http://127.0.0.1:8080/read-env/user')

    self.assertResponsePlain(r)
    self.assertEqual(r.text, 'Hello, %s!' % os.getenv('USER'))

class TestCache(LwanTest):
  def setUp(self):
    self._cache_for = 3

    new_environment = os.environ.copy()
    new_environment.update({
      'KEEP_ALIVE_TIMEOUT': '3',
      'CACHE_FOR': str(self._cache_for),
    })

    super().setUp(env=new_environment)

  @classmethod
  def setUpClass(cls):
    if os.uname().sysname != 'Linux':
      raise unittest.SkipTest

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
      time.sleep(0.05)
      timeout -= 0.05


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

    # 10% over `cache_for` just to be conservative (job thread isn't that precise)
    time.sleep(self._cache_for * 1.10)

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
        self.assertTrue(response.startswith('HTTP/1.1 200 OK'))
        self.assertTrue('X-Proxy: 192.168.242.221' in response)

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
        self.assertTrue(response.startswith('HTTP/1.1 200 OK'))
        self.assertTrue('X-Proxy: 1.2.3.4' in response)

class TestPipelinedRequests(SocketTest):
  def test_pipelined_requests(self):
    response_separator = re.compile('\r\n\r\n')
    names = ['name%04x' % x for x in range(256)]
    reqs = '\r\n\r\n'.join('''GET /hello?name=%s HTTP/1.1\r
Host: localhost\r
Connection: keep-alive\r
Accept: text/plain,text/html;q=0.9,application/xhtml+xml;q=0.9,application/xml;q=0.8,*/*;q=0.7''' % name for name in names)
    reqs += '\r\n\r\n'

    with self.connect() as sock:
      sock.send(reqs)

      responses = ''
      while len(response_separator.findall(responses)) != len(names):
        response = sock.recv(4096)
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


class TestSleep(LwanTest):
  def test_sleep(self):
    now = time.time()
    requests.get('http://127.0.0.1:8080/sleep?ms=1500')
    diff = time.time() - now

    self.assertTrue(1.450 < diff < 1.550)


class TestRequest(LwanTest):
  def test_custom_header_exists(self):
    h = {'Marco': 'Polo'}
    r = requests.get('http://127.0.0.1:8080/customhdr?hdr=Marco', headers = h)

    self.assertEqual(r.text, "Header value: 'Polo'")

  def test_custom_header_does_not_exist(self):
    h = {'Marco': 'Polo'}
    r = requests.get('http://127.0.0.1:8080/customhdr?hdr=Polo', headers = h)

    self.assertEqual(r.status_code, 404)


class TestFuzzRegressionBase(SocketTest):
  def setUp(self):
    new_environment = os.environ.copy()
    new_environment.update({'KEEP_ALIVE_TIMEOUT': '0'})
    super(SocketTest, self).setUp(env=new_environment)

  def run_test(self, contents):
    with self.connect() as sock:
      sock.send(contents)
      first_8 = sock.recv(8)
      self.assertTrue(first_8 in ("HTTP/1.1", "HTTP/1.0", ""))

  @staticmethod
  def wrap(name):
    with open(os.path.join("fuzz", name), "rb") as f:
      contents = str(f.read(), "latin-1")
    def run_test_wrapped(self):
      return self.run_test(contents)
    return run_test_wrapped

TestFuzzRegression = type('TestFuzzRegression', (TestFuzzRegressionBase,), {
  "test_" + name.replace("-", "_"): TestFuzzRegressionBase.wrap(name)
  for name in (
    cf for cf in os.listdir("fuzz") if cf.startswith(("clusterfuzz-", "crash-"))
  )
})

if __name__ == '__main__':
  unittest.main()

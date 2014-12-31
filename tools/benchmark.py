#!/usr/bin/python

import sys
import json
import commands
import time

try:
  import matplotlib.pyplot as plt
except ImportError:
  plt = None


def clearstderrline():
  sys.stderr.write('\033[2K')


def weighttp(url, n_threads, n_connections, n_requests, keep_alive):
  keep_alive = '-k' if keep_alive else ''
  command = 'weighttp %(keep_alive)s ' \
            '-t %(n_threads)d ' \
            '-c %(n_connections)d ' \
            '-n %(n_requests)d ' \
            '-j ' \
            '%(url)s 2> /dev/null' % locals()

  clearstderrline()
  sys.stderr.write('*** %s\r' % command)

  output = commands.getoutput(command)

  return json.loads(output)


def weighttp_has_json_output():
  output = commands.getoutput('weighttp -j')
  return not 'unknown option: -j' in output


def steprange(initial, final, steps=10):
  step = (final - initial) / steps

  while initial <= final:
    yield initial
    initial += step


def sleepwithstatus(msg, period):
  slept = 0
  spinner = 0

  while slept <= period:
    clearstderrline()
    sys.stderr.write('\r%s: %s' % (msg, '/|\\-'[spinner % 4]))

    time.sleep(0.1)
    slept += 0.1
    spinner += 1

  sys.stderr.write('\r')
  clearstderrline()


def cmdlineboolarg(arg):
  has_arg = False
  if arg in sys.argv:
    has_arg = True
    sys.argv.remove(arg)
  return has_arg


def cmdlineintarg(arg, default=0):
  value = default
  if arg in sys.argv:
    index = sys.argv.index(arg)
    del sys.argv[index]
    try:
      value = int(sys.argv[index])
    except ValueError:
      print 'Argument is of invalid type for argument %s, assuming default (%d)' % (arg, default)
    finally:
      del sys.argv[index]
  return value


class CSVOutput:
  def header(self):
    print 'keep_alive,n_connections,rps,kbps,2xx,3xx,4xx,5xx'

  def footer(self):
    clearstderrline()

  def log(self, keep_alive, n_connections, rps, kbps, _2xx, _3xx, _4xx, _5xx):
    clearstderrline()
    print ','.join(str(token) for token in
      (int(keep_alive), n_connections, rps, kbps, _2xx, _3xx, _4xx, _5xx))


class MatplotlibOutput:
  def __init__(self, xkcd=False):
    self.xkcd = xkcd

  def header(self):
    self.n_connections = []
    self.rps = {'keep-alive': [], 'close': []}

  def _plot(self):
    plt.xlabel('# connections')
    plt.ylabel('Requests/s')

    n_connections = self.n_connections[:len(self.rps['close'])]

    plt.plot(n_connections, self.rps['keep-alive'], label='Keep-Alive')
    plt.plot(n_connections, self.rps['close'], label='Close',
          marker='o', linestyle='--', color='r')

    plt.title('Web Server Benchmark')
    plt.legend()
    plt.show()

  def footer(self):
    if self.xkcd:
      with plt.xkcd():
        self._plot()
    else:
      self._plot()

  def log(self, keep_alive, n_connections, rps, kbps, _2xx, _3xx, _4xx, _5xx):
    self.n_connections.append(n_connections)
    if keep_alive:
      self.rps['keep-alive'].append(rps)
    else:
      self.rps['close'].append(rps)


if __name__ == '__main__':
  if not weighttp_has_json_output():
    print 'This script requires a special version of weighttp which supports JSON'
    print 'output. Get it at http://github.com/lpereira/weighttp'
    sys.exit(1)

  plot = cmdlineboolarg('--plot')
  xkcd = cmdlineboolarg('--xkcd')
  n_threads = cmdlineintarg('--threads', 2)
  n_requests = cmdlineintarg('--request', 1000000)
  keep_alive_timeout = cmdlineintarg('--keep-alive-timeout', 5)
  n_conn_start = cmdlineintarg('--start-conn', 100)
  n_conn_end = cmdlineintarg('--end-conn', 60000)
  n_conn_step = cmdlineintarg('--conn-step', 10)
  url = sys.argv[-1] if len(sys.argv) > 1 else 'http://localhost:8080/100.html'

  if plt is None:
    if plot:
      print 'Matplotlib not installed!'
      sys.exit(1)
    output = CSVOutput()
  elif plot:
    output = MatplotlibOutput(xkcd)
  else:
    output = CSVOutput()

  output.header()
  for keep_alive in (True, False):
    for n_connections in steprange(n_conn_start, n_conn_end, n_conn_step):
      results = weighttp(url, n_threads, n_connections, n_requests, keep_alive)
      status = results['status_codes']

      output.log(keep_alive, n_connections, results['reqs_per_sec'],
        results['kbyte_per_sec'], status['2xx'], status['3xx'],
        status['4xx'], status['5xx'])
      sleepwithstatus('Waiting for keepalive connection timeout', keep_alive_timeout * 1.1)

  output.footer()

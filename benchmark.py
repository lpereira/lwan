#!/usr/bin/python

import sys
import json
import commands
import time


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


if __name__ == '__main__':
  url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080/100.html'
  n_threads = 2
  n_requests = 1000000
  keep_alive_timeout = 5

  print 'keep_alive,n_connections,rps,kbps,2xx,3xx,4xx,5xx'
  for keep_alive in (True, False):
    for n_connections in steprange(100, 60000, 10):
      results = weighttp(url, n_threads, n_connections, n_requests, keep_alive)
      status = results['status_codes']

      clearstderrline()
      print ','.join(str(token) for token in
        (int(keep_alive), n_connections, results['reqs_per_sec'],
         results['kbyte_per_sec'], status['2xx'], status['3xx'],
         status['4xx'], status['5xx'])
      )

      sleepwithstatus('Waiting for keepalive connection timeout', keep_alive_timeout * 1.1)

  clearstderrline()

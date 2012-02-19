#!/usr/bin/python

import commands
import pickle
import re
import os
import numpy

RE_RPS = re.compile(r'Requests per second:\s+(\d+\.\d+)')
RE_TRANSF_RATE = re.compile('Transfer rate:\s+(\d+\.\d+)')

def dump_as_csv(r, f):
  r = r[f]
  f = file('benchmark-result-' + f + '.csv', 'w')
  for key in sorted(r.keys()):
    results = r[key]
    f.write(', '.join([str(key), str(results['rps']), str(results['tr'])]))
    f.write('\n')
  f.close()

if os.path.exists('benchmark.pickle'):
  results = pickle.load(file('benchmark.pickle'))
  analyzed = {'keep-alive':{}, 'close':{}}
  for keep_alive, conns in results.keys():
    ab_output = results[(keep_alive,conns)]
    reqs_per_second = RE_RPS.findall(ab_output)
    if not reqs_per_second:
      continue
    reqs_per_second = float(reqs_per_second[0])
    
    transf_rate = RE_TRANSF_RATE.findall(ab_output)
    if not transf_rate:
      continue
    transf_rate = float(transf_rate[0])
    
    analyzed['keep-alive' if keep_alive == '-k' else 'close'][conns] = {
      'rps': reqs_per_second,
      'tr': transf_rate
    }
  
  dump_as_csv(analyzed, 'keep-alive')
  dump_as_csv(analyzed, 'close')

else:
  NUM_REQUESTS = 80000
  MAX_SIM_CONNECTIONS = 100
  AB = '/usr/bin/ab'
  ADDRESS = 'http://localhost:8080/hello'

  results = {}
  for keep_alive in ['', '-k']:
    print 'Benchmarking', 'without' if keep_alive == '' else 'with', 'keep-alive connections'
    for sim_connection in range(1, MAX_SIM_CONNECTIONS + 1):
      print '    %d simultaneous connections, %d total requests' % (sim_connection, NUM_REQUESTS)
      command_line = '%(ab)s %(keep_alive)s -i -n%(requests)d -c%(sim_connection)d %(url)s' % {
        'ab': AB,
        'keep_alive': keep_alive,
        'sim_connection': sim_connection,
        'requests': NUM_REQUESTS,
        'url': ADDRESS
      }
      
      results[(keep_alive,sim_connection)] = commands.getoutput(command_line)

  print 'Saving results to benchmark.pickle: run again to process it'
  f = file('benchmark.pickle', 'w')
  pickle.dump(results, f)
  f.close()


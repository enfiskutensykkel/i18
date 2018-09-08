#!/usr/bin/env python
import requests
import urllib
import hashlib

auth = ('ab689d8efff93a5796493b1bf186ff8923acfbfbf2b11dcdc2c8af96aba4c1d6', '')

#curl -id  https://challenge.i18.no/level/zh0gbke293ur78vzvcwfueuy71opfutf/answer

h = hashlib.sha256('lett som en plett').hexdigest()
print h

query = h

s = requests.session()
r = s.post('https://challenge.i18.no/level/zh0gbke293ur78vzvcwfueuy71opfutf/answer?{}'.format(query) , auth=auth, data=query)

print r.status_code

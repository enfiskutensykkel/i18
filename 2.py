#!/usr/bin/env python
import requests
import urllib

auth = ('ab689d8efff93a5796493b1bf186ff8923acfbfbf2b11dcdc2c8af96aba4c1d6', '')

s = requests.session()
answer = s.get('https://challenge.i18.no/level/fbmserjd3dwtvrspnk8ektmxsvdenwvp').headers['X-Answer']
print answer
r = s.post('https://challenge.i18.no/level/fbmserjd3dwtvrspnk8ektmxsvdenwvp/answer', auth=auth, data=answer)

print r.status_code


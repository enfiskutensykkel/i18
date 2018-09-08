#!/usr/bin/env python
#coding=utf8
import requests
import urllib
import time
import datetime as dt
import passlib.hash
import base64
import hashlib
import re

auth = ('ab689d8efff93a5796493b1bf186ff8923acfbfbf2b11dcdc2c8af96aba4c1d6', '')

s = requests.session()
r = s.get('https://challenge.i18.no/level/j648ibtxapaufhpbvaoicla0e2antfeh', auth=auth)

match = re.search(r'(nsm:[^:]+:\d+)', r.text, re.DOTALL | re.MULTILINE)

pwd = match.group(0)
print pwd

passwd = pwd.split(':')[1]
days = int(pwd.split(':')[2])
user = pwd.split(':')[0]
salt = pwd.split(':')[1].split('$')[2]
hashcode = pwd.split(':')[1].split('$')[3]

date = dt.datetime.fromtimestamp(0) + dt.timedelta(days=days)
year = int(date.year)

answer = None
i = 0
#for word in open('ordliste.txt').readlines():
for word in ['demokrati']:
    word = word.strip().capitalize()
    tests = [word + str(year - 1), word + str(year), word + str(year + 1)]
    match = False

    for test in tests:
        i += 1

        if i % 10000 == 0:
            # progress report
            print i, test

        p = passlib.hash.md5_crypt.hash(test, salt=salt)
        match = p == passwd
        if match:
            answer = test
            break

    if match:
        break

if answer is None:
    print "Could not find answer!"

print answer
print passlib.hash.md5_crypt.hash(answer, salt=salt)
print passwd
print passlib.hash.md5_crypt.verify(answer, passwd)
answer = hashlib.sha256(answer).hexdigest()
print answer

r = s.post('https://challenge.i18.no/level/j648ibtxapaufhpbvaoicla0e2antfeh/answer', auth=auth, data=answer)

print r.status_code

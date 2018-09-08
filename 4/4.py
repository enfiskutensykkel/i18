#!/usr/bin/env python
#coding=utf8
import requests
import os
import re
import hashlib


def parse_headers(fp):
    line = fp.readline().strip().lower()

    if line != "http/1.0 200 ok":
        return None

    headers = {}
    while True:
        line = fp.readline().strip()
        if len(line) == 0:
            break

        m = re.match(r'^(?P<key>[^:]+):\s+(?P<value>.*)$', line)
        headers[m.group('key').lower()] = m.group('value')

    return headers


auth = ('ab689d8efff93a5796493b1bf186ff8923acfbfbf2b11dcdc2c8af96aba4c1d6', '')

for root, dirs, files in os.walk('./'):
    for fname in files:
        base, ext = os.path.splitext(fname)

        if ext == ".http":
            with open(fname) as fp:
                hdrs = parse_headers(fp)

                if hdrs is None:
                    continue

                if hdrs['content-type'] == 'image/png':
                    print 'a'
                    open('image.png', "w").write(fp.read())

print hashlib.sha256('eidsvoll').hexdigest()

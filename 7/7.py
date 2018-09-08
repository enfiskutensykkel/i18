#!/usr/bin/env python
#coding=utf8
import requests

auth = ('ab689d8efff93a5796493b1bf186ff8923acfbfbf2b11dcdc2c8af96aba4c1d6', '')

s = requests.session()

r = s.get('https://challenge.i18.no/level/hfnxjtt09qpwz6nuxeqzt2dqmgtmm3sd/logo.jpg')

# The proper JPEG header is the two-byte sequence, 0xFF-D8, aka Start of Image (SOI) marker.
# JPEG files end with the two-byte sequence, 0xFF-D9, aka End of Image (EOI) marker.
# https://www.garykessler.net/library/file_sigs.html

imgdata = bytearray(r.content)
#imgdata = bytearray(r.text, 'utf8')

prev = None
curr = None
pos = 0

while not (prev == 0xff and curr == 0xd9):
    prev = curr
    curr = imgdata[pos]
    pos += 1

with open('out', 'w') as fp:
    fp.write(imgdata[pos:])


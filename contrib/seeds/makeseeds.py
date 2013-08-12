#!/usr/bin/env python
#
# Generate pnSeed[] from a list of node's ip:port
# (one per line)
#
# could be extracted from logs with something like this:
# nice egrep 'them=[0-9\.]+\:13333' debug.log | sed -e 's/^.*them=//' | sed -e 's/,.*//' > /tmp/seedstmp.txt
# cat /tmp/seedstmp.txt | sort | uniq > /tmp/seeds.txt
#
# cat /tmp/seeds.txt | python contrib/seeds/makeseeds.py

NSEEDS=340

import re
import sys
from subprocess import check_output

def main():
    lines = sys.stdin.readlines()

    ips = []
    pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):13333")
    for line in lines:
        m = pattern.match(line)
        if m is None:
            continue
        ip = 0
        for i in range(0,4):
            ip = ip + (int(m.group(i+1)) << (8*(i)))
        if ip == 0:
            continue
        ips.append(ip)

    for row in range(0, min(NSEEDS,len(ips)), 8):
        print "    " + ", ".join([ "0x%08x"%i for i in ips[row:row+8] ]) + ","

if __name__ == '__main__':
    main()

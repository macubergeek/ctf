#!/bin/bash
## put bssid's in file name bssids
for i in `cat /ctf/essid`
do
terminal -e aircrack-ng  -w /root/Desktop/cracklib-words -b $i /ctf/pcaps/*.caps
done

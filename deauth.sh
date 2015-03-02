#!/bin/bash
for i in 1 2 3 4 5 6 7 8
do
mdk3 wlan$i -b $1 -c $i
done
#! /bin/bash

while [ 1 ]; do
	for CHNUM in {1..13}; do
		iwconfig wlan0 channel $CHNUM
		sleep 1
	done
done


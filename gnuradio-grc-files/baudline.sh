#!/bin/sh
parec --format=s16le --channels=1 --rate=48000 --latency-msec=5 | /opt/baudline_1.08_linux_x86_64/baudline -record -stdin -samplerate 48000

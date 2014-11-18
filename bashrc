#!/bin/bash

if [ ! "$(grep nox /proc/cmdline)" ]
then
	if [ -x /usr/bin/X ]
	then
		if [ -e /etc/startx -a $(tty) = "/dev/tty1" ];
		then
			rm -f /etc/startx
			echo startx | su - 'pentoo'
			[ -f /etc/motd ] && cat /etc/motd
		fi
	fi
fi
alias c='clear'
alias e='exit'
alias d='cd /root/Desktop'
alias a='alpine'
alias am='airmon-zc'
alias ar='aireplay-ng'
alias ac='aircrack-ng'
alias airo='airodump-ng'

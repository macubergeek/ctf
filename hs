#!/bin/bash
## cronjob strip handshakes
##tshark -r <input file name> -R "eapol || wlan.fc.type_subtype == 0x08" -w <output file name>
tshark -r $1 -R "eapol || wlan.fc.type_subtype == 0x08" -w $1.handshakes
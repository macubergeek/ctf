#!/bin/bash
if [ $# -eq 0 ]; then
echo “Save the ctf key to this directory and name it ctf.key”;
echo “Download his flag.sh file into this directory as filename flag”;
echo “Run $0 me.”
echo "";
exit 1;
fi
gpg --allow-secret-key-import --import ctf-private.key
gpg --import ctf-public.key 
gpg --import ctf.key
echo "email: J1mngctf@gmail.com"
echo "All I do is win!"
chmod +x flag && mv flag /usr/local/bin

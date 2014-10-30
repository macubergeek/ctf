#!/bin/bash
#echo save the ctf key to this directory and name it ctf.key
#echo copy and paste contents of ctf-public.key into his website
gpg --allow-secret-key-import --import ctf-private.key
gpg --import ctf-public.key 
gpg --import ctf.key
echo "email: J1mngctf@gmail.com"
echo "All I do is win!"
chmod +x flag && mv flag /usr/local/bin

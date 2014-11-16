#!/usr/bin/env python
""" manual-wireless.py - Configure OLPC's wireless functionality from the terminal"""

## Copyright (C) 2008 Luke Faraone
## Author: Luke Faraone <luke@laptop.org>
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
#
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# TODO: Add an option to save and restore a config.
from __future__ import with_statement

import os
import sys
import subprocess
import time

try:
    import dbus
except ImportError:
    dbus_enabled = False
    print "DBUS Not installed, disabled!"
else:
    dbus_enabled = True

from subprocess import call
from optparse import OptionParser

import getone # Requires getone.py
# TODO: Package that shared lib up.

def do_dhcp(interface="eth0"):
    """ Init a DHCP client for an interface"""
    call(["/sbin/dhclient", interface])

def pop_parser(object):
    object.add_option("-t", "--type", dest="ap_type", action="store",
                      help="type of access point, one of {WPA, WEP, open}")
    # TODO: Actually use the next parameter
    #parser.add_option("-v", "--version", action="store_true", dest="version",
    #                default=False, help="Print the program version")
    object.add_option("-n", "--name", dest="ssid", action="store",
                      help="type of access point, one of {WPA, WEP, open}")
    object.add_option("-p", "--pass", dest="ap_pass", action="store",
                      help="passphrase for accesspoints")
    object.add_option("-f", "--fakeroot", dest="force", action="store_true",
                      default=False, help="Force the script to execute even if\
                      the calling user is not root")
    object.add_option("-d", "--debugmode", dest="debugmode", action="store_true",
                      default=False, help="Don't actually write anything, output to the terminal (for WPA mode only)")


def do_olpc_wpa_config(ssid, wpaver, key,  config_loc=None, debugmode=False):
    """Writes out the configuration file for sugar's network configuration
    system. Takes three arguments, one of the SSID of the wireless network, one
    of the version of WPA (wpaver), and another of the network key"""
    if config_loc is None:
        config_loc = "/home/olpc/.sugar/default/nm/networks.cfg"
    timestamp = int(time.time())
    output = """[%(ssid)s]
timestamp = %(timestamp)s
we_cipher = 0
key = %(key)skey_mgmt = 2
bssids =
""" % {"ssid": ssid, "timestamp": timestamp,  "key": key}

    if int(wpaver) == 1:
        output += "wpa_ver= 1"
    elif int(wpaver) == 2:
        output += "wpa_ver= 2"
    else:
        print "Something has happened; error 0x004"

    if debugmode is False:
        with open(config_loc,  'w') as file:
            file.write(output)
    else:
        #Output what would otherwise be written to a file for debugging purposes.
        print output + "\n--- EOF ---"

def do_olpc_wep_config(ssid,  password):
    # TODO Actually do something
    #One of these three depending on WEP keylength.
    #nmsi.setActiveDevice(eth0, 'ESSID', 0x02, 'fadded1337', 1)
    #nmsi.setActiveDevice(eth0, 'ESSID', 0x10, '01234567890123456789abcdef', 1)
    print "FIXME: WEP not supported"
    pass


def main(argv=None):
    parser = OptionParser()
    pop_parser(parser)
    (options, args) = parser.parse_args()

    if not getone.is_root() and not options.force:
        getone.root_req()
    # TODO: Explain how the prompter works.
    # For now, let's just print out the user's options and verify they are
    # correct
    if options.ssid and options.ssid.isalnum():
        print "AP Name:",options.ssid
    else:
        escape_enc_loop = False
        while not escape_enc_loop:
            options.ssid = raw_input("What is the name of the accesspoint?:  ")
            if options.ssid != "" and " " not in options.ssid:
                # At the moment, all non-empty strings are let through. This is
                # a bad idea.
                # TODO: Need to run the input through a regexp to make sure that
                # we arn't A) Being Screwed With and B) Suffering from (l)users.
                escape_enc_loop = True
            else:
                # The user is dense, let's try this again... :(
                print "Invalid entry. Accesspoint names contain only " +\
                      "alphanumerics. "

    if options.ap_type:
        if options.ap_type == "none":
            print "AP Type: No encryption"
            options.ap_type = None
        else:
            print "AP Type:",options.ap_type
    else:
        escape_enc_loop = False
        while not escape_enc_loop:
            options.ap_type = raw_input("Does the accesspoint use wpa, wep, "+\
                                        "or no encryption? [none]:  ")
            print "So you said:", options.ap_type
            # Here we normalize strings and validate input
            if options.ap_type in ("none", "", "no encryption"):
                options.ap_type = None
                escape_enc_loop = True
            elif options.ap_type in ("wpa", "WPA"):
                while True:
                    # Here we asertain whether the accesspoint uses WPA1 or WPA2
                    try:
                        wpaver = raw_input("Which version of WPA is used? (1 "+\
                                           "or 2): ")
                    except ValueError:
                        print "Error: WPA version must be an integer of " +\
                              "\"1\" or \"2\""
                    if wpaver in ("1", "2"):
                        break
                    print "Error: WPA version must be \"1\" or \"2\""
                    options.ap_type = "wpa" + wpaver
                escape_enc_loop = True
            elif options.ap_type in ("wep", "WEP"):
                options.ap_type = "wep"
                escape_enc_loop = True
            else:
                # The user is dense, let's try this again... :(
                print "Invalid entry. Please choose one of \" wep, wpa, or " +\
                      "none\"."
    if options.ap_type is not None:
        if options.ap_pass:
            if options.ap_type == "none":
                #Maybe use a better word than passphrase?
                # TODO: Have this write to sterror
                print "Warning: A passphrase was spesified at the command " +\
                      "line, but the chosen access point type does not require a " +\
                      "passphrase."
            else:
                print "AP Passphrase:" , options.ap_pass
        else:
            escape_enc_loop = False
            if options.ap_type == "wpa":
                while not escape_enc_loop:
                    options.ap_pass = raw_input("What is the accesspoint's" +\
                                                "passphrase? :  ")
                    # Here we normalize strings and validate input
                    if options.ap_pass != "" and len(options.ap_pass) >= 8:
                        escape_enc_loop = True
                    # The user is dense, let's try this again... :(
                    else:
                        print "Invalid entry. Please enter a accesspoint " +\
                              "passphrase longer than 8 alphanumerics. "
            else:
                while not escape_enc_loop:
                    options.ap_pass = raw_input("What is the accesspoint's " +\
                                                "passphrase? :  ")
                #Here we normalize strings and validate input
                    if options.ap_pass != "":
                    # At the moment, all non-empty strings are let through. This
                    # is a bad idea.
                    # TODO: Need to run the input through a regexp to make sure
                    # that we arn't A) Being Screwed With and B) Suffering from
                    # (l)users.
                    
                    # TODO: Based on AP type, we should detect if they need hex
                    # conversion etc.
                        escape_enc_loop = True
                else:
                    # The user is dense, let's try this again... :(
                    print "Invalid entry. Please enter a accesspoint" +\
                          " passphrase. "


    # TODO: This needs to be a separate function
    if options.ap_type == "wpa":
        wpapassphrase = subprocess.Popen(["/usr/sbin/wpa_passphrase",
                                          options.ssid, options.ap_pass ],  stdout=subprocess.PIPE)
        wpapassphrase.wait()
        for i in wpapassphrase.stdout:
            if "psk=" in i:
                if "#" not in i:
                    prelim = i
                    magic_pass = prelim[5:]
                    break
        else:
            raise WPASupplicantError("The output of wpa_passphrase was not" +\
                                     " valid.")
        do_olpc_wpa_config(options.ssid, wpaver,  magic_pass, debugmode=options.debugmode)
        print "WPA has been configured. Restart sugar via CTRL+ALT+ERASE and " +\
              "click on the circle in the network manager."
    elif options.ap_type == "wep":
        # TODO: Call whatever utility connects via WEP
        do_olpc_wep_config(options.ssid,  options.ap_pass)
        pass
    elif options.ap_type is None:
        print "type none"
        wireless_config_app = call(["/sbin/iwconfig", "eth0", "mode", "managed",
                                    options.ssid])
        do_dhcp()
        #nmsi.setActiveDevice(eth0,  options.ssid, 0x01)



if __name__ == "__main__":
    sys.exit(main())

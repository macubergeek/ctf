#/usr/bin/env python
"""getone: Shared library for the olpc-contrib package

When imported creates confiuration files in the user's home folder"""
## Copyright (C) 2008 FFM
## Author: FFM <http://en.wikipedia.org/User:FFM>
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

from __future__ import with_statement
import subprocess
import os
import sys
import cPickle

getonedir = os.path.join(os.path.expanduser("~"), ".getone")

class NewBuildParsingError(Exception):
    pass

def init_dirs():
    """Create the configuration directory"""
    mkdir(getonedir)    

def is_root():
    '''Return True if the user is root, false if not'''
    if os.geteuid() == 0 or os.getuid() == 0:
        return True
    return False
    
def root_req():
    """Check if the user is root"""
    print "Please run this script as the root user.\n This can be accomplished by typing \"sudo\" or \"su -c\"  to the command, depending on your system."
    sys.exit(1)
    
def mkdir(newdir):
    """works the way a good mkdir should :)
        - already exists, silently complete
        - regular file in the way, raise an exception
        - parent directory(ies) does not exist, make them as well
        
        From ASPN's python cookbook.
    """
    if os.path.isdir(newdir):
        pass
    elif os.path.isfile(newdir):
        raise OSError("a file with the same name as the desired " \
                      "dir, '%s', already exists." % newdir)
    else:
        head, tail = os.path.split(newdir)
        if head and not os.path.isdir(head):
            mkdir(head)
        #print "_mkdir %s" % repr(newdir)
        if tail:
            os.mkdir(newdir)

def is_newbuild(base=getonedir):
    """Figure out whether the OS has been updated.
    """
    # TODO: Finish this.
    try:
        with open(os.path.join(base,"last_build"),  "r") as buildfile:
            old_version = buildfile.readline()
        with open("/boot/olpc_build", "r") as newfile:
            new_version = newfile.readline()           
    except IOError:
        return "Buildfile not found"
    else:
        if old_version == new_version:
            return "Same" # The versions are the same
        else: #Woo Hoo! Time to get some work done!
            return "New"

init_dirs()

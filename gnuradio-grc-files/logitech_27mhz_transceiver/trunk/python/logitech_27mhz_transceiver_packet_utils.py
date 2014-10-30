#
# Copyright 2005,2006,2007 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import struct
import numpy
from gnuradio import gru

import binascii
from struct import *

import sys

shift_flag = False

glob_cnt = 0

def conv_packed_binary_string_to_1_0_string(s):
    """
    '\xAF' --> '10101111'
    """
    r = []
    for ch in s:
        x = ord(ch)
        for i in range(7,-1,-1):
            t = (x >> i) & 0x1
            r.append(t)

    return ''.join(map(lambda x: chr(x + ord('0')), r))

def conv_1_0_string_to_packed_binary_string(s):
    """
    '10101111' -> ('\xAF', False)

    Basically the inverse of conv_packed_binary_string_to_1_0_string,
    but also returns a flag indicating if we had to pad with leading zeros
    to get to a multiple of 8.
    """
    if not is_1_0_string(s):
        raise ValueError, "Input must be a string containing only 0's and 1's"
    
    # pad to multiple of 8
    padded = False
    rem = len(s) % 8
    if rem != 0:
        npad = 8 - rem
        s = '0' * npad + s
        padded = True

    assert len(s) % 8 == 0

    r = []
    i = 0
    while i < len(s):
        t = 0
        for j in range(8):
            t = (t << 1) | (ord(s[i + j]) - ord('0'))
        r.append(chr(t))
        i += 8
    return (''.join(r), padded)
        

default_access_code = \
  conv_packed_binary_string_to_1_0_string('\xAC\xDD\xA4\xE2\xF2\x8C\x20\xFC')
preamble = \
  conv_packed_binary_string_to_1_0_string('\xA4\xF2')

def is_1_0_string(s):
    if not isinstance(s, str):
        return False
    for ch in s:
        if not ch in ('0', '1'):
            return False
    return True

def string_to_hex_list(s):
    return map(lambda x: hex(ord(x)), s)


def whiten(s, o):
    sa = numpy.fromstring(s, numpy.uint8)
    z = sa ^ random_mask_vec8[o:len(sa)+o]
    return z.tostring()

def dewhiten(s, o):
    return whiten(s, o)        # self inverse


def make_header(payload_len, whitener_offset=0):
    # Upper nibble is offset, lower 12 bits is len
    val = ((whitener_offset & 0xf) << 12) | (payload_len & 0x0fff)
    #print "offset =", whitener_offset, " len =", payload_len, " val=", val
    return struct.pack('!HH', val, val)


def gen_and_append_crc4(s):

    CRC4POLY = 0x13
    crc = 0x0

    for ch in s:

	if (crc & 0x8): check = "1"
	else: check = "0"

	if (check != ch):
		crc = ((crc<<1) ^ CRC4POLY) & 0xf
	else:
		crc = (crc<<1) & 0xf

    #print "crc: ", hex(crc)

    crc_bin = dec2binary(crc)
    while len(crc_bin)%4:
	crc_bin = "0" + crc_bin

    return s + crc_bin



def make_packet(payload, samples_per_symbol, bits_per_symbol,
                access_code=default_access_code, pad_for_usrp=True, kbid='', VERBOSE=0,
                whitener_offset=0, whitening=True):
    """
    Build a packet, given access code, payload, and whitener offset

    @param payload:               packet payload, len [0, 4096]
    @param samples_per_symbol:    samples per symbol (needed for padding calculation)
    @type  samples_per_symbol:    int
    @param bits_per_symbol:       (needed for padding calculation)
    @type bits_per_symbol:        int
    @param access_code:           string of ascii 0's and 1's
    @param whitener_offset        offset into whitener string to use [0-16)
    
    Packet will have access code at the beginning, followed by payload and finally CRC-4
    """


    global glob_cnt

    if not is_1_0_string(access_code):
        raise ValueError, "access_code must be a string containing only 0's and 1's (%r)" % (access_code,)

    if not whitener_offset >=0 and whitener_offset < 16:
        raise ValueError, "whitener_offset must be between 0 and 15, inclusive (%i)" % (whitener_offset,)

    access_code = "110011001100110011000000"

    (packed_access_code, padded) = conv_1_0_string_to_packed_binary_string(access_code)
    (packed_preamble, ignore) = conv_1_0_string_to_packed_binary_string(preamble)

    dtype = "0000000100" # data

    if len(kbid) <= 3:
	try:
	    int(kbid,16)
	except:
            raise ValueError, "keyboard id must be a string containing maximal 3 hexadecimal digits (%r)" % (kbid,)	

	kbid_hex = kbid
	if VERBOSE: print "using kbid: " , kbid_hex
    else:
        raise ValueError, "keyboard id must be a string containing maximal 3 hexadecimal digits (%r)" % (kbid,)



    keyboardid = dec2binary(int(kbid_hex,16))
    keyboardid = append_zeros_to_len(keyboardid,12)

    #__________- T Y P E-_________KBID__________-________DATA_________-__CRC__-
    #0 0 0 0 0 0 0 1 1 0 0 1 0 1 0 1 1 0 1 1 0 1 0 1 0 0 1 0 0 1 0 0 0 0 0 0 0 0 0 0 1   #0x56d
    #0 0 0 0 0 0 0 1 1 0 0 0 1 0 1 1 1 1 0 0 0 1 0 1 0 0 1 0 0 1 0 0 0 0 1 0 1 1 1 0 0 0 #0x2f1


    send_capital = False
    #lookup little chars in payload in table   
    payl_ord = ord(payload)
    if (payl_ord-97) >= 0 and (payl_ord-97) < 26: # small letters
	data = "000"+bin_keys[payl_ord-97]+"1"
    elif (payl_ord-65) >= 0 and (payl_ord-65) < 26: # capitals
	send_capital = True
	data = "000"+bin_keys[payl_ord-65]+"1"
	data1 = "000"+bin_symb[bin_symb_ord.index(0)]+"1" #shift

    elif payl_ord == 32: #space
	data = "000"+bin_symb[bin_symb_ord.index(payl_ord)]+"1"

    elif payl_ord == 13: #cr
	data = "000"+bin_symb[bin_symb_ord.index(payl_ord)]+"1"

    elif payl_ord == 17: # defined as ctrl
	data = "000"+ctrls[0]+"1"
    elif payl_ord == 18: # defined as alt
	data = "000"+ctrls[1]+"1"
    elif payl_ord == 19: # defined as del
	data = "000"+ctrls[3]+"1"
    elif payl_ord == 20: # defined as f12
	data = "000"+ctrls[2]+"1"
    elif payl_ord == 21: # defined as win
	data = "000"+ctrls[4]+"1"
    elif payl_ord == 27: # esc
	data = "000"+ctrls[5]+"1"
    elif payl_ord == 31: # remove
	data = "000"+ctrls[6]+"1"
    elif payl_ord == 26: # defined as SYNC
	dtype = "0000000110" # sync
	data = "01001001000" ##works setpoint THE ONLY!!
	data2= "00101110000" ##works setpoint



    else:
	data = "00000000000"
	


    print "SENDING ",payload



    payload_bin = dtype + keyboardid + data  #payload_bin

    if VERBOSE: print "payload_bin:      " , payload_bin

    payload_with_crc = gen_and_append_crc4(payload_bin)

    if VERBOSE: print "payload_with_crc: " , payload_with_crc


    miller_bin = miller_encode(payload_with_crc)



    if VERBOSE: print "access_code + miller_bin: ", access_code, miller_bin

    (pkt_miller_bin,ignore) = conv_1_0_string_to_packed_binary_string(miller_bin)


    zeros = ""
    for n in range(100):
	zeros += "0"
    (pkt_zeros, ignore) = conv_1_0_string_to_packed_binary_string(zeros)

    if payl_ord >= 17 and payl_ord <= 21: #predefined sequences
	pkt = packed_access_code + pkt_miller_bin + pkt_miller_bin + pkt_zeros

    elif payl_ord == 26: # sync

	pkt_miller_bin2  = build_and_encode_pkt(dtype + keyboardid + data2)  #payload_bin2
	print "payload_bin2: " , gen_and_append_crc4(dtype + keyboardid + data2)

#	pkt_miller_bin3  = build_and_encode_pkt(dtype + keyboardid2 + data3)  #payload_bin3

	pkt = packed_access_code + pkt_miller_bin + packed_access_code + pkt_miller_bin + pkt_zeros #+ packed_access_code + pkt_miller_bin2 + packed_access_code + pkt_miller_bin2 + pkt_zeros #+ packed_access_code + pkt_miller_bin3 + packed_access_code + pkt_miller_bin3 + pkt_zeros

        pkt = pkt + pkt
        pkt = pkt + pkt


    elif (send_capital):
	pkt_miller_bin_keyup = build_and_encode_pkt(dtype + keyboardid + data[0:10] + '0')
	pkt_miller_bin1 = build_and_encode_pkt(dtype + keyboardid + data1)  #shift
	pkt_miller_bin1_keyup = build_and_encode_pkt(dtype + keyboardid + data1[0:10] + '0')

	pkt = packed_access_code + pkt_miller_bin1 + packed_access_code + pkt_miller_bin1 + packed_access_code + pkt_miller_bin + packed_access_code + pkt_miller_bin + pkt_zeros + packed_access_code + pkt_miller_bin_keyup + packed_access_code + pkt_miller_bin_keyup + packed_access_code + packed_access_code + pkt_miller_bin1_keyup + packed_access_code + pkt_miller_bin1_keyup + pkt_zeros

    else:
	pkt_miller_bin_keyup = build_and_encode_pkt(dtype + keyboardid + data[0:10] + '0')

	pkt = packed_access_code + pkt_miller_bin + packed_access_code + pkt_miller_bin + pkt_zeros + packed_access_code + pkt_miller_bin_keyup + packed_access_code + pkt_miller_bin_keyup + pkt_zeros

    #print string_to_hex_list(pkt)

    if VERBOSE: print string_to_hex_list(pkt)
    if VERBOSE: print "len_pkt: " ,len(pkt)


    return pkt


def build_and_encode_pkt(payload_bin):
    payload_with_crc = gen_and_append_crc4(payload_bin)
    miller_bin = miller_encode(payload_with_crc)
    (pkt_miller_bin,ignore) = conv_1_0_string_to_packed_binary_string(miller_bin)

    return pkt_miller_bin

def _npadding_bytes(pkt_byte_len, samples_per_symbol, bits_per_symbol):
    """
    Generate sufficient padding such that each packet ultimately ends
    up being a multiple of 512 bytes when sent across the USB.  We
    send 4-byte samples across the USB (16-bit I and 16-bit Q), thus
    we want to pad so that after modulation the resulting packet
    is a multiple of 128 samples.

    @param ptk_byte_len: len in bytes of packet, not including padding.
    @param samples_per_symbol: samples per bit (1 bit / symbolwidth GMSK)
    @type samples_per_symbol: int
    @param bits_per_symbol: bits per symbol (log2(modulation order))
    @type bits_per_symbol: int

    @returns number of bytes of padding to append.
    """
    modulus = 128
    byte_modulus = gru.lcm(modulus/8, samples_per_symbol) * bits_per_symbol / samples_per_symbol
    r = pkt_byte_len % byte_modulus
    if r == 0:
        return 0
    return byte_modulus - r
    

def unmake_packet(whitened_payload_with_crc, verbose=0, whitener_offset=0, dewhitening=False):
    """
    Return (ok, payload)

    @param whitened_payload_with_crc: string
    """

    if dewhitening:
        payload_with_crc = dewhiten(whitened_payload_with_crc, whitener_offset)
    else:
        payload_with_crc = (whitened_payload_with_crc)

 
    ok, payload = miller_decode(payload_with_crc,verbose)



    if 0:
        print "payload_with_crc =", string_to_hex_list(payload_with_crc)


    return ok, payload


def miller_decode(payload, VERBOSE):

    # first create symbol durations (10,15,20 etc.) from level changes 1/0

    sym_len = 5 # because 1 bit because of header missing + first bit in packet 0 not showed
    arr = []

    for i in range(0,len(payload)):

	vect = str_to_binary(payload[i])

	if i>0:
		vect_prev = str_to_binary(payload[i-1])
	for j in range(0,8):
		if i>0:
		   if j == 0:			
			if vect[j] == vect_prev[len(vect_prev)-1]:						
				sym_len += 5
			else:
				arr.append(sym_len)							
				sym_len = 5

		   else: 
			if vect[j] == vect[j-1]:						
				sym_len += 5
			else:
				arr.append(sym_len)			
				sym_len = 5	

		else:
		    if j>0:
			if vect[j] == vect[j-1]:	
				sym_len += 5
			else:
				arr.append(sym_len)
				sym_len = 5


	if sym_len > 100: #should not happen
		break


    #################
    miller_dec_vect=[]
    miller_dec_vect.append(0)	# first dec bit after startseq has to be zero

    for i in range(0,len(arr)):

	  if arr[i] >= 30:
		breakdata = "00"+conv_packed_binary_string_to_1_0_string(payload)+"1"
	      
	  elif arr[i] == 20:
		miller_dec_vect.append(0)
		miller_dec_vect.append(1)

	  elif arr[i] == 10:
	      if miller_dec_vect[len(miller_dec_vect)-1]==1:
		miller_dec_vect.append(1)

	      else:
		miller_dec_vect.append(0)

	  
	  elif arr[i] == 15:
	      if miller_dec_vect[len(miller_dec_vect)-1]== 0:
		miller_dec_vect.append(1)


	      else:
		miller_dec_vect.append(0)
		miller_dec_vect.append(0)


#################
### SECURED PACKETS
###_____TYPE____-_________KBID__________-___________DATA______________-DOWN
###0 0 0 0 1 0 0-0 0 1 1 0 1 1 1 0 0 0 0-0 1 0 1 1 0 1 1 0 1 0 1 0 0 0 1 
###0 1 2 3 4 5 6 7 8 910 1 2 3 4 5 6 7 8 920 1 2 3 4 5 6 7 8 930 1 2 3 4

### UNSECURED PACKETS
###__________- T Y P E-_________KBID__________-________DATA_________-__CRC__-
###0 0 0 0 0 0 0 1 1 0 1 1 1 1 0 0 0 1 0 1 0 1 0 1 0 0 1 0 0 0 1 0 0 0 0 1 0 0 0 0 
##################

### UNSECURED DATA (c)
###__________- T Y P E-_________KBID__________-________DATA_________-__CRC__-
###0 0 0 0 0 0 0 1 0 0 0 1 0 1 0 1 1 0 1 0 1 0 0 0 0 0 1 1 1 0 0 1 1 0 1 1 0 0
##################

    SILENT = 0

    key_found=False
    global shift_flag

    if len(miller_dec_vect) >= 35: # only take full vector

	if (int (''.join(map(str,miller_dec_vect[4:7])),2) == 4): #data flag in secured connection
    	  SECURED = 1
	else:
    	  SECURED = 0


	if not SECURED:
	    #00100 = data    -- miller_dec_vect[5:10] --> 7:9 enough
	    #00110 = sync

	    type_field = int (''.join(map(str,miller_dec_vect[7:9])))

	    if   (type_field ^ 10) == 0: #data
		if (VERBOSE): print "DATA VECTOR"
	    elif (type_field ^ 11) == 0: #sync
		if (VERBOSE): print "SYNC VECTOR"
	    else:
		if (VERBOSE): print "VECTOR DECOD UNKNOWN --> FAILED"
#		return 0


	    # [10:22] = keyboard id
	    keyb_field = int (''.join(map(str,miller_dec_vect[10:22])),2)   # convert to dezimal with base 2

	    if (VERBOSE): print "KEYBOARD ID: 0x%x" % keyb_field

	    if (type_field ^ 10) == 0: # only if data

		    # [25:32] = key
		    key_field = ''.join(map(str,miller_dec_vect[25:32]))  # leave as string

		    if (VERBOSE): print "KEY PRESSED: %s" % key_field;


		    # [32:33] = key up/down
		    keydown_field = int (''.join(map(str,miller_dec_vect[32:33])))

		    if keydown_field == 1: #down
			if (VERBOSE): print "KEY WAS PRESSED"
		    else:
			if (VERBOSE): print "KEY WAS RELEASED"


		    if key_field in bin_keys:
			key_found = chr(97+bin_keys.index(key_field))
			if (VERBOSE): print "FOUND KEY PRESSED: %c" % key_found
		    elif key_field in bin_numbers:
			key_found = chr(48+bin_numbers.index(key_field))
			if (VERBOSE): print "FOUND KEY PRESSED: %c" % key_found
		    elif key_field in bin_symb:
			if bin_symb_ord[bin_symb.index(key_field)] == 0:  #SHIFT FOUND
				if keydown_field: shift_flag = True # use global var, not really elegant
				else: shift_flag = False
				if (VERBOSE): print "SHIFT KEY"
				key_found = False
			else:
				key_found = chr(bin_symb_ord[bin_symb.index(key_field)])
				if (VERBOSE): print "FOUND KEY PRESSED: %c" % key_found
		    else:
			key_found = False
			if (VERBOSE): print "NOT FOUND"


		    if not SILENT and key_found and not VERBOSE and keydown_field == 1: print key_found 


	    # print full decoded vector
	    if (VERBOSE):
		    for i in range(0,len(miller_dec_vect)):
			print miller_dec_vect[i],
		    print ""


	else: #SECURED
	    if (VERBOSE): print "SECURED CONNECTION"
  	    ###_____TYPE____-_________KBID__________-___________DATA______________-DOWN
	    ###0 0 0 0 1 0 0-0 0 1 1 0 1 1 1 0 0 0 0-0 1 0 1 1 0 1 1 0 1 0 1 0 0 0 1 

	    #for i in range(len(miller_dec_vect)):
	    #  print miller_dec_vect[i],

	    # [10:22] = keyboard id
	    keyb_field = int (''.join(map(str,miller_dec_vect[7:19])),2)   # convert to dezimal with base 2

	    if (VERBOSE): print "KEYBOARD ID: 0x%x" % keyb_field
	    # [4:7] = type 0 0 0 0 1 0 0 
	    type_field = int (''.join(map(str,miller_dec_vect[4:7])),2)   # convert to dezimal with base 2

	    #00100 = data    -- miller_dec_vect[5:10] --> 7:9 enough
	    type_field_unsec = int (''.join(map(str,miller_dec_vect[7:9])))

	    if type_field == 4:
		    for i in range(19,35):
		      print miller_dec_vect[i],
		    print ""



	if (VERBOSE): print "_______________"


    if key_found and keydown_field:
	if shift_flag: key_found = chr(ord(key_found)-32) #shift ascii code to capitals
        return 1, key_found
    else:
	return 0, 0




def miller_encode(payload):

	initial=1; # start flag is low, so signal must start high!
	vector=[];
	
	pre = initial;

	for n in range(len(payload)):

	  if (payload[n] == "1"):
	      vector.append(pre)  #[k++]=pre;
	      vector.append(pre^1) #[k++]=-pre;
	      pre=pre^1  #switch signal state

     
	  else:
	      vector.append(pre) #[k++]=pre;
	      vector.append(pre) #[k++]=pre;
	      if (n+1<len(payload)):# {  // ELSE PROBLEM IF n == len
	        if (payload[n+1] == "0"): 
		  pre=pre^1  #switch signal state


	#fill to 6 times high
	i=len(vector)-1


	if vector[i] == 0:

	    j=i-1
	    while vector[j] == vector[i]:  #count how often the last bit came
		j-=1
	    #print "ENDS LOW"
	    for k in range(0,4-(i-j)-2): # expand to low t2
		vector.append(0)

	    for n in range(6):		#add t3 high
		vector.append(1)

#	    if vector[i-1] != 0:	#verfiy if last bit has only one duration, if so, add two more
#		vector.append(0)
#		vector.append(0)
#	    for n in range(6):		#add t3 high
#		vector.append(1)
	else:

#	    if vector[i-1] != 1:	#verfiy if last bit has only one duration, if so, add one more
#		vector.append(1)
#	    vector.append(0)		#signal ended high, add t1 low
#	    vector.append(0)

#	    for n in range(6):		#add t3 high
#		vector.append(1)


	    j=i-1
	    while vector[j] == vector[i]:  #count how often the last bit came
		j-=1
	    #print "ENDS HIGH"
	    for k in range(0,4-(i-j)-2): # expand to high t2
		vector.append(1)

	    vector.append(0)		#signal ended high, add t1 low
	    vector.append(0)

	    for n in range(6):		#add t3 high
		vector.append(1)



	while len(vector)%8: # add ones at the end to have a multiple of 8
	    vector.append(1)
	    

	#convert numeric list to binary string
	ret_string = ''
	for n in vector:
	  ret_string = ret_string + dec2binary(n)

	return ret_string

######################################

def char_to_binary(c):
    n = ord(c)
    result = ""
    while n:
        if n&1: result = "1" + result
        else:   result = "0" + result
        n >>= 1
    return result.zfill(8)

def str_to_binary(s):
    return " ".join([char_to_binary(c) for c in s])

def dec2binary(n):
	bStr = ''
	if n < 0: raise ValueError, "must be a positive integer"
	if n == 0: return '0'
	while n > 0:
		bStr = str(n % 2) + bStr
		n = n >> 1
	return bStr

def append_zeros_to_len(n,l):
    while len(n)%l:
	n = "0" + n
    return n


bin_keys = []
bin_keys.append('0011110') #a -- 97
bin_keys.append('0000101') #b
bin_keys.append('0111001') #c
bin_keys.append('0111110') #d
bin_keys.append('0101010') #e
bin_keys.append('1111110') #f
bin_keys.append('0000001') #g
bin_keys.append('1000001') #h
bin_keys.append('1111010') #i
bin_keys.append('0100001') #j
bin_keys.append('1100001') #k
bin_keys.append('0010001') #l
bin_keys.append('0100101') #m
bin_keys.append('1000101') #n
bin_keys.append('0000110') #o
bin_keys.append('1000110') #p
bin_keys.append('0001010') #q
bin_keys.append('1101010') #r
bin_keys.append('1011110') #s
bin_keys.append('0011010') #t
bin_keys.append('0111010') #u
bin_keys.append('1111001') #v
bin_keys.append('1001010') #w
bin_keys.append('1011001') #x
bin_keys.append('0011001') #y
bin_keys.append('1011010') #z

bin_numbers = []
bin_numbers.append('1101100') #0 -->48
bin_numbers.append('0100100') #1
bin_numbers.append('1100100') #2
bin_numbers.append('0010100') #3
bin_numbers.append('1010100') #4
bin_numbers.append('0110100') #5
bin_numbers.append('1110100') #6
bin_numbers.append('0001100') #7
bin_numbers.append('1001100') #8
bin_numbers.append('0101100') #9

bin_symb = []
bin_symb.append('0111101') #space #dec32
bin_symb.append('1110001') #cr #dec13
bin_symb.append('0010101') #. #dec46
bin_symb.append('1100101') #, #dec44
bin_symb.append('1010101') #- #dec45
bin_symb.append('1110011') # # #dec35
bin_symb.append('1100110') # + #dec43
bin_symb.append('1101001') #shift left
bin_symb.append('0110101') #shift right



bin_symb_ord = []
bin_symb_ord.append(32) #space #dec32
bin_symb_ord.append(13) #cr #dec13
bin_symb_ord.append(46) #. #dec46
bin_symb_ord.append(44) #, #dec44
bin_symb_ord.append(45) #- #dec45
bin_symb_ord.append(35) # # #dec35
bin_symb_ord.append(43) # + #dec43
bin_symb_ord.append(0) #shift left
bin_symb_ord.append(0) #shift right



ctrls = []
ctrls.append('0011101') #ctrl
ctrls.append('1011101') #alt
ctrls.append('1011000') #f12
ctrls.append('0010110') #del
ctrls.append('0111011') #win
ctrls.append('1000000') #esc
ctrls.append('1111100') #remove

ctrls_name = []
ctrls_name.append('ctrl')
ctrls_name.append('alt') #alt
ctrls_name.append('f12') #f12
ctrls_name.append('del') #del
ctrls_name.append('win') #win
ctrls_name.append('esc') #esc
ctrls_name.append('rem') #remove




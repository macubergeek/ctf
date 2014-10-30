# Copyright 2008, 2009 Free Software Foundation, Inc.
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

from gnuradio import gr
from logitech_27mhz_transceiver import logitech_27mhz_transceiver_packet_utils as packet_utils
import logitech_27mhz_transceiver
import gnuradio.gr.gr_threading as _threading
import time

##payload length in bytes
DEFAULT_PAYLOAD_LEN = 512

##how many messages in a queue
DEFAULT_MSGQ_LIMIT = 2

##threshold for unmaking packets
DEFAULT_THRESHOLD = 12

##################################################
## Options Class for OFDM
##################################################
class options(object):
	def __init__(self, **kwargs):
		for key, value in kwargs.iteritems(): setattr(self, key, value)

##################################################
## Packet Encoder
##################################################
class _packet_encoder_thread(_threading.Thread):

	def __init__(self, msgq, payload_length, send):
		self._msgq = msgq
		self._payload_length = payload_length
		self._send = send
		_threading.Thread.__init__(self)
		self.setDaemon(1)
		self.keep_running = True
		self.start()

	def run(self):
		sample = '' #residual sample
		while self.keep_running:
			msg = self._msgq.delete_head() #blocking read of message queue
			sample = sample + msg.to_string() #get the body of the msg as a string


			for i in range(len(sample)):
				if ord(sample[i]) > 0:
					#print "SAMPLE: ", sample[i]
					payload = sample[i]

					if ord(payload) == 28: # "SENDING Ctrl+Alt+Del"
						self._send(chr(17)) # define 17 as ctrl
						self._send(chr(18)) # define 18 as alt
						self._send(chr(19)) # define 19 as del #127?
					elif ord(payload) == 29: # "SENDING Ctrl+Alt+F12"
						self._send(chr(17)) # define 17 as ctrl
						self._send(chr(18)) # define 18 as alt
						self._send(chr(20)) # define 20 as f12
					elif ord(payload) == 30: # "SENDING Windows+r"
						self._send(chr(21)) # define 21 as win
						self._send(chr(114)) # r

					else:						
						self._send(payload)
			#reset sample			
			sample = ''


def string_to_hex_list(s):
    return map(lambda x: hex(ord(x)), s)

class packet_encoder(gr.hier_block2):
	"""
	Hierarchical block for wrapping packet-based modulators.
	"""

	def __init__(self, samples_per_symbol, bits_per_symbol, access_code='', pad_for_usrp=True, kbid='', verbose=0):
		"""
		packet_mod constructor.
		@param samples_per_symbol number of samples per symbol
		@param bits_per_symbol number of bits per symbol
		@param access_code AKA sync vector
		@param pad_for_usrp If true, packets are padded such that they end up a multiple of 128 samples
		@param payload_length number of bytes in a data-stream slice
		"""
		#setup parameters
		self._samples_per_symbol = samples_per_symbol
		self._bits_per_symbol = bits_per_symbol
		self._kbid = kbid
		self._verbose = verbose
		if not access_code: #get access code
			access_code = packet_utils.default_access_code
		if not packet_utils.is_1_0_string(access_code):
			raise ValueError, "Invalid access_code %r. Must be string of 1's and 0's" % (access_code,)
		self._access_code = access_code
		self._pad_for_usrp = pad_for_usrp
		#create blocks
		msg_source = gr.message_source(gr.sizeof_char, DEFAULT_MSGQ_LIMIT)
		self._msgq_out = msg_source.msgq()
		#initialize hier2
		gr.hier_block2.__init__(
			self,
			"packet_encoder",
			gr.io_signature(0, 0, 0), # Input signature
			gr.io_signature(1, 1, gr.sizeof_char) # Output signature
		)
		#connect
		self.connect(msg_source, self)

	def send_pkt(self, payload):
		"""
		Wrap the payload in a packet and push onto the message queue.
		@param payload string, data to send
		"""
		#print "send_pkt: ", len(payload)
		packet = packet_utils.make_packet(
			payload,
			self._samples_per_symbol,
			self._bits_per_symbol,
			self._access_code,
			self._pad_for_usrp,
			self._kbid,
			self._verbose,
		)
		msg = gr.message_from_string(packet)
		self._msgq_out.insert_tail(msg)
		#print "send_pkt: ", string_to_hex_list(packet)

##################################################
## Packet Decoder
##################################################
class _packet_decoder_thread(_threading.Thread):

	def __init__(self, msgq, callback,verbose):
		_threading.Thread.__init__(self)
		self.setDaemon(1)
		self._msgq = msgq
		self.callback = callback
		self._verbose = verbose
		self.keep_running = True
		self.start()

	def run(self):
		while self.keep_running:
			msg = self._msgq.delete_head()
			ok, payload = packet_utils.unmake_packet(msg.to_string(), self._verbose, int(msg.arg1()))
			if self.callback:
				self.callback(ok, payload)

class packet_decoder(gr.hier_block2):
	"""
	Hierarchical block for wrapping packet-based demodulators.
	"""

	def __init__(self, access_code='', threshold=-1, callback=None, verbose=0):
		"""
		packet_demod constructor.
		@param access_code AKA sync vector
		@param threshold detect access_code with up to threshold bits wrong (0 -> use default)
		@param callback a function of args: ok, payload
		"""
		#access code
		if not access_code: #get access code
			access_code = packet_utils.default_access_code
		if not packet_utils.is_1_0_string(access_code):
			raise ValueError, "Invalid access_code %r. Must be string of 1's and 0's" % (access_code,)
		self._access_code = access_code
		#threshold
		if threshold < 0: threshold = DEFAULT_THRESHOLD
		self._threshold = threshold
		#blocks
		msgq = gr.msg_queue(DEFAULT_MSGQ_LIMIT) #holds packets from the PHY
		correlator = gr.correlate_access_code_bb(self._access_code, self._threshold)
		framer_sink = logitech_27mhz_transceiver.framer_sink(msgq)

		#initialize hier2
		gr.hier_block2.__init__(
			self,
			"packet_decoder",
			gr.io_signature(1, 1, gr.sizeof_char), # Input signature
			gr.io_signature(0, 0, 0) # Output signature
		)
		#connect
		self.connect(self, correlator, framer_sink)
		#start thread
		_packet_decoder_thread(msgq, callback,verbose)

##################################################
## Packet Mod for OFDM Mod and Packet Encoder
##################################################
class packet_mod_base(gr.hier_block2):
	"""
	Hierarchical block for wrapping packet source block.
	"""

	def __init__(self, packet_source=None, payload_length=0):
		if not payload_length: #get payload length
			payload_length = DEFAULT_PAYLOAD_LEN
		if payload_length%self._item_size_in != 0:	#verify that packet length is a multiple of the stream size
			raise ValueError, 'The payload length: "%d" is not a mutiple of the stream size: "%d".'%(payload_length, self._item_size_in)
		#initialize hier2
		gr.hier_block2.__init__(
			self,
			"ofdm_mod",
			gr.io_signature(1, 1, self._item_size_in), # Input signature
			gr.io_signature(1, 1, packet_source._hb.output_signature().sizeof_stream_item(0)) # Output signature
		)
		#create blocks
		msgq = gr.msg_queue(DEFAULT_MSGQ_LIMIT)
		msg_sink = gr.message_sink(self._item_size_in, msgq, False) #False -> blocking
		#connect
		self.connect(self, msg_sink)
		self.connect(packet_source, self)
		#start thread
		_packet_encoder_thread(msgq, payload_length, packet_source.send_pkt)

class packet_mod_b(packet_mod_base): _item_size_in = gr.sizeof_char
class packet_mod_s(packet_mod_base): _item_size_in = gr.sizeof_short
class packet_mod_i(packet_mod_base): _item_size_in = gr.sizeof_int
class packet_mod_f(packet_mod_base): _item_size_in = gr.sizeof_float
class packet_mod_c(packet_mod_base): _item_size_in = gr.sizeof_gr_complex

##################################################
## Packet Demod for OFDM Demod and Packet Decoder
##################################################
class packet_demod_base(gr.hier_block2):
	"""
	Hierarchical block for wrapping packet sink block.
	"""

	def __init__(self, packet_sink=None):
		#initialize hier2
		gr.hier_block2.__init__(
			self,
			"ofdm_mod",
			gr.io_signature(1, 1, packet_sink._hb.input_signature().sizeof_stream_item(0)), # Input signature
			gr.io_signature(1, 1, self._item_size_out) # Output signature
		)
		#create blocks
		msg_source = gr.message_source(self._item_size_out, DEFAULT_MSGQ_LIMIT)
		self._msgq_out = msg_source.msgq()
		#connect
		self.connect(self, packet_sink)
		self.connect(msg_source, self)
		if packet_sink._hb.output_signature().sizeof_stream_item(0):
			self.connect(packet_sink, gr.null_sink(packet_sink._hb.output_signature().sizeof_stream_item(0)))

		self.lasttime=[]
		self.chars=[]


	def write_chr_to_file(self, filename, payload):
		self.outfile=open(filename, 'a')				
		self.outfile.write(payload)
		if ord(payload) == 13: # add lf to cr
		  self.outfile.write(chr(10))
		self.outfile.close()
		

	def recv_pkt(self, ok, payload):

		if ok:
 		  ### resend time diff while holding a key ~0.16
		  ### repeat time diff of one key ~0.06

		  # look if key is already in array - meaning it was already received 
		  if payload in self.chars:
			# calculate time difference since keystroke was received and now
			if time.clock()-self.lasttime[self.chars.index(payload)] > 0.1:
				self.write_chr_to_file('/tmp/rec_27mhz_keys.txt',payload)
				self.lasttime[self.chars.index(payload)] = time.clock()
			else: #reset

			   if time.clock()-self.lasttime[self.chars.index(payload)] < 0.05:
				self.lasttime[self.chars.index(payload)] = time.clock()
			   else:
				del self.lasttime[self.chars.index(payload)]
				del self.chars[self.chars.index(payload)]
		  else:
#			print payload
			self.write_chr_to_file('/tmp/rec_27mhz_keys.txt',payload)
			self.chars.append(payload)
			self.lasttime.append(time.clock())



class packet_demod_b(packet_demod_base): _item_size_out = gr.sizeof_char
class packet_demod_s(packet_demod_base): _item_size_out = gr.sizeof_short
class packet_demod_i(packet_demod_base): _item_size_out = gr.sizeof_int
class packet_demod_f(packet_demod_base): _item_size_out = gr.sizeof_float
class packet_demod_c(packet_demod_base): _item_size_out = gr.sizeof_gr_complex

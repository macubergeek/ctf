/* -*- c++ -*- */
/*
 * Copyright 2004,2006 Free Software Foundation, Inc.
 * 
 * This file is part of GNU Radio
 * 
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <logitech_27mhz_transceiver_framer_sink.h>
#include <gr_io_signature.h>
#include <cstdio>
#include <stdexcept>
#include <string.h>

#define VERBOSE 0

inline void
logitech_27mhz_transceiver_framer_sink::enter_search()
{
  if (VERBOSE)
    fprintf(stderr, "@ enter_search\n");

  d_state = STATE_SYNC_SEARCH;
}


inline void
logitech_27mhz_transceiver_framer_sink::enter_have_sync()
{
  if (VERBOSE)
    fprintf(stderr, "@ enter_have_sync ()\n");

  d_state = STATE_HAVE_SYNC;
  d_packetlen = MAX_PKT_LEN;  // use max_pkt_len value since it is cut if no signal is found
  d_packetlen_cnt = 0;
  d_packet_byte = 0;
  d_packet_byte_index = 0;
  d_held_one = 0;
}

logitech_27mhz_transceiver_framer_sink_sptr
logitech_27mhz_transceiver_make_framer_sink(gr_msg_queue_sptr target_queue)
{
  return logitech_27mhz_transceiver_framer_sink_sptr(new logitech_27mhz_transceiver_framer_sink(target_queue));
}


logitech_27mhz_transceiver_framer_sink::logitech_27mhz_transceiver_framer_sink(gr_msg_queue_sptr target_queue)
  : gr_sync_block ("framer_sink_1",
		   gr_make_io_signature (1, 1, sizeof(unsigned char)),
		   gr_make_io_signature (0, 0, 0)),
    d_target_queue(target_queue)
{
  enter_search();
}

logitech_27mhz_transceiver_framer_sink::~logitech_27mhz_transceiver_framer_sink ()
{
}

int
logitech_27mhz_transceiver_framer_sink::work (int noutput_items,
			gr_vector_const_void_star &input_items,
			gr_vector_void_star &output_items)
{
  const unsigned char *in = (const unsigned char *) input_items[0];
  int count=0;
  
  if (VERBOSE)
    fprintf(stderr,">>> Entering state machine\n");

  while (count < noutput_items){
    switch(d_state) {
      
    case STATE_SYNC_SEARCH:    // Look for flag indicating beginning of pkt
      if (VERBOSE)
	fprintf(stderr,"SYNC Search, noutput=%d\n", noutput_items);

      while (count < noutput_items) {
	if (in[count] & 0x2){  // Found it, set up for header decode
	  enter_have_sync();
	  break;
	}
	count++;
      }
      break;

      
    case STATE_HAVE_SYNC:
      if (VERBOSE)
	fprintf(stderr,"Packet Build\n");

      while (count < noutput_items) {   // shift bits into bytes of packet one at a time
	d_packet_byte = (d_packet_byte << 1) | (in[count++] & 0x1);
	
	// MF
	if (in[count-1] == 1)
	  d_held_one++;
	else if (d_held_one < 6)
	  d_held_one=0;

	if (d_packet_byte_index++ == 7) {	  	// byte is full so move to next byte
	  d_packet[d_packetlen_cnt++] = d_packet_byte;
	  d_packet_byte_index = 0;


	  //fprintf(stderr,"d_held_one: %d----d_packetlen_cnt: %d----d_packet_byte: %x\n",d_held_one, d_packetlen_cnt,d_packet_byte);
	  if ((d_held_one >=6) || (d_packetlen_cnt == d_packetlen)) {

	    // msg needs to be a multiple of 4
	    while (d_packetlen_cnt % 4 > 0)
	      d_packet[d_packetlen_cnt++] = 0;


	    // build a message with 
	    gr_message_sptr msg =
	      gr_make_message(0, 0, 0, d_packetlen_cnt);
	    memcpy(msg->msg(), d_packet, d_packetlen_cnt);

	    d_target_queue->insert_tail(msg);		// send it
	    msg.reset();  				// free it up

	    enter_search();
	    break;
	  }

	}
      }
      break;

    default:
      assert(0);

    } // switch

  }   // while

  return noutput_items;
}

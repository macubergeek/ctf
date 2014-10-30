/* -*- c++ -*- */
/*
 * Copyright 2005,2006 Free Software Foundation, Inc.
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

#ifndef INCLUDED_logitech_27mhz_transceiver_framer_sink_H
#define INCLUDED_logitech_27mhz_transceiver_framer_sink_H

#include <gr_sync_block.h>
#include <gr_msg_queue.h>

class logitech_27mhz_transceiver_framer_sink;
typedef boost::shared_ptr<logitech_27mhz_transceiver_framer_sink> logitech_27mhz_transceiver_framer_sink_sptr;

logitech_27mhz_transceiver_framer_sink_sptr 
logitech_27mhz_transceiver_make_framer_sink (gr_msg_queue_sptr target_queue);

/*!
 * \brief Given a stream of bits and access_code flags, assemble packets.
 * \ingroup sink_blk
 *
 * input: stream of bytes from gr_correlate_access_code_bb
 * output: none.  Pushes assembled packet into target queue
 *
 * The framer expects a fixed length header of 2 16-bit shorts
 * containing the payload length, followed by the payload.  If the 
 * 2 16-bit shorts are not identical, this packet is ignored.  Better
 * algs are welcome.
 *
 * The input data consists of bytes that have two bits used.
 * Bit 0, the LSB, contains the data bit.
 * Bit 1 if set, indicates that the corresponding bit is the
 * the first bit of the packet.  That is, this bit is the first
 * one after the access code.
 */
class logitech_27mhz_transceiver_framer_sink : public gr_sync_block
{
  friend logitech_27mhz_transceiver_framer_sink_sptr 
  logitech_27mhz_transceiver_make_framer_sink (gr_msg_queue_sptr target_queue);

 private:
  enum state_t {STATE_SYNC_SEARCH, STATE_HAVE_SYNC};

  static const int MAX_PKT_LEN    = 200;	// has to be >2

  gr_msg_queue_sptr  d_target_queue;		// where to send the packet when received
  state_t            d_state;
  unsigned int       d_header;			// header bits
  int		     d_headerbitlen_cnt;	// how many so far

  unsigned char      d_packet[MAX_PKT_LEN];	// assembled payload
  unsigned char	     d_packet_byte;		// byte being assembled
  int		     d_packet_byte_index;	// which bit of d_packet_byte we're working on
  int 		     d_packetlen;		// length of packet
  int		     d_packetlen_cnt;		// how many so far
  int		     d_held_one;		// counter how many times 1 was held

 protected:
  logitech_27mhz_transceiver_framer_sink(gr_msg_queue_sptr target_queue);

  void enter_search();
  void enter_have_sync();
  

 public:
  ~logitech_27mhz_transceiver_framer_sink();

  int work(int noutput_items,
	   gr_vector_const_void_star &input_items,
	   gr_vector_void_star &output_items);
};

#endif /* INCLUDED_logitech_27mhz_transceiver_framer_sink_H */

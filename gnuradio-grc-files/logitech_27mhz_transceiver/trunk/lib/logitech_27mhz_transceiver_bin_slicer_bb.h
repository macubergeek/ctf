/* -*- c++ -*- */
/*
 * Copyright 2004 Free Software Foundation, Inc.
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
#ifndef INCLUDED_LOGITECH_27MHZ_TRANSCEIVER_BIN_SLICER_bb_H
#define INCLUDED_LOGITECH_27MHZ_TRANSCEIVER_BIN_SLICER_bb_H

#include <gr_block.h>

class logitech_27mhz_transceiver_bin_slicer_bb;

/*
 * We use boost::shared_ptr's instead of raw pointers for all access
 * to gr_blocks (and many other data structures).  The shared_ptr gets
 * us transparent reference counting, which greatly simplifies storage
 * management issues.  This is especially helpful in our hybrid
 * C++ / Python system.
 *
 * See http://www.boost.org/libs/smart_ptr/smart_ptr.htm
 *
 * As a convention, the _sptr suffix indicates a boost::shared_ptr
 */
typedef boost::shared_ptr<logitech_27mhz_transceiver_bin_slicer_bb> logitech_27mhz_transceiver_bin_slicer_bb_sptr;

/*!
 * \brief Return a shared_ptr to a new instance of logitech_27mhz_transceiver_bin_slicer_bb.
 *
 * To avoid accidental use of raw pointers, logitech_27mhz_transceiver_bin_slicer_bb's
 * constructor is private.  logitech_27mhz_transceiver_bin_slicer_bb is the public
 * interface for creating new instances.
 */
logitech_27mhz_transceiver_bin_slicer_bb_sptr logitech_27mhz_transceiver_make_bin_slicer_bb ();

/*!
 * \brief square a stream of floats.
 * \ingroup block
 *
 * \sa logitech_27mhz_transceiver_bin_slicer_bb for a version that subclasses gr_sync_block.
 */
class logitech_27mhz_transceiver_bin_slicer_bb : public gr_block
{
private:
  // The friend declaration allows logitech_27mhz_transceiver_make_bin_slicer_bb to
  // access the private constructor.

  friend logitech_27mhz_transceiver_bin_slicer_bb_sptr logitech_27mhz_transceiver_make_bin_slicer_bb ();

  logitech_27mhz_transceiver_bin_slicer_bb ();  	// private constructor
  int history_size;

 public:
  ~logitech_27mhz_transceiver_bin_slicer_bb ();	// public destructor

  // Where all the action really happens

  int general_work (int noutput_items,
		    gr_vector_int &ninput_items,
		    gr_vector_const_void_star &input_items,
		    gr_vector_void_star &output_items);
};

#endif /* INCLUDED_LOGITECH_27MHZ_TRANSCEIVER_BIN_SLICER_bb_H */

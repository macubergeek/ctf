/* -*- c++ -*- */
/* 
 * Copyright 2012 <+YOU OR YOUR COMPANY+>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_POCSAG_DECODER_H
#define INCLUDED_POCSAG_DECODER_H

#include <pocsag_api.h>
#include <gr_block.h>
#include <string.h>
#include <stdio.h>

class pocsag_decoder;
typedef boost::shared_ptr<pocsag_decoder> pocsag_decoder_sptr;

POCSAG_API pocsag_decoder_sptr pocsag_make_decoder (unsigned int word);

/*!
 * \brief a decoder for POCSAG messages
 * \ingroup block
 * 
 * Blah 
 * Blah
 * Blah
 *
 */
#define POCSAG_BATCH_BYTES 64
#define POCSAG_BATCH_WORDS POCSAG_BATCH_BYTES/sizeof(uint32_t)

#define POCSAG_MESSAGE_MASK 0xFFFFF
#define POCSAG_MESSAGE_SHIFT 11

#define POCSAG_ADDRESS_MASK 0x1FFFF8
#define POCSAG_ADDRESS_SHIFT 10

#define POCSAG_FUNCTION_MASK 0x1800
#define POCSAG_FUNCTION_SHIFT 11

#define POCSAG_IS_TEXT(f) (f == 3)

#define POCSAG_GET_BCD(m) (((m&0xF0000)>>16)&0xF)
#define POCSAG_ASCII_BIT(m) (((m&0x20000)>>17)&0x1)

#define POCSAG_N_RESID 256

#define POCSAG_DEFAULT_SYNCWORD 0x7CD215D8
#define POCSAG_IDLE_WORD        0x7A89C197

class POCSAG_API pocsag_decoder : public gr_block
{
	friend POCSAG_API pocsag_decoder_sptr pocsag_make_decoder (unsigned int word);
 private:
	enum
	{
		SYNC_WAIT,
		SYNCED,
		FUBAR
	} d_state;
	int d_bytecnt;
	uint32_t d_codewords[POCSAG_BATCH_WORDS];
	int d_codendx;
	char d_residual[POCSAG_N_RESID];
	int d_n_residual;
	uint32_t d_syncword, d_codeword, d_bitcounter;
	const char *POCSAG_BCD_MAP;
	int d_debugcounter;
	int d_msgfilter;
	int d_tccnt;
	unsigned char d_textchar;
	char d_nbuffer[256];
	char d_tbuffer[256];
	uint32_t d_address;
	uint32_t d_function;

 public:
 	pocsag_decoder (unsigned int word);
	~pocsag_decoder ();
	
	int set_syncword(unsigned int word);
	int set_msgfilter(int filter);

  int general_work (int noutput_items,
		    gr_vector_int &ninput_items,
		    gr_vector_const_void_star &input_items,
		    gr_vector_void_star &output_items);
};

#endif /* INCLUDED_POCSAG_DECODER_H */


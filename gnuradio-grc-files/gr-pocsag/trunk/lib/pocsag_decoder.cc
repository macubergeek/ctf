/* -*- c++ -*- */
/* 
 * Copyright 2012 Marcus Leech.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gr_io_signature.h>
#include <pocsag_decoder.h>

#define MIN_IN 1
#define MAX_IN 1

#define MIN_OUT 1
#define MAX_OUT 1

static uint32_t bch_syndrome (uint32_t);
static uint32_t bch_fix (uint32_t);

pocsag_decoder_sptr
pocsag_make_decoder (unsigned int codeword)
{
	return pocsag_decoder_sptr (new pocsag_decoder (codeword));
}

/*
 * \brief build a pocsag_decoder instance
 * \param codeword  the SYNC codeword to use.  0 means "use default"
 */
pocsag_decoder::pocsag_decoder (unsigned int codeword)
	: gr_block ("decoder",
		gr_make_io_signature (MIN_IN, MAX_IN, sizeof (unsigned char)),
		gr_make_io_signature (MIN_OUT, MAX_OUT, sizeof (unsigned char))),
		d_state(SYNC_WAIT),
		d_bytecnt(POCSAG_BATCH_BYTES),
		d_codendx(0), d_n_residual(0), d_syncword(codeword), POCSAG_BCD_MAP("0123456789?U -)("),
		d_debugcounter(0), d_codeword(0), d_bitcounter(0), d_msgfilter(1), d_textchar(0), d_tccnt(0),
		d_address(0)
{
	/*
	 * Some tweakage necessary here--big enough for full POCSAG messages is necessary
	 */
	set_output_multiple(120);
	if (codeword == 0)
	{
		d_syncword = POCSAG_DEFAULT_SYNCWORD;
	}
}


pocsag_decoder::~pocsag_decoder ()
{
}


/* A decoder work function for POCSAG
 * 
 * \brief take in unpacked bits.  Occasionally emit some ASCII when we have a good POCSAG decode
 */
int
pocsag_decoder::general_work (int noutput_items,
			       gr_vector_int &ninput_items,
			       gr_vector_const_void_star &input_items,
			       gr_vector_void_star &output_items)
{
  const unsigned char *in = (unsigned char *) input_items[0];
  unsigned char *out = (unsigned char *) output_items[0];
  int i, cdndx;
  int nout;
  char outbuf[1024];
  
  nout = 0;
  outbuf[0] = '\0';
  
  /*
   * We have leftovers, stuff them into the head of "outbuf"
   */
  if (d_n_residual)
  {
	  memcpy (outbuf, d_residual, d_n_residual);
	  outbuf[d_n_residual] = '\0';
	  d_n_residual = 0;
  }
  
  /*
   * While we have input items, runt he state machine
   */
  if (d_msgfilter == -1)
  {
	  consume_each (ninput_items[0]);
	  return 0;
  }
  for (i = 0; i < ninput_items[0]; i++)
  {
	  
	  switch (d_state)
	  {
	  case SYNC_WAIT:
		/*
		 * Look for d_syncword
		 */
		d_codeword <<= 1;
		d_codeword |= in[i]&0x1;
		if (d_codeword == d_syncword)
		{
			d_state = SYNCED;
			d_codendx = 0;
			d_codeword = 0;
			d_bitcounter = 0;
			if (d_msgfilter >= 0)
			{
				sprintf (outbuf+strlen(outbuf), "=====SYNC====\n");
			}
		}
		break;
	
	  /*
	   * We're SYNCED  do stuff
	   */
	  case SYNCED:
	    /*
	     * Stuff codeword
	     */
	    d_codeword <<= 1;
	    d_codeword |= in[i]&0x1;
	    d_bitcounter++;
	    
	    /*
	     * We've stuffed enough bits
	     */
	    if (d_bitcounter >= sizeof(uint32_t)*8)
	    {
			/*
			 * Make sure we start back at the beginning for the new codeword
			 */
			d_bitcounter = 0;
			
			/*
			 * Add it to the pantheon of codewords
			 */
			d_codewords[d_codendx] = d_codeword;
			d_codendx++;
			d_codeword = 0;
			
			/*
			 * We have an entire batch now
			 */
			if (d_codendx >= POCSAG_BATCH_WORDS)
			{
				/*
				 * Reset state back to SYNC_WAIT
				 */
				d_state = SYNC_WAIT;
				d_codendx = 0;
				d_codeword = 0;
				
				/*
				 * We now have a full batch inside d_codewords
				 *
				 * 
				 * For each codeword, process it
				 */
				for (cdndx = 0; cdndx < POCSAG_BATCH_WORDS; cdndx++)
				{
					uint32_t address;
					uint32_t messagebits;
					uint32_t function;

					/*
					 * If the BCH FEC fails, try to fix it.  Doesn't always work.
					 * 
					 */
					if (bch_syndrome(d_codewords[cdndx]))
					{
						d_codewords[cdndx] = bch_fix(d_codewords[cdndx]);
					}
					
					if (d_codewords[cdndx] == POCSAG_IDLE_WORD)
					{
						if (d_msgfilter >= 3)
						{
							sprintf (outbuf+strlen(outbuf), "!IDLE!\n");
						}
						continue;
					}
					
					/*
					 * Message codeword
					 */
					if (d_codewords[cdndx] & (1<<31))
					{
						messagebits = d_codewords[cdndx];
						messagebits >>= POCSAG_MESSAGE_SHIFT;
						messagebits &= POCSAG_MESSAGE_MASK;
						
						/*
						 * Numeric
						 */
						if (!POCSAG_IS_TEXT(function))
						{
							int k;
							
							for (k = 0; k < 5; k++)
							{
								int x;
								x = (messagebits >> ((4-k)*4)) & 0xF;
								if (strlen (d_nbuffer) < sizeof(d_nbuffer)-2)
								{
									sprintf (d_nbuffer+strlen(d_nbuffer), "%c", POCSAG_BCD_MAP[x]);
								}
							}
						}
						
						/*
						 * Text
						 */
						else
						{
							int n;
							
							for (n = 0; n < 20; n++)
							{
								unsigned char x;
								x = ((messagebits & (1<<19))) ? 1 : 0;
								messagebits <<= 1;
								d_textchar |= x << (d_tccnt);
								d_tccnt++;
								if (d_tccnt >= 7)
								{
									if (strlen (d_tbuffer) < sizeof(d_tbuffer)-2)
									{
										sprintf (d_tbuffer+strlen(d_tbuffer), "%c", d_textchar&0x7F);
									}
									d_textchar = 0;
									d_tccnt = 0;
								}
							}
						}
					}
					/*
					 * Address codeword
					 */
					else if ((d_codewords[cdndx] & (1<<31)) == 0)
					{
						
						address = d_codewords[cdndx];
						address >>= POCSAG_ADDRESS_SHIFT;
						address &= POCSAG_ADDRESS_MASK;
						if (address != d_address)
						{
							d_address = address;
						}
						address |= (cdndx>>1);
						
						function = d_codewords[cdndx] & POCSAG_FUNCTION_MASK;
						function >>= POCSAG_FUNCTION_SHIFT;

						/*
						 * We have to "clock out" the previous text when a new address record arrives
						 */
						if (strlen (d_tbuffer) > 0 && d_msgfilter >= 1)
						{
							sprintf (outbuf+strlen(outbuf), "TXT:|%s|\n", d_tbuffer);
							d_tbuffer[0] = 0;
							d_textchar = 0;
							d_tccnt = 0;
						}
						if (strlen (d_nbuffer) > 0 && d_msgfilter >= 2)
						{
							sprintf (outbuf+strlen(outbuf), "NUM:|%s|\n", d_nbuffer);
							d_nbuffer[0] = 0;
						}
											
						if (d_msgfilter >= 1)
						{
							sprintf (outbuf+strlen(outbuf), "ADDR-%06X:\n", address);
						}
					}
				}
				if (strlen (outbuf) > 0)
				{
					sprintf (outbuf+strlen(outbuf), "\n");
				}
			}
		}
	    break;
	  }
  }
  
  nout = 0;
  if (strlen(outbuf) != 0)
  {
	  /*
	   * Output buffer is big enough
	   */
	  if (noutput_items >= strlen(outbuf))
	  {
		memcpy (out, outbuf, strlen(outbuf));
		nout = strlen(outbuf);
	  }
	  /*
	   * Not big enough.  Poop.
	   * 
	   * use our "backing store" inside our object, and we'll make up for it on the next
	   *   pass
	   */
	  else
	  {
		  memcpy (out, outbuf, noutput_items);
		  memcpy (d_residual, outbuf+noutput_items, strlen(outbuf)-noutput_items);
		  nout = noutput_items;
		  d_n_residual = strlen(outbuf)-noutput_items;
	  }
  }

  // Tell runtime system how many input items we consumed on
  // each input stream.
  consume_each (ninput_items[0]);
  
  return (nout);
}

int
pocsag_decoder::set_syncword (unsigned int word)
{
	d_syncword = (uint32_t)word;
}

int
pocsag_decoder::set_msgfilter (int level)
{
	d_msgfilter = level;
}

/*
 * This portion shamelessly ripped off from the OSMOSDR POCSAG code
 * 
 */
#define BCH_POLY 0x769
#define BCH_N 31
#define BCH_K 21

static inline uint8_t
even_parity(uint32_t x)
{
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;
	x &= 0xf;
	return (0x6996 >> x) & 1;
}

static uint32_t
bch_syndrome(uint32_t data)
{
	uint32_t shreg = data >> 1; /* throw away parity bit */
	uint32_t mask = 1L << (BCH_N-1), coeff = BCH_POLY << (BCH_K-1);
	int n = BCH_K;

	for(; n > 0; mask >>= 1, coeff >>= 1, n--)
		if (shreg & mask)
			shreg ^= coeff;

	if (even_parity(data))
		shreg |= (1 << (BCH_N - BCH_K));

	return shreg;
}

static uint32_t
bch_fix(uint32_t data)
{
	uint32_t t;
	int i, j;

	for (i=0; i<32; i++) {
		t = data ^ (1<<i);
		if (!bch_syndrome(t))
			return t;
	}

		for (i=0; i<32; i++) {
			for (j=0; j<32; j++) {
				if (i == j)
					continue;
				t = data ^ ((1<<i) | (1<<j));
				if (!bch_syndrome(t))
					return t;
		}
	}

	return data;
}

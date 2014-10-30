/* -*- c++ -*- */

#define POCSAG_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "pocsag_swig_doc.i"

%{
#include "pocsag_decoder.h"
%}

GR_SWIG_BLOCK_MAGIC(pocsag,decoder);
%include "pocsag_decoder.h"

#if SWIGGUILE
%scheme %{
(load-extension-global "libguile-gnuradio-pocsag_swig" "scm_init_gnuradio_pocsag_swig_module")
%}

%goops %{
(use-modules (gnuradio gnuradio_core_runtime))
%}
#endif

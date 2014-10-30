10:01  satanklawz >> macuberg1ek: if you have an rtl, try something like rtl_fm -f 89000000 -R -s 1000000 -g 0 - | baudline -stdin -samplerate 1000000 -quadrature -flipcomplex -channels 2 -format le16


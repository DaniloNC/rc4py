#!/usr/bin/env python
# -*- coding: utf-8 -*-
#=======================================================================
import sys
import struct
from rc4 import RC4

def main():
    my_key = [0x01, 0x02, 0x03, 0x04, 0x05]
    my_rc4 = RC4(False)
    my_rc4.load_key(my_key)
    my_file = open('rc4data.bin','wb')

    for my_key in range(10000000):
        my_keystream = my_rc4.generate_keystream(1)
        data = struct.pack('B', my_keystream[0])
        my_file.write(data)

    my_file.close()
    

#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())
    

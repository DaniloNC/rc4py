#!/usr/bin/env python
# -*- coding: utf-8 -*-
#=======================================================================
#
# rc4.py
# ------
# Pure Python implementation of the RC4 stream cipher.
# Note: This is for Python 2.x.
#
# The purpose of this module is not to reach maximum performance
# (you wouldn't use Python then anyway). The purpose is to get an
# object oriented, readable, clean, pure Python implementation that
# can be dissected and used as a reference model.
#
# 
# Version: 1.0,
# Release date: 2011-09-01
#
# 
# Author: Joachim Strömbergson
# Copyright (c) 2011, Secworks Sweden AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
# 
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys

        
#-------------------------------------------------------------------
# class RC4()
#-------------------------------------------------------------------
class RC4():
    def __init__(self, verbose = False):
        """Create RC4 object with the storage elements allocated."""
        self.ip = 0
        self.id = 0
        self.jp = 0
        self.jd = 0
        self.kp = 0
        self.kd = 0
        self.keybyte = 0
        self.keystream = []
        self.S = [0] * 256
        self.verbose = verbose
        
        
    def load_key(self, key):
        """Init the cipher based on the supplied key. the
           method supports variable key lengths."""
        self.S = range(256)
        self.jp = 0

        if self.verbose:
            print "Initializing S"
            
        for self.ip in range(256):
            self.id = self.S[self.ip]
            self.keybyte = key[self.ip % len(key)]
            self.jp = (self.jp + self.id + self.keybyte) % 256
            self.jd = self.S[self.jp]

            if self.verbose:
                print "ip = %02x, id = %02x, keybyte = %02x, jp = %02x, jd = %02x" %\
                      (self.ip, self.id, self.keybyte, self.jp, self.jd)

            # Swap elements in S using a nice Python trick.
            self.S[self.ip], self.S[self.jp] = self.S[self.jp], self.S[self.ip]

        if self.verbose:
            print ""
            print "S after initialization:"
            print self.S
            print ""
            
        self.ip = 0
        self.jp = 0
        

    def generate_keystream(self, stream_length = 1):
        """Generate and return a list with stream_length keystream bytes."""
        self.keystream = []

        if self.verbose:
            print "Internal variables during keystream generation:"
            
        for i in range(stream_length):
            self.ip = (self.ip + 1) % 256
            self.id = self.S[self.ip]
            self.jp = (self.jp + self.id) % 256
            self.jd = self.S[self.jp]

            # Swap elements in S using a nice Python trick.
            self.S[self.ip], self.S[self.jp] = self.S[self.jp], self.S[self.ip]

            self.kp = (self.S[self.ip] + self.S[self.jp]) % 256
            self.kd = self.S[self.kp]

            if self.verbose:
                print "ip = %02x, id = %02x, jp = %02x, jd = %02x, kp = %02x, kd = %02x" %\
                      (self.ip, self.id, self.jp, self.jd, self.kp, self.kd)
            
            self.keystream.append(self.kd)

        return self.keystream


#-------------------------------------------------------------------
# print_key(key)
#
# Display the key.
#-------------------------------------------------------------------
def print_key(key):
    print ""
    print "Key: %s" % [hex(i) for i in key]


#-------------------------------------------------------------------
# print_keystream(key)
#
# Display the generated keystream.
#-------------------------------------------------------------------
def print_keystream(keystream):
    print ""
    print "Generated keystream: %s" % ([hex(i) for i in keystream])
    

#-------------------------------------------------------------------
# test_rc4()
#
# Create a RC4 object and test it using the RFC 6229 keys
# http://tools.ietf.org/html/rfc6229
#-------------------------------------------------------------------
def test_rc4():
    my_rc4 = RC4(False)

    testkeys = [[0x01, 0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
               [0x01, 0x02, 0x03, 0x04, 0x05], [0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]]
    
    # RFC 6229 keys1
    rfc6229_keys1 = [[0x01, 0x02, 0x03, 0x04, 0x05],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,\
                      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],\
                     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,\
                      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]]


    # RFC 6229 keys2
    rfc6229_keys2 = [[0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0x8b, 0x37, 0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0xc1, 0x09, 0x16, 0x39, 0x08, 0xeb, 0xe5, 0x1d, 0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37,\
                      0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a],\
                     [0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21, 0xc1, 0x09, 0x16, 0x39, 0x08, 0xeb, 0xe5, 0x1d,\
                      0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a]]


    # Run the RC4 cipher with the list of keys.
#    for my_key in rfc6229_keys1 + rfc6229_keys2:
    for my_key in testkeys:
        print_key(my_key)
        my_rc4.load_key(my_key)
        my_keystream = my_rc4.generate_keystream(8)
        print_keystream(my_keystream)
        print "-------------------------------------------------"

    
#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
    test_rc4()

    
#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF rc4.py
#=======================================================================

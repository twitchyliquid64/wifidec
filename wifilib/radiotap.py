

#
# radiotap.py
# A Radiotap parser for Python
# version 0.2
#
# (c) 2007 Scott Raynel <scottraynel@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#
# $Id$

import struct

# Radiotap "present" field bits
RTAP_TSFT = 0
RTAP_FLAGS = 1
RTAP_RATE = 2
RTAP_CHANNEL = 3
RTAP_FHSS = 4
RTAP_DBM_ANTSIGNAL = 5
RTAP_DBM_ANTNOISE = 6
RTAP_LOCK_QUALITY = 7
RTAP_TX_ATTENUATION = 8
RTAP_DB_TX_ATTENUATION = 9
RTAP_DBM_TX_POWER = 10
RTAP_ANTENNA = 11
RTAP_DB_ANTSIGNAL = 12
RTAP_DB_ANTNOISE = 13
RTAP_RX_FLAGS = 14
RTAP_TX_FLAGS = 15
RTAP_RTS_RETRIES = 16
RTAP_DATA_RETRIES = 17
RTAP_EXT = 31 # Denotes extended "present" fields.

_PREAMBLE_FORMAT = "<BxHI"
_PREAMBLE_SIZE = struct.calcsize(_PREAMBLE_FORMAT)

def get_length(buf):
        """ Returns the length of the Radiotap header.
        
            Use this to determine where the start of the next
            header in the packet is.
        """
        (v,l,p) = _unpack_preamble(buf)
        return l
        
def parse(buf):
        """ Parse a Radiotap header.

        This function parses a radiotap header, returning a dictionary that
        maps RTAP_* constants to the value contained in the radiotap header.
        @param buf A string containing the radiotap header
        @note The dictionary values will be returned in host byte order, even
              though the Radiotap standard encodes all fields in Little Endian
        """

        # All Radiotap fields are in little-endian byte-order.
        # We use our own alignment rules, hence '<'.
        format = "<"
        
        data = {} 
        
        fields = []
        
        (v,l,p) = _unpack_preamble(buf)

        # Skip extended bitmasks
        pp = p
        skip = 0
        while pp & 1 << RTAP_EXT:
                pp = buf[_PREAMBLE_SIZE + skip]
                skip += 1

        # Generate a format string to be passed to unpack
        # To do this, we look at each of the radiotap fields
        # we know about in order. We have to make sure that
        # we keep all fields aligned to the field's natural
        # boundary. E.g. 16 bit fields must be on a 16-bit boundary.

        if p & 1 << RTAP_TSFT:
                format += "Q"
                fields.append(RTAP_TSFT)
        if p & 1 << RTAP_FLAGS:
                format += "B"
                fields.append(RTAP_FLAGS)
        if p & 1 << RTAP_RATE:
                format += "B"
                fields.append(RTAP_RATE)
        if p & 1 << RTAP_CHANNEL:
                # Align to 16 bit boundary:
                format += _field_align(2, format)
                format += "I"
                fields.append(RTAP_CHANNEL)
        if p & 1 << RTAP_FHSS:
                format += "H"
                fields.append(RTAP_FHSS)
        if p & 1 << RTAP_DBM_ANTSIGNAL:
                format += "b"
                fields.append(RTAP_DBM_ANTSIGNAL)
        if p & 1 << RTAP_DBM_ANTNOISE:
                format += "b"
                fields.append(RTAP_DBM_ANTNOISE)
        if p & 1 << RTAP_LOCK_QUALITY:
                format += _field_align(2, format)
                format += "H"
                fields.append(RTAP_LOCK_QUALITY)
        if p & 1 << RTAP_TX_ATTENUATION:
                format += _field_align(2, format)
                format += "H"
                fields.append(RTAP_TX_ATTENUATION)
        if p & 1 << RTAP_DBM_TX_POWER:
                format += "b"
                fields.append(RTAP_DBM_TX_POWER)
        if p & 1 << RTAP_ANTENNA:
                format += "B"
                fields.append(RTAP_ANTENNA)
        if p & 1 << RTAP_DB_ANTSIGNAL:
                format += "B"
                fields.append(RTAP_DB_ANTSIGNAL)
        if p & 1 << RTAP_DB_ANTNOISE:
                format += "B"
                fields.append(RTAP_DB_ANTNOISE)
        if p & 1 << RTAP_RX_FLAGS:
                format += _field_align(2, format)
                format += "H"
                fields.append(RTAP_RX_FLAGS)
        if p & 1 << RTAP_TX_FLAGS:
                format += _field_align(2, format)
                format += "H"
                fields.append(RTAP_TX_FLAGS)
        if p & 1 << RTAP_RTS_RETRIES:
                format += "B"
                fields.append(RTAP_RTS_RETRIES)
        if p & 1 << RTAP_DATA_RETRIES:
                format += "B"
                fields.append(RTAP_DATA_RETRIES)

        end = _PREAMBLE_SIZE + skip + struct.calcsize(format)
        unpacked = struct.unpack(format, buf[_PREAMBLE_SIZE + skip:end])

        for i in range(len(unpacked)):
                data[fields[i]] = unpacked[i]
                
        return data

def _unpack_preamble(buf):
        if len(buf) < _PREAMBLE_SIZE:
                raise Exception("Truncated at Radiotap preamble.")
        (v,l,p) = struct.unpack(_PREAMBLE_FORMAT, buf[:_PREAMBLE_SIZE])
        if v != 0:
                raise Exception("Radiotap version not handled")
        return (v,l,p)


def _field_align(bytes, string):
        """ Returns a number of 'x' characters to ensure that
            the next character fits on a 'bytes' boundary.
        """
        n = struct.calcsize(string) % bytes
        if n == 0:
                return ""
        return 'x' * (bytes - n) 



#!/usr/bin/python
#    This file is part of LfLe.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.1
import logging
import struct

from mutablenamedtuple import mutablenamedtuple

from BinaryParser import Block
from BinaryParser import Nestable
from BinaryParser import read_byte
from BinaryParser import read_dword


LFLE_MAGIC = "LfLe"
MINRECORD = 0x30


class Cursor(Block, Nestable):
    def __init__(self, buf, offset):
        super(Cursor, self).__init__(buf, offset)
        self.declare_field("dword", "length", 0x0)
        self.declare_field("qword", "signature1")  # 0x11112222
        self.declare_field("qword", "signature2")  # 0x33334444
        self.declare_field("dword", "start_offset")
        self.declare_field("dword", "next_offset")
        self.declare_field("dword", "current_record_number")
        self.declare_field("dword", "oldest_record_number")

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x24

    def __len__(self):
        return 0x24


class Header(Block, Nestable):
    def __init__(self, buf, offset):
        super(Header, self).__init__(buf, offset)
        self.declare_field("dword", "length", 0x0)
        self.declare_field("string", "signature", length=4)  # LfLe
        self.declare_field("dword", "major_version")
        self.declare_field("dword", "minor_version")
        self.declare_field("dword", "start_offset")
        self.declare_field("dword", "end_offset")
        self.declare_field("dword", "current_record_number")
        self.declare_field("dword", "oldest_record_number")
        self.declare_field("dword", "max_size")
        self.declare_field("dword", "flags")
        self.declare_field("dword", "retention")
        self.declare_field("dword", "end_length")

    @staticmethod
    def structure_size(buf, offset, parent):
        return 0x2C

    def __len__(self):
        return 0x2C


class SID_IDENTIFIER_AUTHORITY(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SID_IDENTIFIER_AUTHORITY, self).__init__(buf, offset)
        self.declare_field("word_be", "high_part", 0x0)
        self.declare_field("dword_be", "low_part")

    @staticmethod
    def structure_size(buf, offset, parent):
        return 6

    def __len__(self):
        return SID_IDENTIFIER_AUTHORITY.structure_size(self._buf, self.absolute_offset(0x0), None)

    def __str__(self):
        return "%s" % (self.high_part() << 32 + self.low_part())


class SID(Block, Nestable):
    def __init__(self, buf, offset, parent):
        super(SID, self).__init__(buf, offset)
        self.declare_field("byte", "revision", 0x0)
        self.declare_field("byte", "sub_authority_count")
        self.declare_field(SID_IDENTIFIER_AUTHORITY, "identifier_authority")
        self.declare_field("dword", "sub_authorities", count=self.sub_authority_count())

    @staticmethod
    def structure_size(buf, offset, parent):
        sub_auth_count = read_byte(buf, offset + 1)
        auth_size = SID_IDENTIFIER_AUTHORITY.structure_size(buf, offset + 2, parent)
        return 2 + auth_size + (sub_auth_count * 4)

    def __len__(self):
        return self._off_sub_authorities + (self.sub_authority_count() * 4)

    def __str__(self):
        ret = "S-%d-%s" % (self.revision(), self.identifier_authority())
        for sub_auth in self.sub_authorities():
            ret += "-%s" % (str(sub_auth))
        return ret


class Record(Block, Nestable):
    def __init__(self, buf, offset):
        super(Record, self).__init__(buf, offset)
        self.declare_field("dword", "length", 0x0)
        self.declare_field("dword", "signature")  # LfLe
        self.declare_field("dword", "record_number")
        self.declare_field("unixtime", "time_generated")
        self.declare_field("unixtime", "time_written")
        self.declare_field("word", "event_id")
        self.declare_field("word", "event_type", offset=0x18)
        self.declare_field("word", "num_strings")
        self.declare_field("word", "event_category")
        self.declare_field("word", "reserved_flags")
        self.declare_field("dword", "closing_record_number")
        self.declare_field("dword", "strings_offset")
        self.declare_field("dword", "user_sid_length")
        self.declare_field("dword", "user_sid_offset")
        self.declare_field("dword", "data_length")
        self.declare_field("dword", "data_offset")
        if self.user_sid_length() > 0:
            self.declare_field(SID, "user_sid", self.user_sid_offset())
        if self.data_length() > 0:
            self.declare_field("binary", "data", offset=self.data_offset(), length=self.data_length())
        self.add_explicit_field(0x38, "str", "source")
        self.add_explicit_field(self.strings_offset(), "str", "strings")

    def strings(self):
        ret = []
        string_buf = self.unpack_binary(self.strings_offset(), self.length() - self.strings_offset())
        rest = string_buf
        for _ in xrange(self.num_strings()):
            part, _, rest = rest.partition("\x00\x00")
            if len(part) % 2 == 1 or (len(rest) > 0 and rest[0] == "\x00"):
                part += "\x00"
            ret.append(part.lstrip("\x00").decode("utf-16le"))
        return ret

    def source(self):
        source_buf = self.unpack_binary(0x38, self.length() - 0x38)
        part, _, rest = source_buf.partition("\x00\x00")
        if len(part) % 2 == 1 or (len(rest) > 0 and rest[0] == "\x00"):
            part += "\x00"
        return part.decode("utf-16le")

    @staticmethod
    def structure_size(buf, offset, parent):
        return read_dword(buf, offset)

    def __len__(self):
        return self.length()


EvtCarvingStatus = mutablenamedtuple("EvtCarvingStatus",
                                     ["valid",
                                      "too_big",
                                      "too_small",
                                      "bad_structure",
                                      "bad_content"])


class EvtCarver(object):
    def __init__(self, filelikeobject,
                 chunksize=4096 * 1000,
                 maxrecord=4096 * 16):
        self._f = filelikeobject
        self._chunksize = chunksize
        self._maxrecord = maxrecord
        if self._chunksize < self._maxrecord:
            raise RuntimeError("chunksize must be greater than maxrecord")
        self._status = EvtCarvingStatus(0, 0, 0, 0, 0)
        self._logger = logging.getLogger("EvtCarver")

    def carve(self):
        """
        generator of valid entry buffers
        """
        file_offset = 0

        while True:
            self._f.seek(file_offset)
            buf = self._f.read(self._chunksize)

            if len(buf) == 0:
                # here's the expected exit point
                return

            buf_offset = 0
            while True:
                index = buf.find(LFLE_MAGIC, buf_offset, self._chunksize + 4)
                if index == -1:
                    file_offset += len(buf)
                    break

                if index < 0x4:
                    # make sure we can extract the size by shifting
                    # our chunk backwards, if necessary
                    if file_offset >= 4:
                        self._logger.debug("%x: shifting file offset back for record",
                                       file_offset)
                        file_offset -= 4
                        break
                    else:
                        buf_offset = index + 1
                        coninue

                length = struct.unpack_from("<I", buf, index - 4)[0]

                if length <= MINRECORD:  # evt file header
                    self._logger.debug("%x: record too small", file_offset + index)
                    self._status.too_small += 1
                    buf_offset = index + 1
                    continue

                if length > self._maxrecord:
                    self._logger.debug("%x: record too big", file_offset + index)
                    self._status.too_big += 1
                    buf_offset = index + 1
                    continue

                if buf_offset + length > len(buf):
                    # if the record overlaps our buffer chunk
                    # reset the buffer chunk to start at the record start
                    #
                    # we know this must be enough space: MAXRECORD<BUFSIZE
                    file_offset += index - 4
                    self._logger.debug("%x: shifting file offset forward for record",
                                   file_offset)
                    break

                if buf.count(LFLE_MAGIC, index, index + length) != 1:
                    self._logger.debug("%x: record too much magic",
                                   file_offset + index)
                    self._status.bad_content += 1
                    buf_offset = index + 1
                    continue

                if buf[index - 4:index] != \
                   buf[index + length - 8:index + length - 4]:
                    self._logger.debug("%x: record bad magic",
                                   file_offset + index)
                    self._status.bad_structure += 1
                    buf_offset = index + 1
                    continue

                yield(buf[index - 4:index - 4 + length])
                self._status.valid += 1
                buf_offset += length
 
    def get_status(self):
        return self._status


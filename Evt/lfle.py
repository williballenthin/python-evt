#!/usr/bin/python
# By Willi Ballenthin
# <william.ballenthin@mandiant.com>
#
# Recover event log entries from an image
#   by heurisitically looking for record structures.
#
# Dependencies:
#   argparse (easy_install/pip)

import sys
import struct
import logging

import argparse

from mutablenamedtuple import mutablenamedtuple


g_logger = logging.getLogger("lfle")
LFLE_MAGIC = "LfLe"
BUFSIZE = 4096 * 1000
MAXRECORD = 4096 * 16
MINRECORD = 0x30


EvtCarvingStatus = mutablenamedtuple("EvtCarvingStatus",
                                     ["valid",
                                      "too_big",
                                      "too_small",
                                      "bad_structure",
                                      "bad_content"])

class EvtCarver(object):
    def __init__(self, filelikeobject):
        self._f = filelikeobject
        self._status = EvtCarvingStatus(0, 0, 0, 0, 0)
        self._logger = logging.getLogger("EvtCarver")

    def carve(self):
        """
        generator of valid records
        """
        file_offset = 0

        while True:
            self._f.seek(file_offset)
            buf = self._f.read(BUFSIZE)

            if len(buf) == 0:
                # here's the expected exit point
                return

            buf_offset = 0
            while True:
                index = buf.find(LFLE_MAGIC, buf_offset, BUFSIZE + 4)
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

                if length > MAXRECORD:
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


def write_evt_header(filelikeobject):
    # Evt header:
    #
    # 0000   30 00 00 00 4C 66 4C 65 01 00 00 00 01 00 00 00    0...LfLe........
    # 0010   30 00 00 00 30 00 00 00 01 00 00 00 00 00 00 00    0...0...........
    # 0020   00 00 01 00 00 00 00 00 80 51 01 00 30 00 00 00    .........Q..0...
    #
    # 0x0 (dword)length	0x30
    # 0x4 (string)signature	LfLe
    # 0x8 (dword)major_version	0x1
    # 0xc (dword)minor_version	0x1
    # 0x10 (dword)start_offset	0x30
    # 0x14 (dword)end_offset	0x30
    # 0x18 (dword)current_record_number	0x1
    # 0x1c (dword)oldest_record_number	0x0
    # 0x20 (dword)max_size	0x10000
    # 0x24 (dword)flags	0x0
    # 0x28 (dword)retention	0x15180
    # 0x2c (dword)end_length	0x30
    filelikeobject.write("0\x00\x00\x00LfLe\x01\x00\x00\x00\x01\x00\x00\x000\x00\x00\x000\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x80Q\x01\x000\x00\x00\x00")
    filelikeobject.flush()


def write_evt_cursor(filelikeobject):
    # EVT cursor:
    #
    # 0000   28 00 00 00 11 11 11 11 22 22 22 22 33 33 33 33    (.......""""3333
    # 0010   44 44 44 44 30 00 00 00 B8 5F 00 00 65 00 00 00    DDDD0...._..e...
    # 0020   01 00 00 00 28 00 00 00                            ....(...
    #
    # 0x0 (dword)length	0x28
    # 0x4 (qword)signature1	0x2222222211111111
    # 0xc (qword)signature2	0x4444444433333333
    # 0x14 (dword)start_offset	0x30
    # 0x18 (dword)next_offset	0x58
    # 0x1c (dword)current_record_number	0x1
    # 0x20 (dword)oldest_record_number	0x1
    filelikeobject.write("(\x00\x00\x00\x11\x11\x11\x11\"\"\"\"3333DDDD0\x00\x00\x00\x58\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00(\x00\x00\x00")
    filelikeobject.flush()
       

def do_carve(fin, fout):
    write_evt_header(fout)
    write_evt_cursor(fout)

    analyzer = EvtCarver(fin)

    for entry in analyzer.carve():
        fout.write(entry)

    s = analyzer.get_status()
    g_logger.info("Carved %d records", s.valid)

    g_logger.info("Skipped %d records with length greater than %s",
                  s.too_big, hex(MAXRECORD))
    g_logger.info("Skipped %d records with length less than %s",
                  s.too_small, hex(MINRECORD))
    g_logger.info("Skipped %d records with invalid structure",
                  s.bad_structure)
    g_logger.info("Skipped %d records with invalid content",
                  s.bad_content)
            

def main():
    parser = argparse.ArgumentParser(
        description='Recover event log entries from an image ' +
                    'by heurisitically looking for record structures.')
    parser.add_argument('input_path',
                        nargs="?",
                        default="STDIN",
                        help="Path to a raw (dd) image file.")
    parser.add_argument('output_path',
                        nargs="?",
                        default="STDOUT",
                        help="Path to write output file that contains " +
                        "recovered event log entries.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging logging")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    fin = None
    if args.input_path == "STDIN":
        import sys
        fin = sys.stdin
        g_logger.info("No input file provided, assuming STDIN")
    else:
        fin = open(args.input_path, "rb")

    fout = None
    if args.output_path == "STDOUT":
        import sys
        fout = sys.stdout
        g_logger.info("No output file provided, assuming STDOUT")
    else:
        fout = open(args.input_path, "rb")

    try:
        do_carve(fin, fout)
    finally:
        fin.close()
        fout.close()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3

# inject or convert shellcode to PE.
#
# Copyright (c) 2019, binary-ballistics
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#     * Neither the name of ext2 nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Requires pefile (pip install pefile)
# Based on the work at https://axcheron.github.io/code-injection-with-python/
# A better shellcode2exe!
#
# Usage:
# python3 inject2pe.py --help
# Convert shellcode to Portable Executable directly:
# python3 inject2pe.py s2e --help
# Inject shellcode into an existing Portable Executable:
# python3 inject2pe.py i2e --help
#


import pefile
import mmap
import os
import argparse
import binascii

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser(description='Inject code into new section')

subparsers = parser.add_subparsers(help='help for subcommand', dest="module")
i2e = subparsers.add_parser('inject2exe', aliases=['i2e'], help='i2e --help')
i2e.add_argument('--exe', dest='exe', metavar="<PATH>", required=True, action='store', help='PATH of exe file to be used for injection')
i2e.add_argument('--no-ep', dest='no_ep', required=False, action='store_true', help='Do not change entry point')

i2e.add_argument('--shellcode', metavar="<PATH>", dest='shellcode', required=True, action='store', help='PATH of shellcode file for injection')
i2e.add_argument('--offset', type=auto_int, dest='offset', required=False, default=0x0, action='store', help='hex offset value. Example: 0x727')
i2e.add_argument('--output', metavar="<PATH>", dest='output', required=True, action='store', help='PATH of output file')


s2e = subparsers.add_parser('shellcode2exe', aliases=['s2e'], help='s2e --help')
s2e.add_argument('--shellcode', metavar="<PATH>", dest='shellcode', required=True, action='store', help='PATH of shellcode file for injection')
s2e.add_argument('--offset', type=auto_int, dest='offset', required=False, default=0x0, action='store', help='hex offset value. Example: 0x727')
s2e.add_argument('--output', metavar="<PATH>", dest='output', required=True, action='store', help='PATH of output file')


def align(val_to_align, alignment):
    return int((val_to_align + alignment - 1) / alignment) * alignment


def resize(exe_path, shellcode):
    pe = pefile.PE(exe_path)
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    shellcode_size = len(shellcode)
    original_size = os.path.getsize(exe_path)
    print( "\t[+] Original Size = %d" % original_size )
    fd = open(exe_path, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)

    size_increment = align(shellcode_size, file_alignment) + 0x1000
    map.resize(original_size + size_increment)
    #DBG: map.resize(original_size + 0x50000)
    map.close()
    fd.close()


def resize_mem(exe_buffer, shellcode):
    pe = pefile.PE(data=exe_buffer)
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    shellcode_size = len(shellcode)

    size_increment = align(shellcode_size, file_alignment) + 0x1000
    print( "\t[+] Size Increment = %d bytes" % size_increment )
    exe_buffer += b'\x00' * size_increment
    return exe_buffer


def inject(pe, shellcode, offset, no_ep, output):
    shellcode_size = len(shellcode)
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    raw_size = align(shellcode_size, file_alignment)
    virtual_size = align(shellcode_size, section_alignment)

    number_of_section = pe.FILE_HEADER.NumberOfSections
    if number_of_section != 0:
        last_section = number_of_section - 1

        new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

        # Look for valid values for the new section header

        #DBG: raw_size = align(0x40000, file_alignment)
        #DBG: virtual_size = align(0x40000, section_alignment)
        raw_offset = align((pe.sections[last_section].PointerToRawData +
                            pe.sections[last_section].SizeOfRawData),
                           file_alignment)

        virtual_offset = align((pe.sections[last_section].VirtualAddress +
                                pe.sections[last_section].Misc_VirtualSize),
                               section_alignment)

    else:
        new_section_offset = pe.FILE_HEADER.SizeOfOptionalHeader + pe.OPTIONAL_HEADER.get_file_offset()
        virtual_offset = section_alignment
        raw_offset = file_alignment

    # CODE | EXECUTE | READ | WRITE
    characteristics = 0xE0000020
    # Section name must be equal to 8 bytes
    name = b".inj" + (4 * b'\x00')

    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name)
    print( "\t[+] Section Name = %s" % name )
    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    print( "\t[+] Virtual Size = %s" % hex(virtual_size) )
    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    print( "\t[+] Virtual Offset = %s" % hex(virtual_offset) )
    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    print( "\t[+] Raw Size = %s" % hex(raw_size) )
    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    print( "\t[+] Raw Offset = %s" % hex(raw_offset) )
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * b'\x00'))
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)
    print( "\t[+] Characteristics = %s\n" % hex(characteristics) )

    # STEP 0x03 - Modify the Main Headers
    print( "[*] STEP 0x03 - Modify the Main Headers" )
    pe.FILE_HEADER.NumberOfSections += 1
    print( "\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections )
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    print( "\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage )

    pe.write(output)

    if not no_ep:
        pe = pefile.PE(output)
        number_of_section = pe.FILE_HEADER.NumberOfSections
        last_section = number_of_section - 1
        new_ep = pe.sections[last_section].VirtualAddress + offset
        print( "\t[+] New Entry Point = %s" % hex(new_ep) )
        oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print( "\t[+] Original Entry Point = %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) )
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

    # STEP 0x04 - Inject the Shellcode in the New Section
    print( "[*] STEP 0x04 - Inject the Shellcode in the New Section" )

    raw_offset = pe.sections[last_section].PointerToRawData
    pe.set_bytes_at_offset(raw_offset, shellcode)
    print( "\t[+] Shellcode wrote in the new section" )

    pe.write(output)


def inject_file(exe_path, shellcode, offset, no_ep, output):
    # STEP 0x01 - Resize the Executable
    # Note: I added some more space to avoid error
    print( "[*] STEP 0x01 - Resize the Executable" )
    resize(exe_path, shellcode)
    print( "\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path) )

    # STEP 0x02 - Add the New Section Header
    print( "[*] STEP 0x02 - Add the New Section Header" )
    pe = pefile.PE(exe_path)

    inject(pe, shellcode, offset, no_ep, output)

def shellcode2exe(shellcode, offset, output):
    print( "[*] STEP 0x01 - Prepare the Executable" )
    # Dummy PE is modified version of:
    # https://github.com/ecx86/tinyPE/blob/master/smallest-pe-with-sections.exe.hex
    dummy_pe = "4d5a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000504500004c010000000000000000000000000000e00003010b010e00000200000000000000000000000000000000000000000000000040000010000000020000050001000000000005000100000000000020000000020000000000000200000400001000001000000000100000100000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    x = binascii.unhexlify(dummy_pe)

    x = resize_mem(x, shellcode)
    print( "\t[+] New Size = %d bytes\n" % len(x) )

    # STEP 0x02 - Add the New Section Header
    print( "[*] STEP 0x02 - Add the New Section Header" )
    pe = pefile.PE(data=x)

    inject(pe, shellcode, offset, False, output)


def read_shellcode_file(shellcode_path):
    with open(shellcode_path, "rb") as f:
        shellcode = f.read()
    return shellcode


def main():
    args = parser.parse_args()
    shellcode = read_shellcode_file(args.shellcode)
    if args.module in ['shellcode2exe', 's2e']:
        shellcode2exe(shellcode, args.offset, args.output)
    else:
        inject_file(args.exe, shellcode, args.offset, args.no_ep, args.output)


if __name__ == '__main__':
    main()


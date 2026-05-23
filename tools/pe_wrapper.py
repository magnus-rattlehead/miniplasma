#!/usr/bin/env python3
"""Create a minimal PE32+ wrapper around raw shellcode."""
import sys

def make_tiny_pe(shellcode_path, output_path):
    with open(shellcode_path, 'rb') as f:
        code = f.read()

    code_size = len(code)
    sect_align = 0x200
    file_align = 0x200
    image_base = 0x0000000140000000

    # Section table starts at this offset
    sect_offset = 0x108
    # Raw data starts after section table
    raw_offset = sect_offset + 40  # one section header
    # Round up to file alignment
    raw_offset = ((raw_offset + file_align - 1) // file_align) * file_align
    # Virtual size (round up to section alignment)
    virtual_size = ((code_size + sect_align - 1) // sect_align) * sect_align
    # Size of headers
    size_of_headers = raw_offset

    size_of_image = size_of_headers + virtual_size

    pe = bytearray()
    # DOS header (standard 64 bytes, e_lfanew at 0x3C)
    pe += b'MZ' + b'\x00' * 58 + b'\x08\x01\x00\x00'  # e_lfanew = 0x108

    # PE signature
    pe += b'PE\x00\x00'

    # COFF header (20 bytes)
    pe += b'\x64\x86'           # Machine: IMAGE_FILE_MACHINE_AMD64
    pe += b'\x01\x00'            # NumberOfSections: 1
    pe += b'\x00\x00\x00\x00'   # TimeDateStamp
    pe += b'\x00\x00\x00\x00'   # PointerToSymbolTable
    pe += b'\x00\x00\x00\x00'   # NumberOfSymbols
    pe += b'\xf0\x00'            # SizeOfOptionalHeader
    pe += b'\x02\x02'            # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    # Optional header PE32+ (240 bytes, but we use 0xF0 = 240)
    pe += b'\x0b\x02'            # Magic: PE32+
    pe += b'\x0e\x00'            # MajorLinkerVersion
    pe += b'\x00\x00'            # MinorLinkerVersion (padding)
    pe += b'\x00\x00\x00\x00'   # SizeOfCode (set below)
    pe += b'\x00\x00\x00\x00'   # SizeOfInitializedData
    pe += b'\x00\x00\x00\x00'   # SizeOfUninitializedData
    pe += b'\x00\x10\x00\x00'   # AddressOfEntryPoint (RVA = 0x1000)
    pe += b'\x00\x10\x00\x00'   # BaseOfCode (RVA)
    # PE32+ specific
    pe += image_base.to_bytes(8, 'little')  # ImageBase
    pe += sect_align.to_bytes(4, 'little')  # SectionAlignment
    pe += file_align.to_bytes(4, 'little')  # FileAlignment
    pe += b'\x04\x00\x00\x00'   # MajorOperatingSystemVersion
    pe += b'\x00\x00\x00\x00'   # MinorOperatingSystemVersion
    pe += b'\x06\x00\x00\x00'   # MajorImageVersion
    pe += b'\x00\x00\x00\x00'   # MinorImageVersion
    pe += b'\x06\x00\x00\x00'   # MajorSubsystemVersion
    pe += b'\x00\x00\x00\x00'   # MinorSubsystemVersion
    pe += b'\x00\x00\x00\x00'   # Win32VersionValue
    pe += size_of_image.to_bytes(4, 'little')  # SizeOfImage
    pe += size_of_headers.to_bytes(4, 'little')  # SizeOfHeaders
    pe += b'\x00\x00\x00\x00'   # CheckSum
    pe += b'\x03\x00'            # Subsystem: CONSOLE
    pe += b'\x00\x00'            # DllCharacteristics (padding)
    pe += b'\x00\x00\x01\x00\x00\x00\x00\x00'  # SizeOfStackReserve
    pe += b'\x00\x00\x01\x00\x00\x00\x00\x00'  # SizeOfStackCommit
    pe += b'\x00\x00\x01\x00\x00\x00\x00\x00'  # SizeOfHeapReserve
    pe += b'\x00\x00\x01\x00\x00\x00\x00\x00'  # SizeOfHeapCommit
    pe += b'\x00\x00\x00\x00'   # LoaderFlags
    pe += b'\x10\x00\x00\x00'   # NumberOfRvaAndSizes (16)

    # Data directories (16 entries, 8 bytes each = 128 bytes)
    for _ in range(16):
        pe += b'\x00\x00\x00\x00\x00\x00\x00\x00'

    # Section header .text (40 bytes)
    pe += b'.text\x00\x00\x00'  # Name
    pe += virtual_size.to_bytes(4, 'little')  # VirtualSize
    pe += b'\x00\x10\x00\x00'   # VirtualAddress (0x1000)
    pe += code_size.to_bytes(4, 'little')     # SizeOfRawData
    pe += raw_offset.to_bytes(4, 'little')    # PointerToRawData
    pe += b'\x00\x00\x00\x00'   # PointerToRelocations
    pe += b'\x00\x00\x00\x00'   # PointerToLineNumbers
    pe += b'\x00\x00\x00\x00'   # NumberOfRelocations
    pe += b'\x00\x00\x00\x00'   # NumberOfLinenumbers
    pe += b'\x60\x00\x00\x40'   # Characteristics: CODE | EXECUTE | READ

    # Pad to raw_offset
    pe += b'\x00' * (raw_offset - len(pe))

    # Shellcode data
    pe += code

    # Write output
    with open(output_path, 'wb') as f:
        f.write(pe)

    print(f"Created {output_path}: {len(pe)} bytes ({code_size} bytes shellcode)")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> <output.exe>")
        sys.exit(1)
    make_tiny_pe(sys.argv[1], sys.argv[2])

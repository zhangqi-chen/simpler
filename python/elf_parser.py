"""
Object File Parser for AICore Kernel Binaries

Pure Python implementation for extracting .text section from ELF64 or Mach-O .o files.
Based on the C++ implementation in binary_loader.cpp.

For Mach-O ARM64, this module also applies relocations to BL instructions so that
the extracted .text section can be executed standalone without linking.
"""

import struct
from pathlib import Path
from typing import Union, Dict, List, Tuple, Optional


# ELF Magic Numbers
ELFMAG0 = 0x7F
ELFMAG1 = ord('E')
ELFMAG2 = ord('L')
ELFMAG3 = ord('F')

# Mach-O Magic Numbers
MH_MAGIC_64 = 0xFEEDFACF

# Mach-O Load Command types
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02

# Mach-O ARM64 relocation types
ARM64_RELOC_BRANCH26 = 2


def extract_text_section(obj_input: Union[str, Path, bytes]) -> bytes:
    """
    Extract .text section from an ELF64 or Mach-O .o file.

    Args:
        obj_input: Either a path to the .o file (str/Path) or the binary data (bytes)

    Returns:
        Binary data of the .text section

    Raises:
        FileNotFoundError: If file path is provided and does not exist
        ValueError: If data is not a valid object file or .text section not found
    """
    # Handle input: either path or bytes
    if isinstance(obj_input, bytes):
        obj_data = obj_input
        source_name = "<bytes>"
    else:
        path = Path(obj_input)
        if not path.exists():
            raise FileNotFoundError(f"Object file not found: {obj_input}")
        with open(obj_input, 'rb') as f:
            obj_data = f.read()
        source_name = str(obj_input)

    if len(obj_data) < 4:
        raise ValueError(f"Data too small to be a valid object file: {source_name}")

    # Detect format by magic number
    magic32 = struct.unpack('<I', obj_data[:4])[0]
    if magic32 == MH_MAGIC_64:
        return _extract_text_macho64(obj_data, source_name)

    if (obj_data[0] == ELFMAG0 and obj_data[1] == ELFMAG1 and
        obj_data[2] == ELFMAG2 and obj_data[3] == ELFMAG3):
        return _extract_text_elf64(obj_data, source_name)

    raise ValueError(f"Not a valid ELF or Mach-O file: {source_name}")


def _extract_text_elf64(elf_data: bytes, source_name: str) -> bytes:
    """Extract .text section from ELF64 data."""
    if len(elf_data) < 64:
        raise ValueError(f"Data too small to be a valid ELF: {source_name}")

    # Extract section header table info from ELF header
    e_shoff = struct.unpack('<Q', elf_data[40:48])[0]
    e_shnum = struct.unpack('<H', elf_data[60:62])[0]
    e_shstrndx = struct.unpack('<H', elf_data[62:64])[0]

    # Get string table section header
    shstr_offset = e_shoff + e_shstrndx * 64
    shstr_sh_offset = struct.unpack('<Q', elf_data[shstr_offset+24:shstr_offset+32])[0]
    shstr_sh_size = struct.unpack('<Q', elf_data[shstr_offset+32:shstr_offset+40])[0]

    # Extract string table
    strtab = elf_data[shstr_sh_offset:shstr_sh_offset+shstr_sh_size]

    # Find .text section
    for i in range(e_shnum):
        section_offset = e_shoff + i * 64
        sh_name = struct.unpack('<I', elf_data[section_offset:section_offset+4])[0]
        sh_offset = struct.unpack('<Q', elf_data[section_offset+24:section_offset+32])[0]
        sh_size = struct.unpack('<Q', elf_data[section_offset+32:section_offset+40])[0]

        section_name = _extract_cstring(strtab, sh_name)
        if section_name == '.text':
            text_data = elf_data[sh_offset:sh_offset+sh_size]
            print(f"Loaded .text section from {source_name} (size: {sh_size} bytes)")
            return text_data

    raise ValueError(f".text section not found in: {source_name}")


def _extract_text_macho64(data: bytes, source_name: str) -> bytes:
    """
    Extract __text section from Mach-O 64-bit data.

    For ARM64, also applies BR26 relocations to fix BL instruction offsets.
    """
    if len(data) < 32:
        raise ValueError(f"Data too small to be a valid Mach-O: {source_name}")

    ncmds = struct.unpack('<I', data[16:20])[0]

    # First pass: collect symbol table info and find __text section
    symtab_info = None  # (symoff, nsyms, stroff, strsize)
    text_section_info = None  # (s_addr, s_size, s_offset, reloff, nreloc)

    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd = struct.unpack('<I', data[offset:offset+4])[0]
        cmdsize = struct.unpack('<I', data[offset+4:offset+8])[0]

        if cmd == LC_SYMTAB:
            # symtab_command: cmd(4) + cmdsize(4) + symoff(4) + nsyms(4) + stroff(4) + strsize(4)
            symoff = struct.unpack('<I', data[offset+8:offset+12])[0]
            nsyms = struct.unpack('<I', data[offset+12:offset+16])[0]
            stroff = struct.unpack('<I', data[offset+16:offset+20])[0]
            strsize = struct.unpack('<I', data[offset+20:offset+24])[0]
            symtab_info = (symoff, nsyms, stroff, strsize)

        elif cmd == LC_SEGMENT_64:
            nsects = struct.unpack('<I', data[offset+64:offset+68])[0]
            sect_base = offset + 72

            for s in range(nsects):
                sect_off = sect_base + s * 80
                sectname = data[sect_off:sect_off+16].split(b'\x00')[0].decode('ascii')

                if sectname == '__text':
                    s_addr = struct.unpack('<Q', data[sect_off+32:sect_off+40])[0]
                    s_size = struct.unpack('<Q', data[sect_off+40:sect_off+48])[0]
                    s_offset = struct.unpack('<I', data[sect_off+48:sect_off+52])[0]
                    reloff = struct.unpack('<I', data[sect_off+56:sect_off+60])[0]
                    nreloc = struct.unpack('<I', data[sect_off+60:sect_off+64])[0]
                    text_section_info = (s_addr, s_size, s_offset, reloff, nreloc)

        offset += cmdsize

    if text_section_info is None:
        raise ValueError(f"__text section not found in: {source_name}")

    s_addr, s_size, s_offset, reloff, nreloc = text_section_info

    # Extract text data as mutable bytearray
    text_data = bytearray(data[s_offset:s_offset+s_size])

    # If no relocations or no symbol table, return as-is
    if nreloc == 0 or symtab_info is None:
        print(f"Loaded __text section from {source_name} (size: {s_size} bytes, no relocations)")
        return bytes(text_data)

    # Parse symbol table to get symbol addresses
    symoff, nsyms, stroff, strsize = symtab_info
    symbol_addresses = _parse_macho_symbols(data, symoff, nsyms, stroff)

    # Apply relocations
    reloc_count = _apply_macho_relocations(
        text_data, data, reloff, nreloc, s_addr, symbol_addresses
    )

    print(f"Loaded __text section from {source_name} (size: {s_size} bytes, applied {reloc_count} relocations)")
    return bytes(text_data)


def _parse_macho_symbols(data: bytes, symoff: int, nsyms: int, stroff: int) -> Dict[int, int]:
    """
    Parse Mach-O symbol table and return a dict of symbol_index -> address.

    nlist_64 structure (16 bytes):
        n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8)
    """
    symbol_addresses = {}

    for i in range(nsyms):
        sym_offset = symoff + i * 16
        if sym_offset + 16 > len(data):
            break

        # n_value is at offset 8 within nlist_64
        n_value = struct.unpack('<Q', data[sym_offset+8:sym_offset+16])[0]
        symbol_addresses[i] = n_value

    return symbol_addresses


def _apply_macho_relocations(
    text_data: bytearray,
    obj_data: bytes,
    reloff: int,
    nreloc: int,
    text_addr: int,
    symbol_addresses: Dict[int, int]
) -> int:
    """
    Apply Mach-O relocations to text section.

    Relocation entry (8 bytes):
        r_address(4) + r_info(4)

    r_info bits:
        [23:0]  = r_symbolnum (symbol index or section ordinal)
        [24]    = r_pcrel (1 = PC-relative)
        [26:25] = r_length (0=byte, 1=word, 2=long, 3=quad)
        [27]    = r_extern (1 = external symbol)
        [31:28] = r_type

    Returns:
        Number of relocations applied
    """
    applied = 0

    for i in range(nreloc):
        rel_offset = reloff + i * 8
        if rel_offset + 8 > len(obj_data):
            break

        r_address = struct.unpack('<I', obj_data[rel_offset:rel_offset+4])[0]
        r_info = struct.unpack('<I', obj_data[rel_offset+4:rel_offset+8])[0]

        # Extract fields from r_info
        r_symbolnum = r_info & 0x00FFFFFF
        r_pcrel = (r_info >> 24) & 0x1
        r_length = (r_info >> 25) & 0x3
        r_extern = (r_info >> 27) & 0x1
        r_type = (r_info >> 28) & 0xF

        # Only handle ARM64_RELOC_BRANCH26 (type 2)
        if r_type != ARM64_RELOC_BRANCH26:
            continue

        # Must be PC-relative and extern
        if not r_pcrel or not r_extern:
            continue

        # Get target symbol address
        if r_symbolnum not in symbol_addresses:
            print(f"  Warning: symbol {r_symbolnum} not found for relocation at 0x{r_address:x}")
            continue

        target_addr = symbol_addresses[r_symbolnum]

        # Calculate PC-relative offset
        # BL instruction is at text_addr + r_address
        # Offset = (target_addr - (text_addr + r_address)) / 4
        pc = text_addr + r_address
        offset = (target_addr - pc) // 4

        # Check if offset fits in 26-bit signed immediate
        if offset < -(1 << 25) or offset >= (1 << 25):
            print(f"  Warning: branch offset {offset} out of range at 0x{r_address:x}")
            continue

        # Apply relocation: modify BL instruction's imm26 field
        if r_address + 4 > len(text_data):
            continue

        # Read current instruction
        instr = struct.unpack('<I', text_data[r_address:r_address+4])[0]

        # Verify it's a BL instruction (opcode 100101 in bits [31:26])
        if (instr >> 26) != 0x25:
            print(f"  Warning: instruction at 0x{r_address:x} is not BL (got 0x{instr:08x})")
            continue

        # Encode offset as 26-bit signed value and combine with opcode
        imm26 = offset & 0x03FFFFFF
        new_instr = (0x25 << 26) | imm26

        # Write back
        text_data[r_address:r_address+4] = struct.pack('<I', new_instr)
        applied += 1

    return applied


def _extract_cstring(data: bytes, offset: int) -> str:
    """
    Extract a null-terminated C string from bytes.

    Args:
        data: Byte data
        offset: Starting offset

    Returns:
        Decoded string
    """
    end = data.find(b'\x00', offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode('ascii', errors='ignore')

#!/usr/bin/env python3
# pack_nes_with_shellcode.py
# Build an iNES ROM that prints "6" on NES, and append x86 shellcode (raw) to the ROM
# Usage: python3 pack_nes_with_shellcode.py out.nes

from pathlib import Path
import sys

# --- PRG (6502) binary (we include a tiny PRG that writes tile 0 at nametable and enables background)
# This PRG is 16KB sized after padding. The reset vector points to $8000.
# The following bytes were assembled from earlier NESASM-like code; they are minimal and safe for demo.
# For clarity we use a pre-built PRG image (fill with zeros then place machine code).
# NOTE: On real projects you'd assemble with an assembler, but for PoC we include bytes.

# Minimal PRG at $8000 (assembled opcodes) - will be padded to 16KB
# This PRG does:
#  SEI, CLD, LDX #$40, STX $4017, LDX #$00, TXS,
#  Clear PPU, set PPUADDR $2006, write tile index 0 to $2007, set palette, enable background, infinite loop.
prg_code = bytes([
    0x78,       # SEI
    0xD8,       # CLD
    0xA2, 0x40, # LDX #$40
    0x8E, 0x17, 0x40, # STX $4017
    0xA2, 0x00, # LDX #$00
    0x9A,       # TXS
    0xA9, 0x00, # LDA #$00
    0x8D, 0x00, 0x20, # STA $2000
    0x8D, 0x01, 0x20, # STA $2001
    # set PPUADDR to $2000
    0xA9, 0x20, # LDA #$20
    0x8D, 0x06, 0x20, # STA $2006
    0xA9, 0x00, # LDA #$00
    0x8D, 0x06, 0x20, # STA $2006
    # write tile index 0
    0xA9, 0x00, # LDA #$00
    0x8D, 0x07, 0x20, # STA $2007
    # set palette at $3F00
    0xA9, 0x3F, # LDA #$3F
    0x8D, 0x06, 0x20, # STA $2006
    0xA9, 0x00, # LDA #$00
    0x8D, 0x06, 0x20, # STA $2006
    0xA9, 0x0F, # LDA #$0F
    0x8D, 0x07, 0x20, # STA $2007
    0xA9, 0x01, 0x8D, 0x07, 0x20,  # STA palette repeating (quick)
    0xA9, 0x01, 0x8D, 0x07, 0x20,
    # enable background
    0xA9, 0x08, 0x8D, 0x01, 0x20,
    # infinite loop
    0x4C, 0x2A, 0x80  # JMP $802A  (address within PRG; will be adjusted by vector below)
])

# Put Reset vector at end of PRG (little endian) pointing to $8000
# We'll pad prg_data to 16KB then set vectors at 0x3FFC..0x3FFF
PRG_SIZE = 16 * 1024
prg = bytearray(prg_code)
if len(prg) > PRG_SIZE - 6:
    print("PRG code too large!", file=sys.stderr)
    sys.exit(1)
# pad to PRG_SIZE
prg = prg.ljust(PRG_SIZE, b'\x00')
# Reset vector at last 4 bytes: 0xFFFC=low, 0xFFFD=high
reset_addr = 0x8000
prg[-6:] = b'\x00\x00\x00\x00\x00\x00'  # ensure clear (just for consistency)
prg[-4] = reset_addr & 0xFF
prg[-3] = (reset_addr >> 8) & 0xFF
prg[-2] = 0x00
prg[-1] = 0x00

# --- CHR (tile data) --- (8 KB)
# Provide one tile for "6", plane0 + plane1 (we use plane1 zeros here)
# bytes: 00 3C 62 60 7C 62 62 3C  00 00 00 00 00 00 00 00
chr_tile = bytes([0x00,0x3C,0x62,0x60,0x7C,0x62,0x62,0x3C,
                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
CHR_SIZE = 8*1024
chr_data = chr_tile + bytes(CHR_SIZE - len(chr_tile))

# --- x86 shellcode to append (raw) ---
# Using the shellcode you provided (write "6\n", exit(6))
x86_shell = bytes.fromhex(
    "66 68 36 0a 31 c0 b0 04 31 db b3 01 89 e1 31 d2 b2 02 cd 80"
    "31 c0 b0 01 31 db b3 06 cd 80"
)

# --- Build iNES header ---
header = bytearray(b"NES\x1A")
header += bytes([1,1])  # 1 PRG bank, 1 CHR bank
header += bytes([0])    # flags 6 low
header += bytes([0,0,0,0,0])  # zeros to reach 16 bytes
# pad header to 16 bytes
header = header.ljust(16, b'\x00')

# final file: header + prg + chr + appended shellcode
out = header + bytes(prg) + bytes(chr_data) + x86_shell

outfile = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("poly_nes_shell.nes")
outfile.write_bytes(out)
print("Wrote", outfile, "size=", len(out))
print("PRG size:", len(prg), "CHR size:", len(chr_data), "shell len:", len(x86_shell))
print("To test NES: open", outfile, "in FCEUX or Mesen.")
print("To extract x86 shellcode: dd if=%s bs=1 skip=%d of=shell.bin" % (outfile, 16 + len(prg) + len(chr_data)))

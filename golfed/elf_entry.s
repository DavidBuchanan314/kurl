/*

This file defines a 112-byte aarch64 static ELF header, loadble by Linux.
It features overlapping ehdr and phdr, but the overlap isn't very aggressive
(only 8 overlapping bytes). The remaining "holes" in the headers are used to
write a minimal _start function, which extracts argc and argv from AUXV, calls
main, and then cleanly exits with whatever main() returned.

All the code in this file gets stored in the .init segment. Normally this would
be occupied by libc init stuff (crt), but the expectation here is that you're
compiling in freestanding mode without a libc.

Since .init gets linked ahead of .text (etc.), we mostly-guarantee it'll come
before everything else we care about. Rather than mess around with custom linker
scripts to emit a flat binary, the intention is to compile to a regular ELF,
then slice our custom golfed ELF out of the "container" ELF file.

As a bonus, the outer ELF retains the original un-mangled headers and symbols,
making it convenient to debug and analyse.

NOTE: p_filesz and p_memsz calculations are hacky. __bss_start__
and __bss_end__ may have different names depending on whatever linker script you use

References: https://tmpout.sh/2/11.html (We use the "0x38 Overlay")

*/


// there's nothing else in the init section, so this ensures we go first, without needing a custom linker script
.section .init

.globl _start
.extern main

// align to the next 64k boundary (16k would be enough on my system, but 64k should offer maximum compat)
.p2align 16

// elf64_ehdr
elf_base:
.ascii "\x7f" "ELF" // e_ident

_start:
ldr        w0,[sp]
add        x1, sp, #0x08
b          nearly_call_main

.hword 2    // e_type
.hword 0xb7 // e_machine
.word 1     // e_version

.dword _start // e_entry
.dword phdr_start-elf_base     // e_phoff (offset from elf base)

// e_shoff, e_flags:
call_main:
bl         main
mov        x8,#0x5d
svc        0x0      // sys__exit

.hword 64    // e_ehsize (doesn't actually matter)
.hword 0x38  // e_phentsize

// elf64_phdr
phdr_start:
.word 1         // e_phnum, p_type (PT_LOAD)
.word 7         // p_flags (RWX)
.dword 0        // p_offset
.dword elf_base // p_vaddr

// p_paddr:
nearly_call_main:
sub        sp, sp, #0x10
b          call_main

.dword __bss_start__-elf_base   // p_filesz
.dword __bss_end__-elf_base      // p_memsz
.dword 0x10000                  // p_align (we really are aligned to this)




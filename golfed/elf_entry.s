// there's nothing else in the init section, so this ensures we go first, without a linker script
.section .init

//.globl _start
.extern _start
.extern main

// align to the next 64k boundary (16k would be enough on my system, but 64k should offer maximum compat)
.p2align 16

// elf64_ehdr
elf_base:
.ascii "\x7f" "ELF" // e_ident
.byte 0x02 // ei_class
.byte 0x01 // ei_data
.byte 0x01 // ei_version
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0 // ident padding

.hword 2    // e_type
.hword 0xb7 // e_machine
.word 1     // e_version

.dword _start // e_entry
.dword 64     // e_phoff (offset from elf base)
.dword 0      // e_shoff (don't care)

.word 0      // e_flags
.hword 64    // e_ehsize (doesn't actually matter)
.hword 0x38  // e_phentsize
.hword 1     // e_phnum

.hword 0
.hword 0
.hword 0

// elf64_phdr
.word 1         // p_type (PT_LOAD)
.word 7         // p_flags (RWX)
.dword 0        // p_offset
.dword elf_base // p_vaddr
.dword elf_base // p_paddr
.dword 0x1000   // p_filesz (overkill since we don't know the real value)
.dword 0x100000 // p_memsz  (likewise)
.dword 0x10000  // p_align (we really are aligned to this)

_start: // NOTE: not yet optimised, straight out of gcc!
stp        x29,x30,[sp, #-0x10]!
mov        x29,sp
add        x1,x29,#0x18
ldr        w0,[x29, #0x10]
bl         main
sxtw       x0,w0
mov        x8,#0x5d
svc        0x0      // sys__exit

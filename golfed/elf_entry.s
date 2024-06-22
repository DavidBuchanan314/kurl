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

.dword 0x1000   // p_filesz (overkill since we don't know the real value)
.dword 0x100000 // p_memsz  (likewise)
.dword 0x10000  // p_align (we really are aligned to this)



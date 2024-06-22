all: kurl

CFLAGS := -s -Os -ffreestanding -nostdlib -static -Wl,--omagic -fcf-protection=none -Wl,--build-id=none -fomit-frame-pointer -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -fomit-frame-pointer

kurl: kurl.c
	#gcc -c libc.c -o libc.o  $(CFLAGS) -fno-lto
	#gcc -c elf_entry.s -o elf_entry.o
	gcc elf_entry.s kurl.c -o kurl $(CFLAGS) -flto
	python3 elf_mangler.py kurl kurl
	#hexdump -vC kurl
	wc -c kurl

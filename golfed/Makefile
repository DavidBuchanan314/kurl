all: kurl

CFLAGS := -flto -g -Os -ffreestanding -nostdlib -static -Wl,--omagic -fcf-protection=none -Wl,--build-id=none -fomit-frame-pointer -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -fomit-frame-pointer

kurl: elf_entry.s kurl.c linux_syscall_support.h
	#gcc -c libc.c -o libc.o  $(CFLAGS) -fno-lto
	#gcc -c elf_entry.s -o elf_entry.o
	gcc elf_entry.s kurl.c -o kurl_dbg $(CFLAGS)
	python3 elf_mangler.py kurl_dbg kurl
	#hexdump -vC kurl
	wc -c kurl

sha256_test: sha256_test.c linux_syscall_support.h
	gcc elf_entry.s sha256_test.c -o sha256_test_dbg $(CFLAGS) -march=armv8-a+crc+crypto
	python3 elf_mangler.py sha256_test_dbg sha256_test
	wc -c sha256_test

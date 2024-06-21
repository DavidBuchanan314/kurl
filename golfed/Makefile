all: kurl

CFLAGS := -s -Os -ffreestanding -nostdlib -static -Wl,--omagic -fcf-protection=none -Wl,--build-id=none -fomit-frame-pointer -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector

kurl: kurl.c
	#gcc -c libc.c -o libc.o  $(CFLAGS) -fno-lto
	gcc kurl.c -o kurl $(CFLAGS) -flto -T linker.lds
	python3 elf_mangler.py kurl kurl
	#hexdump -vC kurl
	wc -c kurl

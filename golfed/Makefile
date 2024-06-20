all: kurl

kurl: kurl.c
	gcc kurl.c -o kurl -ffreestanding -nostdlib -static -Os -N -s -fcf-protection=none -Wl,--build-id=none -fomit-frame-pointer -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
	#hexdump -vC kurl
	wc -c kurl

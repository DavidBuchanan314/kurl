# kurl

This is repo hosts my WIP entry to [BGGP5](https://binary.golf/5/). This README acts as a dev log of sorts (It's a bit of an un-edited stream of consciousness right now, I'll do a proper writeup later. hopefully).

The main goal of BGGP5 is to download the file at [https://binary.golf/5/5](https://binary.golf/5/5) and display its contents, using less than 4KB of code (stored in whatever format you like).

*My* goal is to create the smallest possible HTTPS client as a static Linux ELF binary. I don't yet know if that's possible, within the 4KB constraint! I'll definitely have to cut corners to make it work, especially in the security department.

Tiny disclaimer: As part of the BGGP staff team I knew about the theme in advance, and I absolutely could not resist getting started a few days early. This entry is more about being cool than being competitive, so I hope you can forgive me!

## The Plan

"HTTPS", for my purposes, means HTTP 1.1 over TLS 1.3 (over TCP, over IP, over...)

The HTTP part is easy, it's a super simple protocol. At least, the part for requesting a document is simple:

```sh
echo -en $'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
 | nc example.com 80
```

But to make it HTTP**S**, we need to add TLS (Transport Layer Security) between the HTTP layer and the TCP layer. Any sane person would want to use a library that implements TLS, like OpenSSL. Or indeed a library that implements HTTPS as a whole, like libcurl.

While libcurl and OpenSSL are both way larger than 4KB, with the wonders of Dynamic Linking you don't need to directly include them in your program. But that would introduce a dependency, and I don't like those. I want a strong independent program! To make things both interesting and feasible, I set myself the following constraint:

> I want a self-contained program with no user-space dependencies.

No *user-space* dependencies means no external libraries, but it does mean we can lean on Linux kernel APIs to help us out. We're already depending on the kernel to load our program and do I/O, so there's no reason not to use it for more. But what more does it have to offer?

[Kernel TLS](https://www.kernel.org/doc/html/latest/networking/tls.html) and the [Kernel crypto interface](https://www.kernel.org/doc/html/latest/crypto/userspace-if.html)!

These APIs *should* offer everything we need to implement HTTPS "from scratch".

In case it wasn't already obvious, the code I write here isn't going to be "secure" by any stretch of the imagination. My goal is simply to retrieve a URL, I don't care about confidentiality or integrity, and I will cut as many corners as I can. I'm only using HTTPS because it's 2024 and nobody serves HTTP anymore.

## Initial Prototyping

I'd never used the ktls or kernel crypto APIs before, and they're not terribly well documented. Rather than diving in with a code-golfed C implementation, I started off with a "simple" proof-of-concept in Python, which you can see in `python_prototype/`. The goal here was to understand the APIs, figure out the main "business logic" requirements, and provide test/reference values for the inevitable debugging of the final version of the program.

### Kernel TLS

Kernel TLS is a very promising idea, on the surface it sounds like it solves all our problems at once. But, there's a sizeable caveat. To oversimplify, TLS has two phases: the handshake (which negotiates parameters and uses asymmetric crypto to establish symmetric session keys), and then the rest of the session that transports the encrypted application-layer traffic. The kernel only assists us with the second half, so we need to do the handshake phase all by ourselves.

After many hours of hacking away, I got my prototype to work. I used Scapy to handle the parsing and serialisation of TLS records, python libraries for the handshake crypto, and finally the kernel TLS apis to encrypt/decrypt the session traffic.

[This page](https://tls13.xargs.org/) was absolutely invaluable for understanding the TLS1.3 protocol, along with [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446).

At this point I realised that 95% of the work *is* the handshake. And once you have the code for the handshake, the amount of additional code required to handle session traffic is miniscule. The ktls API isn't helping much, if at all!

However, the other kernel crypto APIs (which I'll investigate further in my C implementation) will at least save us from implementing the crypto primitives from scratch.

For reference, my python *source* code currently weighs in at about 10KB (including debug logging, comments, whitespace etc.). This is a bit of an apples-to-oranges comparison, but it does give some appreciation for how small 4KB is, while simultaneously giving me hope that I'll be able to golf down my final version to <4KB.

## C Prototype

The goal for this prototype is to concretely implement everything in C, including understanding the other non-ktls kernel crypto APIs, and implementing TLS record parsing logic myself (replacing scapy).

This will act as a more readable and debuggable program, acting as a stepping stone to the final golfed version.

### secp256r1 woes

It was at this point that I realised that the crypto UAPIs don't currently support secp256r1 or any other KPPs ("Key-agreement Protocol Primitives"). I wonder... if I set my private key to the scalar value "1", then deriving the shared secret from the server's DH share should be trivial (it's just the X coordinate). Will it work?

Turns out, yes it does!!! This obviously completely breaks the security of the protocol, but it means our implementation of ECDH can effectively become a nop. I was worried that maybe servers would try to prevent this in the name of security, but apparently not (there isn't much you can do if the client is being uncooperative).

### DNS

It just occurred to me that I'm also going to be responsible for DNS resolution. I could hardcode an IP, but that would be a bit lame. I think I'll write my own basic DNS client. BUT, I'll start by hardcoding the IP.

### Compression

As an aside, it would be nice to be able to utilise compression in some way. Since we have no userspace dependencies, we could in theory pack a custom linux initramfs (a compressed cpio archive) with our executable as the init binary. The main caveat would be getting the kernel to set up its own networking stack properly, which I *think* it can do, with the right kernel commandline options.

## Golfing

Right now, the executable weighs in at 200KB when compiled on aarch64, and 17KB on x86-64.

The aarch64 build is so large because the sections are padded out to 64k boundaries, compared to 4k on x86. But even if I gzip it (which I use as a very lazy proxy for ignoring all the padding), it's still 6.5KB. Clearly, there's a lot of golfing left to do. A lot of the cruft is going to be coming from dynamicly linking with glibc. Let's remove the glibc dependency, compile to a static ELF, and do bare syscalls with [LSS](https://chromium.googlesource.com/linux-syscall-support).

With this technique, a "hello world" binary weighs in at 512 bytes:

```
$ gcc kurl.c -o kurl -ffreestanding -nostdlib -static -Os -N -s -fcf-protection=none -Wl,--build-id=none -fomit-frame-pointer -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
$ hexdump -vC kurl
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 b7 00 01 00 00 00  b0 00 40 00 00 00 00 00  |..........@.....|
00000020  40 00 00 00 00 00 00 00  00 01 00 00 00 00 00 00  |@...............|
00000030  00 00 00 00 40 00 38 00  02 00 40 00 04 00 03 00  |....@.8...@.....|
00000040  01 00 00 00 07 00 00 00  b0 00 00 00 00 00 00 00  |................|
00000050  b0 00 40 00 00 00 00 00  b0 00 40 00 00 00 00 00  |..@.......@.....|
00000060  37 00 00 00 00 00 00 00  37 00 00 00 00 00 00 00  |7.......7.......|
00000070  04 00 00 00 00 00 00 00  51 e5 74 64 06 00 00 00  |........Q.td....|
00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000a0  00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
000000b0  01 00 00 90 20 00 80 d2  21 60 03 91 c2 01 80 d2  |.... ...!`......|
000000c0  08 08 80 d2 01 00 00 d4  00 00 80 d2 a8 0b 80 d2  |................|
000000d0  01 00 00 d4 c0 03 5f d6  48 65 6c 6c 6f 2c 20 77  |......_.Hello, w|
000000e0  6f 72 6c 64 21 0a 00 00  2e 73 68 73 74 72 74 61  |orld!....shstrta|
000000f0  62 00 2e 74 65 78 74 00  2e 64 61 74 61 00 00 00  |b..text..data...|
00000100  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000110  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000120  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000130  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000140  0b 00 00 00 01 00 00 00  07 00 00 00 00 00 00 00  |................|
00000150  b0 00 40 00 00 00 00 00  b0 00 00 00 00 00 00 00  |..@.............|
00000160  28 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |(...............|
00000170  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000180  11 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |................|
00000190  d8 00 40 00 00 00 00 00  d8 00 00 00 00 00 00 00  |..@.............|
000001a0  0f 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001b0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001c0  01 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
000001d0  00 00 00 00 00 00 00 00  e7 00 00 00 00 00 00 00  |................|
000001e0  17 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001f0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000200
```

Adding back the rest of the code, porting things as neccessary (memcpy, etc. need reimplementing), results in a 3760 byte binary (compiling for aarch64).

That's a TLS client in under 4KB!!!!

We've even got 320 bytes left for a DNS client.

Adding the DNS client brought it up to ~3900 bytes, and then some golfing brought it back down to 3768.

And then ~~3744~~ ~~3536~~ ~~3472~~ ~~3432~~ 3232.

## Bonus Features?

Now that I'm comfortably below 4KB, I can think about some enhancements, my dream would be to have something more `curl`-like, which means the ability to pass in a URL. This implies the need for:

- AUXV extraction (normally done by libc before main)
- basic URL parsing (we can bodge this by passing domain in argv[1] and path in argv[2] but that's a bit unsatisfying)
- DNS query construction and slightly dynamic response parsing
- dynamically inserting the hostname and path into the HTTP query
- dynamically setting the SNI hostname in client_hello (this seems optional for the github pages host, but might not be optional elsewhere)
- correct recvall logic (not a strict requirement but will increase compat)

## Fixing Fragmentation

With some sites, (notably google.com), the handshake hangs after a `encrypted_extensions(8)` message. I need to figure out why!

Ok it looks like we're not handling record fragmentation properly.

Google (and others) are sending some of their handshake responses bundled together within a single outer envelope. We need to iteratively parse records within the decrypted data, I think?

## DNS CNAME

New problem: DNS responses involving CNAME don't work properly. Example: `old.reddit.com`

Solution: a better response "parsing" heuristic.

## ELF Golfing

I was able to save 352 bytes by simply cutting off the end of the file (see `elf_mangler.py`), which included the section headers and strtab (i.e. data not necessary at runtime).

The next piece of cruft is the `GNU_STACK` program header, which is put there by either gcc or ld (not sure). I can't figure out how to make it not do that. It might be time for a custom linker script?

Yup, a custom linker script solved it. I believe there's some more bytes on the table through overlapping the ELF header and program header, and *maybe* putting the entrypoint in the headers too.

If I write the headers and `_start` in asm, I can have it call `main` and still have the bulk of my code written in C. I implemented this and it works great (see `elf_entry.s`), now we're down to 3071 bytes.

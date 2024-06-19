# kurl

This is repo hosts my WIP entry to [BGGP5](#TODO). This README acts as a dev log of sorts.

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

# slirp-go
----------

Simple slirp implementation in golang for user mode Linux

## version 0.0.2

- use claude 4 (backup: gemini 2.5 pro)
- manual integration
- get ipv4 udp packet, relay to outside, especially test for dns query

```
write a program in golang:
- input is an ip packet with udp contents
- extract info from the packet, create udp connection, relay the payload and get response
- generate an ip packet for the response and print to stdout
```

## version 0.0.1

- use claude 4 (backup: gemini 2.5 pro)
- get ipv4 packet, response unreachable host with an icmp packet with drop

```
write 2 functions in golang `encodeSLIP` and `decodeSLIP`:
- implement codec of slip protocol
- 0xC0 as head and tail byte
- 0xDB 0xDC represents 0xC0 in the middle, 0xDB 0xDD represents 0xDB
```

```
write a program in golang:
- input is an ip packet
- generate a response ip packet to drop connection
```


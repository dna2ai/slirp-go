# slirp-go
----------

Simple slirp implementation in golang for user mode Linux

## version 0.0.4

- use claude 4 (backup: gemini 2.5 pro)
- manual integraion
- get ipv4 icmp packet, relay to outside
- get ipv4 icmp packet, if intranet, send ok directly

```
write a program in golang:
- input is an ip packet with icmp contents
- extract info from the packet, create ping connection without root, relay the payload and get response
- generate an ip packet for the response and print to stdout
- using built-in package for example syscall
```

```
write a program in golang:
- input is an ip packet with icmp contents
- generate an ip packet for icmp response with ok message
```

## version 0.0.3

- use claude 4 (backup: gemini 2.5 pro)
- manual integration
- get ipv4 udp packet, relay to outside, keepalive to get more data if any

```
write a program in golang:
- input is a sequence of ip packets with udp contents
- maintain a map to identify source + destination, record the connection for reuse
- for each packet, extract info, get connection in the map or create a new one, relay the payload and get reponse
- generate ip packet for the response and print to stdout
```

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


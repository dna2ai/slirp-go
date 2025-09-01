# slirp-go
----------

Simple slirp implementation in golang for user mode Linux

## how to use

- download linux kernel source code, extract and `ARCH=um make menuconfig` + `ARCH=um make` to get `linux`
- `go build -o slirp main.go`
- `linux udba=./rootfs.img root=/dev/udba rw init=/bin/bash eth0=slirp,,/path/to/slirp,-debug`
- in the user mode linux

### Command Line Options

- `-debug`: Enable debug output
- `-mtu <size>`: Set MTU value (default: 1500)
- `-ipv6`: Enable IPv6 support
- `-servers`: Enable server support (SOCKS5 proxy)
- `-socks5-port <port>`: SOCKS5 proxy port (default: 1080)

```
# example of ubuntu rootfs
# before, use proot to install inet-tools/iproute2 for ifconfig and route
$ ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
$ route add default gw 10.0.2.2

$ ip -6 addr add fd00::15/64 dev eth0
$ ip -6 route add default via fd00::2

$ apt update
$ apt install -y curl
$ curl https://www.google.com

$ ping 8.8.8.8
$ nslookup google.com
$ wget http://example.com

$ ping6 2001:4860:4860::8888
$ nslookup google.com 2001:4860:4860::8888
$ wget http://ipv6.google.com

# on host
$ curl --socks5 localhost:1080 http://10.0.2.15:8080/
```
## known issues and future work

- [ ] add test

## version 0.0.6

- implement assisted with Cursor + Claude 4
- support icmp ipv6
- support udp ipv6
- support tcp ipv6
- support tcp/udp server via simple socks5

```
# try 1
we have a SLIRP program in golang to enable internet access for user mode ilnux, now the implementation is complete for:
- relay ping/icmp packet, user mode linux connect to our slirp program can ping outside
- relay udp packet, can query dns outside
- relay tcp packet, in ubuntu image, can apt update, apt install
- only support ipv4 protocol
please help write code to:
- support tcp/udp server; for example, we should have a socks5 proxy started in our slirp program, outside program like curl should visit our service in user mode linux via the socks proxy so that we can get client payload; if we get payload, we need to simulate to send SYN packet and after SYN-ACK, send ACK, then we send the payload. similar to udp, but udp is much simpler.
- support icmp ipv6 processing
- support udp ipv6 processing
- support tcp ipv6 processing

# try 2
in your implemented @socks5.go , there is no interaction with user mode linux; where `serverBuffer` is used? you only append income data into the buffer, but no consumer? if any connection, you should create a tcp listener, try send SYN via stdout to user mode linux, if get SYN-ACK, then send ACK and accept the client connection to the server; similar to FIN; and for data, if client send data, you should split into fragments and send to user mode linux via stdout; and if you get data from server, send them to client.

# try 3
better now, but you do not handle the server connection correctly:
- you only try to send SYN to server, but the tcp uses 3 handshake, SYN, SYN-ACK, ACK; if server does not reply SYN-ACK, you should not establish the connection and you should close client connection; similar to FIN
- if no SYN-ACK, you can assume there is no such server running
```

## version 0.0.5

- improvements by Bytedance Doubao

```
please read slirp.go and understand how it can interact with user mode linux;
fix bugs for tcp relay processing.
```

- send payload to outside, filter in valid data in a simple way

```
please write a function in golang:
`checkTcpPacketDup(packetSeqNum, lastSeqNum, packetTcpPayloadLength)`;
if missing info, please add more args
```

- get ipv4 tcp packet, get large response, send into a queue
- send data fragment, receive ack, send next fragment

```
write a function in golang to implement `fill(out, data, iseof)`:
- data is binary payload
- out is an array of binary data
- if not iseof, append data to last item of out
- if iseof, create a new item in out and append data
```

```
write a function in golang:
- split large data into fragments
- generate ip packet to wrap the tcp fragments
```

- use claude 4 (backup: gemini 2.5 pro)
- manual integraion
- get ipv4 tcp packet, relay to outside and get response without fragments
- use gpt5-high to debug tcp connection problem (claude4 and gemini 2.5 pro get always wrong answer)

```
write a program in golang:
- input is a sequence of ip packets with tcp contents
- use map for tcp state machine to handle packets correctly including SYN, ACK, FIN, ...
```

```
write a program in golang:
- open a tcp connection with "net" package
- send payload directly without "http" package
- get response and print to stdout
```

```
# gpt5-high
\`\`\`
<paste code of HandleTcpClnSYN, HandleTcpClnACK and some more code>
\`\`\`
above is the code to process ip packet for tcp connection in user mode linux,
but use this code with curl, it always reports:
`curl: (1) Received HTTP/0.9 when not allowed`
how to fix this bug?
```

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

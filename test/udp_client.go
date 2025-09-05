package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "os"
)

func main() {
    // Connect to SOCKS5 proxy
    socksAddr := "127.0.0.1:11080"

    // TCP connection to SOCKS5 for handshake
    tcpConn, err := net.Dial("tcp", socksAddr)
    if err != nil {
        fmt.Println("Error connecting to SOCKS5:", err)
        os.Exit(1)
    }
    defer tcpConn.Close()

    // SOCKS5 handshake
    // Send greeting
    tcpConn.Write([]byte{0x05, 0x01, 0x00}) // VER, NMETHODS, NO AUTH

    // Read response
    resp := make([]byte, 2)
    tcpConn.Read(resp)
    if resp[0] != 0x05 || resp[1] != 0x00 {
        fmt.Println("SOCKS5 handshake failed")
        os.Exit(1)
    }

    // UDP ASSOCIATE request
    targetIP := net.ParseIP("10.0.2.15")
    req := []byte{0x05, 0x03, 0x00, 0x01} // VER, CMD (UDP ASSOCIATE), RSV, ATYP (IPv4)
    req = append(req, targetIP.To4()...)
    req = append(req, 0x00, 0x00) // Port 0 (let proxy assign)

    tcpConn.Write(req)

    // Read response
    resp2 := make([]byte, 10)
    n, _ := tcpConn.Read(resp2)
    if resp2[1] != 0x00 {
        fmt.Printf("UDP ASSOCIATE failed: %x\n", resp2[1])
        os.Exit(1)
    }

    // Parse UDP relay address
    udpRelayPort := binary.BigEndian.Uint16(resp2[n-2:])
    udpRelayAddr := fmt.Sprintf("127.0.0.1:%d", udpRelayPort)

    // Create UDP connection
    udpConn, err := net.Dial("udp", udpRelayAddr)
    if err != nil {
        fmt.Println("Error creating UDP connection:", err)
        os.Exit(1)
    }
    defer udpConn.Close()

    // Build UDP request with SOCKS5 header
    udpReq := []byte{0x00, 0x00, 0x00, 0x01} // RSV, FRAG, ATYP (IPv4)
    udpReq = append(udpReq, targetIP.To4()...)
    udpReq = append(udpReq, 0x1f, 0x91) // Port 8081
    udpReq = append(udpReq, []byte("hello")...)

    // Send UDP packet
    _, err = udpConn.Write(udpReq)
    if err != nil {
        fmt.Println("Error sending UDP:", err)
        os.Exit(1)
    }

    // Read response
    buffer := make([]byte, 1024)
    n, err = udpConn.Read(buffer)
    if err != nil {
        fmt.Println("Error reading response:", err)
        os.Exit(1)
    }

    // Parse response (skip SOCKS5 UDP header - 10 bytes)
    if n > 10 {
        response := string(buffer[10:n])
        fmt.Println("Response:", response)
    }
}

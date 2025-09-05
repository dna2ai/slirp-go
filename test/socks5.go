package main

import (
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "sync"
    "time"
)

type UDPRelay struct {
    clientAddr *net.TCPAddr
    udpConn    *net.UDPConn
    clients    map[string]*net.UDPAddr
    mutex      sync.Mutex
}

func main() {
    listener, err := net.Listen("tcp", ":11080")
    if err != nil {
        fmt.Println("Error starting SOCKS5 server:", err)
        return
    }
    defer listener.Close()

    fmt.Println("SOCKS5 server listening on :11080")

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error accepting connection:", err)
            continue
        }
        go handleClient(conn)
    }
}

func handleClient(conn net.Conn) {
    defer conn.Close()

    // Read greeting
    buf := make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return
    }

    ver, nmethods := buf[0], buf[1]
    if ver != 0x05 {
        return
    }

    // Read methods
    methods := make([]byte, nmethods)
    if _, err := io.ReadFull(conn, methods); err != nil {
        return
    }

    // Reply with no auth required
    conn.Write([]byte{0x05, 0x00})

    // Read request
    buf = make([]byte, 4)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return
    }

    ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
    if ver != 0x05 {
        return
    }

    // Read address
    var addr string
    switch atyp {
    case 0x01: // IPv4
        buf := make([]byte, 4)
        io.ReadFull(conn, buf)
        addr = net.IP(buf).String()
    case 0x03: // Domain
        buf := make([]byte, 1)
        io.ReadFull(conn, buf)
        domainLen := buf[0]
        domain := make([]byte, domainLen)
        io.ReadFull(conn, domain)
        addr = string(domain)
    default:
        conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }

    // Read port
    portBuf := make([]byte, 2)
    io.ReadFull(conn, portBuf)
    port := binary.BigEndian.Uint16(portBuf)

    switch cmd {
    case 0x01: // CONNECT
        handleConnect(conn, addr, port)
    case 0x03: // UDP ASSOCIATE
        handleUDPAssociate(conn)
    default:
        conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
    }
}

func handleConnect(conn net.Conn, addr string, port uint16) {
    target := fmt.Sprintf("%s:%d", addr, port)
    targetConn, err := net.Dial("tcp", target)
    if err != nil {
        conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }
    defer targetConn.Close()

    // Send success response
    conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

    // Relay data
    go io.Copy(targetConn, conn)
    io.Copy(conn, targetConn)
}

func handleUDPAssociate(conn net.Conn) {
    // Create UDP socket
    udpAddr, _ := net.ResolveUDPAddr("udp", ":0")
    udpConn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }

    // Get the assigned port
    localAddr := udpConn.LocalAddr().(*net.UDPAddr)
    port := localAddr.Port

    // Send success response with UDP relay address
    resp := []byte{0x05, 0x00, 0x00, 0x01}
    resp = append(resp, 127, 0, 0, 1) // 127.0.0.1
    resp = append(resp, byte(port>>8), byte(port&0xff))
    conn.Write(resp)

    relay := &UDPRelay{
        udpConn: udpConn,
        clients: make(map[string]*net.UDPAddr),
    }

    // Handle UDP relay
    go relay.handleUDP()

    // Keep TCP connection alive
    buf := make([]byte, 1)
    for {
        if _, err := conn.Read(buf); err != nil {
            udpConn.Close()
            break
        }
    }
}

func (r *UDPRelay) handleUDP() {
    buffer := make([]byte, 4096)
    for {
        n, clientAddr, err := r.udpConn.ReadFromUDP(buffer)
        if err != nil {
            break
        }

        if n < 10 {
            continue
        }

        // Parse SOCKS5 UDP header
        atyp := buffer[3]
        var targetAddr string
        var headerLen int

        switch atyp {
        case 0x01: // IPv4
            targetAddr = net.IP(buffer[4:8]).String()
            port := binary.BigEndian.Uint16(buffer[8:10])
            targetAddr = fmt.Sprintf("%s:%d", targetAddr, port)
            headerLen = 10
        default:
            continue
        }

        // Store client address
        r.mutex.Lock()
        r.clients[targetAddr] = clientAddr
        r.mutex.Unlock()

        // Forward to target
        targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
        if err != nil {
            continue
        }

        targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
        if err != nil {
            continue
        }

        // Send data without SOCKS5 header
        targetConn.Write(buffer[headerLen:n])

        // Read response
        go func(targetConn *net.UDPConn, targetAddr string) {
            defer targetConn.Close()
            respBuf := make([]byte, 4096)
            targetConn.SetReadDeadline(time.Now().Add(10 * time.Second))
            n, err := targetConn.Read(respBuf)
            if err != nil {
                return
            }

            r.mutex.Lock()
            clientAddr, ok := r.clients[targetAddr]
            r.mutex.Unlock()

            if ok {
                // Build SOCKS5 UDP response
                resp := []byte{0x00, 0x00, 0x00, 0x01} // RSV, FRAG, ATYP
                targetIP, targetPort, _ := net.SplitHostPort(targetAddr)
                resp = append(resp, net.ParseIP(targetIP).To4()...)
                port, _ := net.LookupPort("udp", targetPort)
                resp = append(resp, byte(port>>8), byte(port&0xff))
                resp = append(resp, respBuf[:n]...)

                r.udpConn.WriteToUDP(resp, clientAddr)
            }
        }(targetConn, targetAddr)
    }
}

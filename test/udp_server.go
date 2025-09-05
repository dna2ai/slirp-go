package main

import (
    "fmt"
    "net"
    "os"
)

func main() {
    // Listen on UDP port 8081
    addr, err := net.ResolveUDPAddr("udp", ":8081")
    if err != nil {
        fmt.Println("Error resolving address:", err)
        os.Exit(1)
    }

    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        fmt.Println("Error listening:", err)
        os.Exit(1)
    }
    defer conn.Close()

    fmt.Println("UDP server listening on :8081")

    buffer := make([]byte, 1024)
    for {
        n, clientAddr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            fmt.Println("Error reading:", err)
            continue
        }

        message := string(buffer[:n])
        fmt.Printf("Received from %s: %s\n", clientAddr, message)

        if message == "hello" {
            _, err = conn.WriteToUDP([]byte("world"), clientAddr)
            if err != nil {
                fmt.Println("Error writing:", err)
            }
        }
    }
}

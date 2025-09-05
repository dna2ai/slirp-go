package main

import (
    "fmt"
    "net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "world")
}

func main() {
    http.HandleFunc("/hello", helloHandler)
    
    fmt.Println("HTTP server listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Println("Error starting HTTP server:", err)
    }
}

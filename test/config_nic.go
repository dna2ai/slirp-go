package main

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	IFNAMSIZ = 16
	RTF_UP = 0x0001
	RTF_GATEWAY = 0x0002
)

type sockaddr struct {
	Family uint16
	Data   [14]byte
}

type sockaddr_in struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

type ifreq struct {
	Name  [IFNAMSIZ]byte
	Union [24]byte
}

type rtentry struct {
	Pad1    uint64
	Dst     sockaddr
	Gateway sockaddr
	Genmask sockaddr
	Flags   uint16
	Pad2    int16
	Pad3    uint64
	Tos     uint8
	Class   uint8
	Pad4    int16
	Metric  int16
	Dev     uintptr
	Mtu     uint64
	Window  uint64
	Irtt    uint16
}

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		os.Exit(1)
	}
	defer syscall.Close(fd)

	// Configure lo
	configureInterface(fd, "lo", "127.0.0.1", "255.0.0.0")

	// Configure eth0
	configureInterface(fd, "eth0", "10.0.2.15", "255.255.255.0")

	// Set default gateway to 10.0.2.2 via eth0
	setDefaultGateway(fd, "10.0.2.2", "eth0")
}

func configureInterface(fd int, ifname string, ipStr string, maskStr string) {
	// Set IP address
	var ifr ifreq
	copy(ifr.Name[:], ifname)

	sa := sockaddr_in{Family: syscall.AF_INET}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		os.Exit(1)
	}
	copy(sa.Addr[:], ip)
	*(*sockaddr_in)(unsafe.Pointer(&ifr.Union[0])) = sa

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifr)))
	if err != 0 {
		os.Exit(1)
	}

	// Set netmask
	copy(ifr.Name[:], ifname)
	sa = sockaddr_in{Family: syscall.AF_INET}
	mask := net.ParseIP(maskStr).To4()
	if mask == nil {
		os.Exit(1)
	}
	copy(sa.Addr[:], mask)
	*(*sockaddr_in)(unsafe.Pointer(&ifr.Union[0])) = sa

	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifr)))
	if err != 0 {
		os.Exit(1)
	}

	// Bring up the interface
	copy(ifr.Name[:], ifname)
	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if err != 0 {
		os.Exit(1)
	}

	flags := *(*int16)(unsafe.Pointer(&ifr.Union[0]))
	flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	*(*int16)(unsafe.Pointer(&ifr.Union[0])) = flags

	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if err != 0 {
		os.Exit(1)
	}
}

func setDefaultGateway(fd int, gwStr string, ifname string) {
	var rt rtentry

	// Dst: 0.0.0.0
	rt.Dst.Family = syscall.AF_INET
	copy(rt.Dst.Data[2:6], []byte{0, 0, 0, 0})

	// Genmask: 0.0.0.0
	rt.Genmask.Family = syscall.AF_INET
	copy(rt.Genmask.Data[2:6], []byte{0, 0, 0, 0})

	// Gateway
	rt.Gateway.Family = syscall.AF_INET
	gw := net.ParseIP(gwStr).To4()
	if gw == nil {
		os.Exit(1)
	}
	copy(rt.Gateway.Data[2:6], gw)

	rt.Flags = RTF_UP | RTF_GATEWAY
	rt.Metric = 1

	var devname [IFNAMSIZ + 1]byte
	copy(devname[:], ifname)
	rt.Dev = uintptr(unsafe.Pointer(&devname[0]))

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCADDRT, uintptr(unsafe.Pointer(&rt)))
	if err != 0 {
		os.Exit(1)
	}
}

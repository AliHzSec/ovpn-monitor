package sysinfo

import (
	"fmt"
	"runtime"
	"time"
)

// SystemStats holds a point-in-time snapshot of system metrics.
type SystemStats struct {
	CPUPercent   float64  `json:"cpu_percent"`
	CPUCores     int      `json:"cpu_cores"`
	MemTotal     uint64   `json:"mem_total"`
	MemUsed      uint64   `json:"mem_used"`
	MemFree      uint64   `json:"mem_free"`
	SwapTotal    uint64   `json:"swap_total"`
	SwapUsed     uint64   `json:"swap_used"`
	DiskTotal    uint64   `json:"disk_total"`
	DiskUsed     uint64   `json:"disk_used"`
	DiskFree     uint64   `json:"disk_free"`
	NetUpSpeed   uint64   `json:"net_up_speed"`   // bytes/sec
	NetDownSpeed uint64   `json:"net_down_speed"` // bytes/sec
	NetSent      uint64   `json:"net_sent"`       // interface counter: total bytes sent since boot
	NetRecv      uint64   `json:"net_recv"`       // interface counter: total bytes received since boot
	VPNTotalSent uint64   `json:"vpn_total_sent"` // all-time sum of VPN client bytes_sent from DB
	VPNTotalRecv uint64   `json:"vpn_total_recv"` // all-time sum of VPN client bytes_received from DB
	IPs          []string `json:"ips"`
	IPv6s        []string `json:"ipv6s"`
	TCPCount     int      `json:"tcp_count"`
	UDPCount     int      `json:"udp_count"`
	OSUptime     uint64   `json:"os_uptime"`        // seconds since system boot
	OVPNUptime   uint64   `json:"ovpn_uptime"`      // seconds since openvpn service started
	WGUptime     uint64   `json:"wireguard_uptime"` // seconds since wg-quick@wg0 went active
	OSName       string   `json:"os_name"`          // PRETTY_NAME from /etc/os-release
	ClientOnline int      `json:"client_online"`    // currently connected VPN clients
	ClientTotal  int      `json:"client_total"`     // total registered VPN clients

	KernelVersion  string `json:"kernel_version"` // output of uname -r
	Timezone       string `json:"timezone"`       // system time zone, e.g. Europe/Berlin
	Virtualization string `json:"virtualization"` // e.g. KVM, OpenVZ, LXC, None / Bare Metal
}

// Collect gathers all metrics and returns a SystemStats snapshot.
// It blocks for ~1 second to sample CPU and network speed.
func Collect() (*SystemStats, error) {
	cpu0, err := readCPUStat()
	if err != nil {
		return nil, fmt.Errorf("cpu stat: %w", err)
	}
	net0, err := readNetDev()
	if err != nil {
		return nil, fmt.Errorf("net dev: %w", err)
	}

	time.Sleep(time.Second)

	cpu1, err := readCPUStat()
	if err != nil {
		return nil, fmt.Errorf("cpu stat: %w", err)
	}
	net1, err := readNetDev()
	if err != nil {
		return nil, fmt.Errorf("net dev: %w", err)
	}

	totalDelta := cpu1.total - cpu0.total
	idleDelta := cpu1.idle - cpu0.idle
	var cpuPct float64
	if totalDelta > 0 {
		busy := totalDelta - idleDelta
		cpuPct = float64(busy) / float64(totalDelta) * 100.0
		if cpuPct > 100 {
			cpuPct = 100
		}
	}

	var upSpeed, downSpeed uint64
	if net1.sent >= net0.sent {
		upSpeed = net1.sent - net0.sent
	}
	if net1.recv >= net0.recv {
		downSpeed = net1.recv - net0.recv
	}

	mem, err := readMemInfo()
	if err != nil {
		return nil, fmt.Errorf("meminfo: %w", err)
	}

	disk, err := readDisk("/")
	if err != nil {
		return nil, fmt.Errorf("disk: %w", err)
	}

	ips, err := getLocalIPs()
	if err != nil {
		return nil, fmt.Errorf("local ips: %w", err)
	}

	ipv6s, err := getLocalIPv6s()
	if err != nil {
		return nil, fmt.Errorf("local ipv6s: %w", err)
	}

	// state 01 = ESTABLISHED
	tcpCount, err := countProcNet("/proc/net/tcp", "01")
	if err != nil {
		return nil, fmt.Errorf("tcp count: %w", err)
	}

	udpCount, err := countProcNet("/proc/net/udp", "")
	if err != nil {
		return nil, fmt.Errorf("udp count: %w", err)
	}

	osUptime, _ := readOSUptime()
	ovpnUptime := getOVPNUptime(osUptime)
	wgUptime := getWGUptime(osUptime)
	osName := readOSName()
	kernel, timezone, virtualization := hostInfo()

	return &SystemStats{
		CPUPercent:   cpuPct,
		CPUCores:     runtime.NumCPU(),
		MemTotal:     mem.total,
		MemUsed:      mem.used,
		MemFree:      mem.free,
		SwapTotal:    mem.swapTotal,
		SwapUsed:     mem.swapUsed,
		DiskTotal:    disk.total,
		DiskUsed:     disk.used,
		DiskFree:     disk.free,
		NetUpSpeed:   upSpeed,
		NetDownSpeed: downSpeed,
		NetSent:      net0.sent, // totals from first read
		NetRecv:      net0.recv,
		IPs:          ips,
		IPv6s:        ipv6s,
		TCPCount:     tcpCount,
		UDPCount:     udpCount,
		OSUptime:     osUptime,
		OVPNUptime:   ovpnUptime,
		WGUptime:     wgUptime,
		OSName:       osName,

		KernelVersion:  kernel,
		Timezone:       timezone,
		Virtualization: virtualization,
	}, nil
}

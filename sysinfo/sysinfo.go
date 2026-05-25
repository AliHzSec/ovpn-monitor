package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	OSUptime     uint64   `json:"os_uptime"`   // seconds since system boot
	OVPNUptime   uint64   `json:"ovpn_uptime"` // seconds since openvpn service started
}

type cpuSample struct {
	total uint64
	idle  uint64
}

func readCPUStat() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return cpuSample{}, fmt.Errorf("unexpected /proc/stat format")
		}
		nums := make([]uint64, 0, len(fields)-1)
		for _, s := range fields[1:] {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				break
			}
			nums = append(nums, v)
		}
		if len(nums) < 4 {
			return cpuSample{}, fmt.Errorf("insufficient cpu fields in /proc/stat")
		}
		for len(nums) < 8 {
			nums = append(nums, 0)
		}
		user, nice, system, idle := nums[0], nums[1], nums[2], nums[3]
		iowait, irq, softirq, steal := nums[4], nums[5], nums[6], nums[7]
		idleAll := idle + iowait
		nonIdle := user + nice + system + irq + softirq + steal
		return cpuSample{total: idleAll + nonIdle, idle: idleAll}, nil
	}
	if err := sc.Err(); err != nil {
		return cpuSample{}, err
	}
	return cpuSample{}, fmt.Errorf("cpu line not found in /proc/stat")
}

type netSample struct {
	sent uint64
	recv uint64
}

func readNetDev() (netSample, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return netSample{}, err
	}
	defer f.Close()

	var totalSent, totalRecv uint64
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip two header lines
		}
		line := sc.Text()
		before, after, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(before)
		if iface == "lo" {
			continue
		}
		// fields after colon: recv_bytes recv_pkts ... (8 fields) sent_bytes sent_pkts ...
		fields := strings.Fields(after)
		if len(fields) < 9 {
			continue
		}
		recv, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		sent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		totalRecv += recv
		totalSent += sent
	}
	if err := sc.Err(); err != nil {
		return netSample{}, err
	}
	return netSample{sent: totalSent, recv: totalRecv}, nil
}

type memInfo struct {
	total     uint64
	used      uint64
	free      uint64
	swapTotal uint64
	swapUsed  uint64
}

func readMemInfo() (memInfo, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return memInfo{}, err
	}
	defer f.Close()

	vals := make(map[string]uint64, 8)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		vals[key] = v * 1024 // kB → bytes
	}
	if err := sc.Err(); err != nil {
		return memInfo{}, err
	}
	total := vals["MemTotal"]
	free := vals["MemFree"]
	available := vals["MemAvailable"]
	var used uint64
	if total > available {
		used = total - available
	}
	swapTotal := vals["SwapTotal"]
	swapFree := vals["SwapFree"]
	var swapUsed uint64
	if swapTotal > swapFree {
		swapUsed = swapTotal - swapFree
	}
	return memInfo{total: total, used: used, free: free, swapTotal: swapTotal, swapUsed: swapUsed}, nil
}

type diskInfo struct {
	total uint64
	used  uint64
	free  uint64
}

func readDisk(path string) (diskInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskInfo{}, err
	}
	bsize := uint64(stat.Bsize)
	total := stat.Blocks * bsize
	free := stat.Bavail * bsize
	var used uint64
	if stat.Blocks > stat.Bfree {
		used = (stat.Blocks - stat.Bfree) * bsize
	}
	return diskInfo{total: total, used: used, free: free}, nil
}

func getLocalIPs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0)
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			ips = append(ips, ip4.String())
		}
	}
	return ips, nil
}

// isPublicIPv6 returns true only for global unicast addresses (2000::/3).
// This filters out loopback (::1), link-local (fe80::/10), and ULA (fc00::/7).
func isPublicIPv6(s string) bool {
	return len(s) > 0 && (s[0] == '2' || s[0] == '3')
}

func getLocalIPv6s() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0)
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			continue // skip IPv4
		}
		s := ip.String()
		if !isPublicIPv6(s) {
			continue // only keep global unicast
		}
		ips = append(ips, s)
	}
	return ips, nil
}

// countProcNet counts entries in a /proc/net/{tcp,udp} file.
// If filterState is non-empty, only lines whose 4th field matches it are counted.
// The header line is always skipped.
func countProcNet(path string, filterState string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // skip header line
		}
		if filterState == "" {
			count++
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] == filterState {
			count++
		}
	}
	return count, sc.Err()
}

func readOSUptime() (uint64, error) {
	f, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 1 {
			secs, err := strconv.ParseFloat(fields[0], 64)
			if err != nil {
				return 0, err
			}
			return uint64(secs), nil
		}
	}
	return 0, fmt.Errorf("failed to parse /proc/uptime")
}

func getServiceUptime(osUptimeSec uint64, serviceName string) (uint64, error) {
	out, err := exec.Command("systemctl", "show", serviceName,
		"--property=ActiveEnterTimestampMonotonic", "--no-pager").Output()
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(out))
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return 0, fmt.Errorf("unexpected systemctl output: %q", line)
	}
	microseconds, err := strconv.ParseUint(strings.TrimSpace(line[idx+1:]), 10, 64)
	if err != nil {
		return 0, err
	}
	if microseconds == 0 {
		return 0, fmt.Errorf("service %q not active", serviceName)
	}
	startedAtSec := microseconds / 1_000_000
	if osUptimeSec < startedAtSec {
		return 0, nil
	}
	return osUptimeSec - startedAtSec, nil
}

func getOVPNUptime(osUptimeSec uint64) uint64 {
	candidates := []string{"openvpn-server@server", "openvpn@server"}
	for _, name := range candidates {
		if uptime, err := getServiceUptime(osUptimeSec, name); err == nil {
			return uptime
		}
	}
	return 0
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
	}, nil
}

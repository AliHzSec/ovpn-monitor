package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemStats holds a point-in-time snapshot of system metrics.
type SystemStats struct {
	CPUPercent   float64  `json:"cpu_percent"`
	MemTotal     uint64   `json:"mem_total"`
	MemUsed      uint64   `json:"mem_used"`
	MemFree      uint64   `json:"mem_free"`
	DiskTotal    uint64   `json:"disk_total"`
	DiskUsed     uint64   `json:"disk_used"`
	DiskFree     uint64   `json:"disk_free"`
	NetUpSpeed   uint64   `json:"net_up_speed"`   // bytes/sec
	NetDownSpeed uint64   `json:"net_down_speed"` // bytes/sec
	NetSent      uint64   `json:"net_sent"`       // total bytes sent (all time)
	NetRecv      uint64   `json:"net_recv"`       // total bytes received (all time)
	IPs          []string `json:"ips"`
	TCPCount     int      `json:"tcp_count"`
	UDPCount     int      `json:"udp_count"`
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
	total uint64
	used  uint64
	free  uint64
}

func readMemInfo() (memInfo, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return memInfo{}, err
	}
	defer f.Close()

	vals := make(map[string]uint64, 6)
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
		if _, ok1 := vals["MemTotal"]; ok1 {
			if _, ok2 := vals["MemFree"]; ok2 {
				if _, ok3 := vals["MemAvailable"]; ok3 {
					break
				}
			}
		}
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
	return memInfo{total: total, used: used, free: free}, nil
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

	// state 01 = ESTABLISHED
	tcpCount, err := countProcNet("/proc/net/tcp", "01")
	if err != nil {
		return nil, fmt.Errorf("tcp count: %w", err)
	}

	udpCount, err := countProcNet("/proc/net/udp", "")
	if err != nil {
		return nil, fmt.Errorf("udp count: %w", err)
	}

	return &SystemStats{
		CPUPercent:   cpuPct,
		MemTotal:     mem.total,
		MemUsed:      mem.used,
		MemFree:      mem.free,
		DiskTotal:    disk.total,
		DiskUsed:     disk.used,
		DiskFree:     disk.free,
		NetUpSpeed:   upSpeed,
		NetDownSpeed: downSpeed,
		NetSent:      net0.sent, // totals from first read
		NetRecv:      net0.recv,
		IPs:          ips,
		TCPCount:     tcpCount,
		UDPCount:     udpCount,
	}, nil
}

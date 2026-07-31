package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

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

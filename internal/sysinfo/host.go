package sysinfo

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func readOSName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		val := strings.TrimPrefix(line, "PRETTY_NAME=")
		return strings.Trim(val, `"`)
	}
	return ""
}

// Kernel version, time zone and virtualization type never change while the
// process runs, so they are resolved once and reused on every collection cycle.
var (
	hostInfoOnce  sync.Once
	kernelVersion string
	timezoneName  string
	virtName      string
)

func hostInfo() (kernel, timezone, virtualization string) {
	hostInfoOnce.Do(func() {
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			kernelVersion = strings.TrimSpace(string(out))
		}
		timezoneName = readTimezone()
		virtName = detectVirtualization()
	})
	return kernelVersion, timezoneName, virtName
}

func readTimezone() string {
	// /etc/localtime is a symlink into the zoneinfo database and always
	// reflects the active zone. /etc/timezone can go stale (e.g. left at
	// "Etc/UTC" after the zone was changed with timedatectl), so it is only
	// consulted as a fallback.
	if target, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			if tz := target[i+len("zoneinfo/"):]; tz != "" {
				return tz
			}
		}
	}
	if out, err := exec.Command("timedatectl", "show", "--property=Timezone", "--value").Output(); err == nil {
		if tz := strings.TrimSpace(string(out)); tz != "" {
			return tz
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		if tz := strings.TrimSpace(string(b)); tz != "" {
			return tz
		}
	}
	return "UTC"
}

// detectVirtualization identifies the virtualization technology the host runs
// under (KVM, OpenVZ, LXC, Docker, …) or reports bare metal.
func detectVirtualization() string {
	// systemd-detect-virt prints the technology name and exits non-zero for
	// "none", so the output is meaningful even when err != nil.
	out, _ := exec.Command("systemd-detect-virt").Output()
	if v := strings.TrimSpace(string(out)); v != "" {
		return prettyVirtName(v)
	}
	// Fallbacks for systems without systemd-detect-virt.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}
	if _, err := os.Stat("/proc/vz"); err == nil {
		// /proc/bc exists only on the OpenVZ host node, not inside containers.
		if _, err := os.Stat("/proc/bc"); os.IsNotExist(err) {
			return "OpenVZ"
		}
	}
	if b, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return prettyVirtName(v)
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil && strings.Contains(string(b), "hypervisor") {
		return "VM (unknown)"
	}
	return "None / Bare Metal"
}

func prettyVirtName(v string) string {
	switch strings.ToLower(v) {
	case "none":
		return "None / Bare Metal"
	case "kvm":
		return "KVM"
	case "qemu":
		return "QEMU"
	case "vmware":
		return "VMware"
	case "microsoft":
		return "Hyper-V"
	case "oracle":
		return "VirtualBox"
	case "xen":
		return "Xen"
	case "openvz":
		return "OpenVZ"
	case "lxc":
		return "LXC"
	case "lxc-libvirt":
		return "LXC (libvirt)"
	case "docker":
		return "Docker"
	case "podman":
		return "Podman"
	case "systemd-nspawn":
		return "systemd-nspawn"
	case "wsl":
		return "WSL"
	default:
		return v
	}
}

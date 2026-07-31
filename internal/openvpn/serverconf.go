package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ParseServerSubnet reads an OpenVPN server config file and extracts the VPN
// subnet from the "server <ip> <mask>" directive, returning it as a CIDR string.
func ParseServerSubnet(configPath string) (string, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "server ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ipStr := fields[1]
		maskStr := fields[2]

		parsedMask := net.ParseIP(maskStr)
		if parsedMask == nil {
			return "", fmt.Errorf("invalid netmask %q in server config", maskStr)
		}
		m := net.IPMask(parsedMask.To4())
		ones, bits := m.Size()
		if bits == 0 {
			return "", fmt.Errorf("could not determine prefix length from mask %q", maskStr)
		}
		return fmt.Sprintf("%s/%d", ipStr, ones), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no 'server' directive found in %s", configPath)
}

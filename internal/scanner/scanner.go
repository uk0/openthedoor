package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"fwctl/internal/config"
)

// PortInfo represents information about an open port
type PortInfo struct {
	Port      int
	Protocol  string
	Process   string
	PID       int
	Address   string
	State     string
	Protected bool
}

// Scanner scans for open ports and their associated processes
type Scanner struct{}

// New creates a new Scanner
func New() *Scanner {
	return &Scanner{}
}

// ScanPorts scans for listening ports and returns port information
func (s *Scanner) ScanPorts() ([]PortInfo, error) {
	// Try ss first, fall back to netstat
	ports, err := s.scanWithSS()
	if err != nil {
		ports, err = s.scanWithNetstat()
		if err != nil {
			return nil, fmt.Errorf("failed to scan ports: %v", err)
		}
	}

	// Mark protected ports
	for i := range ports {
		ports[i].Protected = config.IsProtectedPort(ports[i].Port)
	}

	// Deduplicate by port number (merge IPv4 and IPv6)
	return s.deduplicatePorts(ports), nil
}

// deduplicatePorts merges duplicate ports (IPv4/IPv6) keeping the one with more info
func (s *Scanner) deduplicatePorts(ports []PortInfo) []PortInfo {
	seen := make(map[int]*PortInfo)
	for i := range ports {
		p := &ports[i]
		if existing, ok := seen[p.Port]; ok {
			// Keep the one with process info, prefer IPv4
			if existing.Process == "" && p.Process != "" {
				seen[p.Port] = p
			}
		} else {
			seen[p.Port] = p
		}
	}

	result := make([]PortInfo, 0, len(seen))
	for _, p := range seen {
		result = append(result, *p)
	}
	return result
}

// scanWithSS uses the ss command to scan ports
func (s *Scanner) scanWithSS() ([]PortInfo, error) {
	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return s.parseSSOutput(string(output))
}

// parseSSOutput parses ss -tlnp output
func (s *Scanner) parseSSOutput(output string) ([]PortInfo, error) {
	var ports []PortInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header
	scanner.Scan()

	// Regex to extract process info: users:(("process",pid=123,fd=4))
	processRegex := regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse local address (field 4)
		localAddr := fields[3]
		port, addr := parseAddress(localAddr)
		if port == 0 {
			continue
		}

		info := PortInfo{
			Port:     port,
			Protocol: "tcp",
			Address:  addr,
			State:    fields[0],
		}

		// Parse process info if available
		if len(fields) >= 6 {
			matches := processRegex.FindStringSubmatch(fields[5])
			if len(matches) >= 3 {
				info.Process = matches[1]
				info.PID, _ = strconv.Atoi(matches[2])
			}
		}

		ports = append(ports, info)
	}

	return ports, nil
}

// scanWithNetstat uses netstat as fallback
func (s *Scanner) scanWithNetstat() ([]PortInfo, error) {
	cmd := exec.Command("netstat", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return s.parseNetstatOutput(string(output))
}

// parseNetstatOutput parses netstat -tlnp output
func (s *Scanner) parseNetstatOutput(output string) ([]PortInfo, error) {
	var ports []PortInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip headers
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "tcp") {
			fields := strings.Fields(line)
			if len(fields) < 7 {
				continue
			}

			// Parse local address (field 3)
			localAddr := fields[3]
			port, addr := parseAddress(localAddr)
			if port == 0 {
				continue
			}

			info := PortInfo{
				Port:     port,
				Protocol: "tcp",
				Address:  addr,
				State:    fields[5],
			}

			// Parse PID/Program (field 6)
			pidProg := fields[6]
			if pidProg != "-" {
				parts := strings.Split(pidProg, "/")
				if len(parts) >= 2 {
					info.PID, _ = strconv.Atoi(parts[0])
					info.Process = parts[1]
				}
			}

			ports = append(ports, info)
		}
	}

	return ports, nil
}

// parseAddress extracts port and address from addr:port format
func parseAddress(addr string) (int, string) {
	// Handle IPv6 format [::]:port
	if strings.HasPrefix(addr, "[") {
		idx := strings.LastIndex(addr, "]:")
		if idx == -1 {
			return 0, ""
		}
		port, _ := strconv.Atoi(addr[idx+2:])
		return port, addr[:idx+1]
	}

	// Handle IPv4 format addr:port
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return 0, ""
	}
	port, _ := strconv.Atoi(addr[idx+1:])
	return port, addr[:idx]
}

// ScanUDP scans for UDP listening ports
func (s *Scanner) ScanUDP() ([]PortInfo, error) {
	cmd := exec.Command("ss", "-ulnp")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	ports, err := s.parseSSOutput(string(output))
	if err != nil {
		return nil, err
	}

	// Set protocol to UDP
	for i := range ports {
		ports[i].Protocol = "udp"
		ports[i].Protected = config.IsProtectedPort(ports[i].Port)
	}

	return ports, nil
}

// GetProcessByPort returns process info for a specific port
func (s *Scanner) GetProcessByPort(port int) (*PortInfo, error) {
	// Try to read from /proc/net/tcp
	info, err := s.findPortInProc(port)
	if err == nil {
		return info, nil
	}

	// Fallback to ss
	ports, err := s.ScanPorts()
	if err != nil {
		return nil, err
	}

	for _, p := range ports {
		if p.Port == port {
			return &p, nil
		}
	}

	return nil, fmt.Errorf("port %d not found", port)
}

// findPortInProc reads /proc/net/tcp to find port info
func (s *Scanner) findPortInProc(targetPort int) (*PortInfo, error) {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse local address (field 1)
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		portHex := parts[1]
		port, _ := strconv.ParseInt(portHex, 16, 32)

		if int(port) == targetPort {
			// Found the port, try to get process info
			inode := fields[9]
			process, pid := s.findProcessByInode(inode)

			return &PortInfo{
				Port:      targetPort,
				Protocol:  "tcp",
				Process:   process,
				PID:       pid,
				State:     "LISTEN",
				Protected: config.IsProtectedPort(targetPort),
			}, nil
		}
	}

	return nil, fmt.Errorf("port not found in /proc/net/tcp")
}

// findProcessByInode finds process name and PID by socket inode
func (s *Scanner) findProcessByInode(inode string) (string, int) {
	// This is a simplified implementation
	// In production, you'd walk /proc/*/fd/ to find the process
	procDir, err := os.Open("/proc")
	if err != nil {
		return "", 0
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return "", 0
	}

	socketLink := fmt.Sprintf("socket:[%s]", inode)

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}

			if link == socketLink {
				// Found the process, get its name
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				return strings.TrimSpace(string(comm)), pid
			}
		}
	}

	return "", 0
}

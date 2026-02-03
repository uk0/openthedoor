package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Firewalld implements the Backend interface for firewalld
type Firewalld struct{}

// NewFirewalld creates a new Firewalld backend
func NewFirewalld() *Firewalld {
	return &Firewalld{}
}

// Name returns the backend name
func (f *Firewalld) Name() string {
	return "firewalld"
}

// IsAvailable checks if firewalld is available and running
func (f *Firewalld) IsAvailable() bool {
	if !commandExists("firewall-cmd") {
		return false
	}
	// Check if firewalld is running
	output, err := runCommand("firewall-cmd", "--state")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == "running"
}

// BlockPort blocks a port, allowing only specified IPs and localhost
// Strategy: Remove port from zone (default deny), then add accept rules for allowed IPs only
func (f *Firewalld) BlockPort(port int, protocol string, allowedIPs []string) error {
	// Remove existing rules first
	f.RemoveRule(port, protocol)

	// Get default zone
	zoneOutput, _ := runCommand("firewall-cmd", "--get-default-zone")
	zone := strings.TrimSpace(zoneOutput)
	if zone == "" {
		zone = "public"
	}

	// Remove port from zone's allowed ports (ensure default deny)
	portSpec := fmt.Sprintf("%d/%s", port, protocol)
	runCommand("firewall-cmd", "--permanent", "--zone="+zone, "--remove-port="+portSpec)

	// Add accept rule for localhost
	localhostRule := fmt.Sprintf(`rule family="ipv4" source address="127.0.0.1" port port="%d" protocol="%s" accept`, port, protocol)
	_, err := runCommand("firewall-cmd", "--permanent", "--add-rich-rule="+localhostRule)
	if err != nil {
		return fmt.Errorf("failed to add localhost rule: %v", err)
	}

	// Add accept rules for specified IPs (NO reject rule - rely on default deny)
	for _, ip := range allowedIPs {
		allowRule := fmt.Sprintf(`rule family="ipv4" source address="%s" port port="%d" protocol="%s" accept`, ip, port, protocol)
		_, err = runCommand("firewall-cmd", "--permanent", "--add-rich-rule="+allowRule)
		if err != nil {
			return fmt.Errorf("failed to add allow rule for %s: %v", ip, err)
		}
	}

	// Reload to apply changes
	_, err = runCommand("firewall-cmd", "--reload")
	if err != nil {
		return fmt.Errorf("failed to reload firewalld: %v", err)
	}

	return nil
}

// AllowIP adds an IP to the allowed list for a port
func (f *Firewalld) AllowIP(port int, protocol string, ip string) error {
	allowRule := fmt.Sprintf(`rule family="ipv4" source address="%s" port port="%d" protocol="%s" accept`, ip, port, protocol)
	_, err := runCommand("firewall-cmd", "--permanent", "--add-rich-rule="+allowRule)
	if err != nil {
		return fmt.Errorf("failed to add allow rule: %v", err)
	}

	// Reload to apply changes
	_, err = runCommand("firewall-cmd", "--reload")
	if err != nil {
		return fmt.Errorf("failed to reload firewalld: %v", err)
	}

	return nil
}

// RemoveRule removes all rules for a port (unblock - restore normal access)
func (f *Firewalld) RemoveRule(port int, protocol string) error {
	// Get default zone
	zoneOutput, _ := runCommand("firewall-cmd", "--get-default-zone")
	zone := strings.TrimSpace(zoneOutput)
	if zone == "" {
		zone = "public"
	}

	// Remove rich rules for this port
	output, err := runCommand("firewall-cmd", "--list-rich-rules")
	if err == nil {
		portPattern := fmt.Sprintf(`port="%d"`, port)
		lines := strings.Split(output, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, portPattern) && strings.Contains(line, protocol) {
				runCommand("firewall-cmd", "--permanent", "--remove-rich-rule="+line)
			}
		}
	}

	// Reload to apply changes
	runCommand("firewall-cmd", "--reload")

	return nil
}

// ListRules returns all rules managed by fwctl
func (f *Firewalld) ListRules() ([]Rule, error) {
	output, err := runCommand("firewall-cmd", "--list-rich-rules")
	if err != nil {
		return []Rule{}, nil
	}

	return f.parseRules(output), nil
}

// GetStatus returns the firewall status
func (f *Firewalld) GetStatus() (Status, error) {
	status := Status{
		BackendName: f.Name(),
	}

	output, err := runCommand("firewall-cmd", "--state")
	if err != nil {
		return status, err
	}

	status.Active = strings.TrimSpace(output) == "running"

	rules, _ := f.ListRules()
	status.RuleCount = len(rules)

	return status, nil
}

// parseRules parses firewalld rich rules into Rule structs
// New strategy: ports with accept rules (but not in zone's allowed ports) are considered BLOCKED with whitelist
func (f *Firewalld) parseRules(output string) []Rule {
	lines := strings.Split(output, "\n")
	portRules := make(map[int]*Rule)

	// Match rich rules like: rule family="ipv4" source address="1.2.3.4" port port="3306" protocol="tcp" accept
	portRe := regexp.MustCompile(`port="(\d+)"`)
	protoRe := regexp.MustCompile(`protocol="(tcp|udp)"`)
	sourceRe := regexp.MustCompile(`source address="([^"]+)"`)

	// Get zone's allowed ports
	zoneOutput, _ := runCommand("firewall-cmd", "--get-default-zone")
	zone := strings.TrimSpace(zoneOutput)
	if zone == "" {
		zone = "public"
	}
	allowedPortsOutput, _ := runCommand("firewall-cmd", "--zone="+zone, "--list-ports")
	allowedPorts := make(map[int]bool)
	for _, p := range strings.Fields(allowedPortsOutput) {
		// Parse "3306/tcp" format
		parts := strings.Split(p, "/")
		if len(parts) >= 1 {
			if port, err := strconv.Atoi(parts[0]); err == nil {
				allowedPorts[port] = true
			}
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "accept") {
			continue
		}

		portMatch := portRe.FindStringSubmatch(line)
		if len(portMatch) < 2 {
			continue
		}
		port, _ := strconv.Atoi(portMatch[1])

		protocol := "tcp"
		if protoMatch := protoRe.FindStringSubmatch(line); len(protoMatch) >= 2 {
			protocol = protoMatch[1]
		}

		// If port is in zone's allowed list, it's not blocked by us
		if allowedPorts[port] {
			continue
		}

		if _, exists := portRules[port]; !exists {
			portRules[port] = &Rule{
				Port:       port,
				Protocol:   protocol,
				AllowedIPs: []string{},
				Action:     "BLOCK", // Port not in allowed list = blocked, with whitelist
			}
		}

		// Extract allowed IPs (exclude localhost)
		if sourceMatch := sourceRe.FindStringSubmatch(line); len(sourceMatch) >= 2 {
			ip := sourceMatch[1]
			if ip != "127.0.0.1" {
				portRules[port].AllowedIPs = append(portRules[port].AllowedIPs, ip)
			}
		}
	}

	var rules []Rule
	for _, rule := range portRules {
		rules = append(rules, *rule)
	}

	return rules
}

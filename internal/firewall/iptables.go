package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"fwctl/internal/config"
)

// IPTables implements the Backend interface for iptables
type IPTables struct{}

// NewIPTables creates a new IPTables backend
func NewIPTables() *IPTables {
	return &IPTables{}
}

// Name returns the backend name
func (i *IPTables) Name() string {
	return "iptables"
}

// IsAvailable checks if iptables is available
func (i *IPTables) IsAvailable() bool {
	return commandExists("iptables")
}

// BlockPort blocks a port at the raw table PREROUTING (before NAT/Docker)
func (i *IPTables) BlockPort(port int, protocol string, allowedIPs []string) error {
	// Ensure our chain exists in raw table
	if err := i.ensureChain(); err != nil {
		return err
	}

	// Remove existing rules for this port first
	i.RemoveRule(port, protocol)

	// Allow localhost (traffic from lo interface)
	if err := i.addRule("-A", config.ChainName,
		"-p", protocol, "--dport", strconv.Itoa(port),
		"-i", "lo", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add localhost rule: %v", err)
	}

	// Allow specified IPs
	for _, ip := range allowedIPs {
		if err := i.addRule("-A", config.ChainName,
			"-p", protocol, "--dport", strconv.Itoa(port),
			"-s", ip, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("failed to add allow rule for %s: %v", ip, err)
		}
	}

	// Drop all other traffic to this port
	if err := i.addRule("-A", config.ChainName,
		"-p", protocol, "--dport", strconv.Itoa(port),
		"-j", "DROP"); err != nil {
		return fmt.Errorf("failed to add drop rule: %v", err)
	}

	return nil
}

// addRule adds an iptables rule, trying with comment first, then without for older versions
func (i *IPTables) addRule(args ...string) error {
	// Try with comment first (newer iptables)
	fullArgs := append([]string{"-t", "raw"}, args...)
	fullArgs = append(fullArgs, "-m", "comment", "--comment", config.RuleComment)

	_, err := runCommand("iptables", fullArgs...)
	if err == nil {
		return nil
	}

	// Fallback: try without comment module (older iptables like v1.4.21)
	fullArgs = append([]string{"-t", "raw"}, args...)
	_, err = runCommand("iptables", fullArgs...)
	return err
}

// AllowIP adds an IP to the allowed list for a port
func (i *IPTables) AllowIP(port int, protocol string, ip string) error {
	if err := i.ensureChain(); err != nil {
		return err
	}

	// Find the DROP rule position and insert before it
	output, err := runCommand("iptables", "-t", "raw", "-L", config.ChainName, "-n", "--line-numbers")
	if err != nil {
		return err
	}

	dropLineNum := i.findDropRuleLineNumber(output, port, protocol)
	if dropLineNum == 0 {
		return fmt.Errorf("port %d is not blocked, use 'block' command first", port)
	}

	// Insert before DROP rule (try with comment first, then without)
	args := []string{"-I", config.ChainName, strconv.Itoa(dropLineNum),
		"-p", protocol, "--dport", strconv.Itoa(port),
		"-s", ip, "-j", "ACCEPT"}

	return i.addRule(args...)
}

// RemoveRule removes all rules for a port
func (i *IPTables) RemoveRule(port int, protocol string) error {
	for {
		output, err := runCommand("iptables", "-t", "raw", "-L", config.ChainName, "-n", "--line-numbers")
		if err != nil {
			return nil
		}

		lineNum := i.findAnyRuleLineNumber(output, port, protocol)
		if lineNum == 0 {
			break
		}

		_, err = runCommand("iptables", "-t", "raw", "-D", config.ChainName, strconv.Itoa(lineNum))
		if err != nil {
			return err
		}
	}

	return nil
}

// ListRules returns all rules managed by fwctl
func (i *IPTables) ListRules() ([]Rule, error) {
	output, err := runCommand("iptables", "-t", "raw", "-L", config.ChainName, "-n", "-v")
	if err != nil {
		return []Rule{}, nil
	}

	return i.parseRules(output), nil
}

// GetStatus returns the firewall status
func (i *IPTables) GetStatus() (Status, error) {
	status := Status{
		BackendName: i.Name(),
	}

	output, err := runCommand("iptables", "-L", "-n")
	if err != nil {
		return status, err
	}

	status.Active = len(output) > 0

	rules, _ := i.ListRules()
	status.RuleCount = len(rules)

	return status, nil
}

// ensureChain creates the FWCTL chain in raw table if it doesn't exist
func (i *IPTables) ensureChain() error {
	// Try to create the chain in raw table
	runCommand("iptables", "-t", "raw", "-N", config.ChainName)

	// Ensure the chain is referenced from PREROUTING in raw table
	output, err := runCommand("iptables", "-t", "raw", "-L", "PREROUTING", "-n")
	if err != nil {
		return err
	}

	if !strings.Contains(output, config.ChainName) {
		_, err = runCommand("iptables", "-t", "raw", "-I", "PREROUTING", "-j", config.ChainName)
		if err != nil {
			return fmt.Errorf("failed to add chain to PREROUTING: %v", err)
		}
	}

	return nil
}

// findDropRuleLineNumber finds the line number of the DROP rule for a port
func (i *IPTables) findDropRuleLineNumber(output string, port int, protocol string) int {
	lines := strings.Split(output, "\n")
	portStr := strconv.Itoa(port)
	re := regexp.MustCompile(`^(\d+)\s+DROP\s+` + protocol + `\s+.*dpt:` + portStr)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			num, _ := strconv.Atoi(matches[1])
			return num
		}
	}
	return 0
}

// findAnyRuleLineNumber finds any rule line number for a port
func (i *IPTables) findAnyRuleLineNumber(output string, port int, protocol string) int {
	lines := strings.Split(output, "\n")
	portStr := strconv.Itoa(port)
	re := regexp.MustCompile(`^(\d+)\s+\w+\s+` + protocol + `\s+.*dpt:` + portStr)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			num, _ := strconv.Atoi(matches[1])
			return num
		}
	}
	return 0
}

// parseRules parses iptables output into Rule structs
func (i *IPTables) parseRules(output string) []Rule {
	var rules []Rule
	lines := strings.Split(output, "\n")

	// Format: pkts bytes target prot opt in out source destination [options]
	// Example: 82  7429 ACCEPT tcp  --  *  *  154.21.81.194  0.0.0.0/0  tcp dpt:23222
	portRules := make(map[int]*Rule)

	for _, line := range lines {
		// Skip header and empty lines
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "Chain") ||
			strings.HasPrefix(strings.TrimSpace(line), "pkts") {
			continue
		}

		// Extract port from dpt:PORT
		portRe := regexp.MustCompile(`dpt:(\d+)`)
		portMatch := portRe.FindStringSubmatch(line)
		if len(portMatch) < 2 {
			continue
		}
		port, _ := strconv.Atoi(portMatch[1])

		// Parse fields
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		action := fields[2]   // ACCEPT, DROP, REJECT
		protocol := fields[3] // tcp, udp
		source := fields[7]   // source IP

		if _, exists := portRules[port]; !exists {
			portRules[port] = &Rule{
				Port:       port,
				Protocol:   protocol,
				AllowedIPs: []string{},
				Action:     "BLOCK",
			}
		}

		// Collect allowed IPs (ACCEPT rules with specific source)
		if action == "ACCEPT" && source != "0.0.0.0/0" && source != "anywhere" {
			portRules[port].AllowedIPs = append(portRules[port].AllowedIPs, source)
		}
	}

	for _, rule := range portRules {
		rules = append(rules, *rule)
	}

	return rules
}

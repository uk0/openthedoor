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

// ============================================================================
// Hex Filter Implementation (Experimental)
// ============================================================================

// ensureHexChain creates the FWCTL_HEX chain if it doesn't exist
func (i *IPTables) ensureHexChain() error {
	// Try to create the chain in raw table
	runCommand("iptables", "-t", "raw", "-N", config.HexChainName)

	// Ensure the chain is referenced from PREROUTING
	output, err := runCommand("iptables", "-t", "raw", "-L", "PREROUTING", "-n")
	if err != nil {
		return err
	}

	if !strings.Contains(output, config.HexChainName) {
		_, err = runCommand("iptables", "-t", "raw", "-I", "PREROUTING", "-j", config.HexChainName)
		if err != nil {
			return fmt.Errorf("failed to add hex chain to PREROUTING: %v", err)
		}
	}

	return nil
}

// AddHexFilter adds a hex pattern filter rule
func (i *IPTables) AddHexFilter(pattern string, port int, protocol string, comment string) error {
	if err := i.ensureHexChain(); err != nil {
		return err
	}

	// Build iptables command
	args := []string{"-A", config.HexChainName}

	// Add protocol and port if specified
	if protocol != "" {
		args = append(args, "-p", protocol)
	}
	if port > 0 {
		if protocol == "" {
			args = append(args, "-p", "tcp") // default to tcp if port specified
		}
		args = append(args, "--dport", strconv.Itoa(port))
	}

	// Add string match with hex pattern
	args = append(args, "-m", "string", "--algo", "bm", "--hex-string", pattern, "-j", "DROP")

	// Try with comment first, fallback without
	fullArgs := append([]string{"-t", "raw"}, args...)
	if comment != "" {
		fullArgsWithComment := append(fullArgs, "-m", "comment", "--comment", comment)
		_, err := runCommand("iptables", fullArgsWithComment...)
		if err == nil {
			return nil
		}
	}

	_, err := runCommand("iptables", fullArgs...)
	return err
}

// RemoveHexFilter removes a hex filter rule by line number or pattern
func (i *IPTables) RemoveHexFilter(idOrPattern string) error {
	// Try to parse as line number first
	if lineNum, err := strconv.Atoi(idOrPattern); err == nil {
		_, err := runCommand("iptables", "-t", "raw", "-D", config.HexChainName, strconv.Itoa(lineNum))
		return err
	}

	// Otherwise, find and remove by pattern
	output, err := runCommand("iptables", "-t", "raw", "-L", config.HexChainName, "-n", "--line-numbers")
	if err != nil {
		return err
	}

	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- { // reverse order to preserve line numbers
		line := lines[i]
		if strings.Contains(line, idOrPattern) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if num, err := strconv.Atoi(fields[0]); err == nil {
					runCommand("iptables", "-t", "raw", "-D", config.HexChainName, strconv.Itoa(num))
				}
			}
		}
	}

	return nil
}

// ListHexFilters returns all hex filter rules
func (i *IPTables) ListHexFilters() ([]HexRule, error) {
	output, err := runCommand("iptables", "-t", "raw", "-L", config.HexChainName, "-n", "-v", "--line-numbers")
	if err != nil {
		return []HexRule{}, nil
	}

	return i.parseHexRules(output), nil
}

// parseHexRules parses iptables output into HexRule structs
func (i *IPTables) parseHexRules(output string) []HexRule {
	var rules []HexRule
	lines := strings.Split(output, "\n")

	// Match hex-string pattern
	hexRe := regexp.MustCompile(`STRING match\s+"([^"]+)"`)
	portRe := regexp.MustCompile(`dpt:(\d+)`)
	commentRe := regexp.MustCompile(`/\*\s*([^*]+)\s*\*/`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "pkts") {
			continue
		}

		// Must be a DROP rule with hex string
		if !strings.Contains(line, "DROP") || !strings.Contains(line, "STRING match") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Parse line number
		lineNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		rule := HexRule{
			ID:       lineNum,
			Protocol: fields[4], // protocol field
		}

		// Extract hex pattern
		if match := hexRe.FindStringSubmatch(line); len(match) >= 2 {
			rule.Pattern = match[1]
		}

		// Extract port if present
		if match := portRe.FindStringSubmatch(line); len(match) >= 2 {
			rule.Port, _ = strconv.Atoi(match[1])
		}

		// Extract comment if present
		if match := commentRe.FindStringSubmatch(line); len(match) >= 2 {
			rule.Comment = strings.TrimSpace(match[1])
		}

		if rule.Pattern != "" {
			rules = append(rules, rule)
		}
	}

	return rules
}

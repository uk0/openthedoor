package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// UFW implements the Backend interface for UFW
type UFW struct{}

// NewUFW creates a new UFW backend
func NewUFW() *UFW {
	return &UFW{}
}

// Name returns the backend name
func (u *UFW) Name() string {
	return "ufw"
}

// IsAvailable checks if UFW is available
func (u *UFW) IsAvailable() bool {
	if !commandExists("ufw") {
		return false
	}
	// Check if UFW is enabled
	output, err := runCommand("ufw", "status")
	if err != nil {
		return false
	}
	return strings.Contains(output, "Status: active")
}

// BlockPort blocks a port, allowing only specified IPs and localhost
func (u *UFW) BlockPort(port int, protocol string, allowedIPs []string) error {
	// Remove existing fwctl rules first
	u.RemoveRule(port, protocol)

	// Allow localhost first
	// ufw allow from 127.0.0.1 to any port 3306 proto tcp
	_, err := runCommand("ufw", "allow", "from", "127.0.0.1", "to", "any", "port", strconv.Itoa(port), "proto", protocol)
	if err != nil {
		return fmt.Errorf("failed to allow localhost: %v", err)
	}

	// Allow specified IPs
	for _, ip := range allowedIPs {
		_, err = runCommand("ufw", "allow", "from", ip, "to", "any", "port", strconv.Itoa(port), "proto", protocol)
		if err != nil {
			return fmt.Errorf("failed to allow IP %s: %v", ip, err)
		}
	}

	// Deny the port for everyone else (this rule comes last)
	// ufw deny 3306/tcp
	_, err = runCommand("ufw", "deny", fmt.Sprintf("%d/%s", port, protocol))
	if err != nil {
		return fmt.Errorf("failed to deny port: %v", err)
	}

	return nil
}

// AllowIP adds an IP to the allowed list for a port
func (u *UFW) AllowIP(port int, protocol string, ip string) error {
	// Insert allow rule (UFW processes rules in order, so we need to insert before deny)
	// First check if port is blocked
	rules, _ := u.ListRules()
	isBlocked := false
	for _, r := range rules {
		if r.Port == port && r.Action == "BLOCK" {
			isBlocked = true
			break
		}
	}

	if !isBlocked {
		return fmt.Errorf("port %d is not blocked, use 'block' command first", port)
	}

	// Get the deny rule number and insert before it
	output, _ := runCommand("ufw", "status", "numbered")
	denyRuleNum := u.findDenyRuleNumber(output, port, protocol)

	if denyRuleNum > 0 {
		// Insert allow rule before deny rule
		_, err := runCommand("ufw", "insert", strconv.Itoa(denyRuleNum),
			"allow", "from", ip, "to", "any", "port", strconv.Itoa(port), "proto", protocol)
		if err != nil {
			return fmt.Errorf("failed to allow IP %s: %v", ip, err)
		}
	} else {
		// No deny rule found, just add allow
		_, err := runCommand("ufw", "allow", "from", ip, "to", "any", "port", strconv.Itoa(port), "proto", protocol)
		if err != nil {
			return fmt.Errorf("failed to allow IP %s: %v", ip, err)
		}
	}

	return nil
}

// RemoveRule removes all fwctl rules for a port
func (u *UFW) RemoveRule(port int, protocol string) error {
	// Delete deny rule first
	portSpec := fmt.Sprintf("%d/%s", port, protocol)
	runCommand("ufw", "delete", "deny", portSpec)

	// Delete allow rules for specific IPs (in reverse order)
	for {
		output, err := runCommand("ufw", "status", "numbered")
		if err != nil {
			break
		}

		ruleNum := u.findPortAllowRuleNumber(output, port, protocol)
		if ruleNum == 0 {
			break
		}

		_, err = runCommand("ufw", "--force", "delete", strconv.Itoa(ruleNum))
		if err != nil {
			break
		}
	}

	return nil
}

// ListRules returns all rules managed by fwctl (only blocked ports)
func (u *UFW) ListRules() ([]Rule, error) {
	output, err := runCommand("ufw", "status")
	if err != nil {
		return nil, err
	}

	return u.parseRules(output), nil
}

// GetStatus returns the firewall status
func (u *UFW) GetStatus() (Status, error) {
	status := Status{
		BackendName: u.Name(),
	}

	output, err := runCommand("ufw", "status")
	if err != nil {
		return status, err
	}

	status.Active = strings.Contains(output, "Status: active")

	rules, _ := u.ListRules()
	status.RuleCount = len(rules)

	return status, nil
}

// findDenyRuleNumber finds the rule number of DENY rule for a port
func (u *UFW) findDenyRuleNumber(output string, port int, protocol string) int {
	lines := strings.Split(output, "\n")
	portSpec := fmt.Sprintf("%d/%s", port, protocol)

	// Match lines like "[ 5] 3306/tcp                   DENY IN     Anywhere"
	re := regexp.MustCompile(`\[\s*(\d+)\]\s+` + regexp.QuoteMeta(portSpec) + `\s+DENY`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			num, _ := strconv.Atoi(matches[1])
			return num
		}
	}
	return 0
}

// findPortAllowRuleNumber finds any ALLOW rule number for a port with specific IP
func (u *UFW) findPortAllowRuleNumber(output string, port int, protocol string) int {
	lines := strings.Split(output, "\n")
	portStr := strconv.Itoa(port)

	// Match lines like "[ 3] 3306/tcp                   ALLOW IN    192.168.1.1"
	// or "[ 3] 3306                       ALLOW IN    192.168.1.1"
	re := regexp.MustCompile(`\[\s*(\d+)\]\s+` + portStr + `(/` + protocol + `)?\s+ALLOW\s+IN\s+(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			num, _ := strconv.Atoi(matches[1])
			return num
		}
	}
	return 0
}

// parseRules parses UFW status output into Rule structs
// Only returns ports that have DENY rules (blocked by fwctl)
func (u *UFW) parseRules(output string) []Rule {
	lines := strings.Split(output, "\n")

	// First pass: find all DENY rules (blocked ports)
	// Match: "3306/tcp                   DENY        Anywhere"
	denyRe := regexp.MustCompile(`^(\d+)/(tcp|udp)\s+DENY\s+`)

	blockedPorts := make(map[int]*Rule)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := denyRe.FindStringSubmatch(line)
		if len(matches) >= 3 {
			port, _ := strconv.Atoi(matches[1])
			protocol := matches[2]
			blockedPorts[port] = &Rule{
				Port:       port,
				Protocol:   protocol,
				AllowedIPs: []string{},
				Action:     "BLOCK",
			}
		}
	}

	// Second pass: find ALLOW rules for blocked ports (whitelist IPs)
	// Match: "3306/tcp                   ALLOW       192.168.1.1"
	// or "3306                       ALLOW       192.168.1.1"
	allowRe := regexp.MustCompile(`^(\d+)(?:/(tcp|udp))?\s+ALLOW\s+(?:IN\s+)?(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := allowRe.FindStringSubmatch(line)
		if len(matches) >= 4 {
			port, _ := strconv.Atoi(matches[1])
			ip := matches[3]

			// Only add if this port is blocked and IP is not localhost
			if rule, exists := blockedPorts[port]; exists && ip != "127.0.0.1" {
				rule.AllowedIPs = append(rule.AllowedIPs, ip)
			}
		}
	}

	var rules []Rule
	for _, rule := range blockedPorts {
		rules = append(rules, *rule)
	}

	return rules
}

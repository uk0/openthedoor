package config

// ProtectionLevel defines the protection level for a process
type ProtectionLevel int

const (
	// ProtectionNone - no protection
	ProtectionNone ProtectionLevel = iota
	// ProtectionWarn - yellow warning, can block
	ProtectionWarn
	// ProtectionStrict - red warning, requires whitelist IP to block
	ProtectionStrict
)

// ProcessProtection defines protection rules by process name
var ProcessProtection = map[string]ProtectionLevel{
	"sshd":  ProtectionStrict, // RED - cannot block without whitelist
	"nginx": ProtectionWarn,   // YELLOW - warning only
	"httpd": ProtectionWarn,   // YELLOW - Apache
	"apache2": ProtectionWarn, // YELLOW - Apache on Debian
}

// ProcessDescription provides human-readable descriptions
var ProcessDescription = map[string]string{
	"sshd":    "SSH Server",
	"nginx":   "Nginx Web Server",
	"httpd":   "Apache Web Server",
	"apache2": "Apache Web Server",
}

// GetProtectionLevel returns the protection level for a process
func GetProtectionLevel(processName string) ProtectionLevel {
	if level, ok := ProcessProtection[processName]; ok {
		return level
	}
	return ProtectionNone
}

// GetProcessDescription returns description for a process
func GetProcessDescription(processName string) string {
	if desc, ok := ProcessDescription[processName]; ok {
		return desc
	}
	return ""
}

// IsStrictlyProtected checks if process requires whitelist to block
func IsStrictlyProtected(processName string) bool {
	return GetProtectionLevel(processName) == ProtectionStrict
}

// IsProtectedPort checks if a port is protected (legacy, for compatibility)
func IsProtectedPort(port int) bool {
	return port == 22 || port == 80 || port == 443
}

// GetProtectedPortName returns the service name for a protected port (legacy)
func GetProtectedPortName(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 80:
		return "HTTP (Nginx)"
	case 443:
		return "HTTPS (Nginx)"
	}
	return ""
}

// ChainName is the iptables chain name used by fwctl
const ChainName = "FWCTL"

// HexChainName is the iptables chain name for hex filters
const HexChainName = "FWCTL_HEX"

// RuleComment is used to identify rules created by fwctl
const RuleComment = "fwctl-managed"

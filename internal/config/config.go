package config

// ProtectedPorts defines ports that should not be blocked without --force
var ProtectedPorts = map[int]string{
	22:  "SSH",
	80:  "HTTP (Nginx)",
	443: "HTTPS (Nginx)",
}

// IsProtectedPort checks if a port is protected
func IsProtectedPort(port int) bool {
	_, ok := ProtectedPorts[port]
	return ok
}

// GetProtectedPortName returns the service name for a protected port
func GetProtectedPortName(port int) string {
	if name, ok := ProtectedPorts[port]; ok {
		return name
	}
	return ""
}

// ChainName is the iptables chain name used by fwctl
const ChainName = "FWCTL"

// RuleComment is used to identify rules created by fwctl
const RuleComment = "fwctl-managed"

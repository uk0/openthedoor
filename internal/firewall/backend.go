package firewall

import "fmt"

// Rule represents a firewall rule
type Rule struct {
	Port       int
	Protocol   string
	AllowedIPs []string
	Action     string // ACCEPT, DROP, REJECT
}

// HexRule represents a hex filter rule (experimental)
type HexRule struct {
	ID       int
	Pattern  string // hex pattern like "|de ad be ef|"
	Port     int    // 0 means all ports
	Protocol string // tcp, udp, or empty for all
	Comment  string
}

// Status represents firewall status
type Status struct {
	Active       bool
	BackendName  string
	RuleCount    int
	HexRuleCount int
}

// Backend defines the interface for firewall backends
type Backend interface {
	// Name returns the backend name
	Name() string

	// IsAvailable checks if this backend is available on the system
	IsAvailable() bool

	// BlockPort blocks a port, only allowing specified IPs (and localhost)
	BlockPort(port int, protocol string, allowedIPs []string) error

	// AllowIP adds an IP to the allowed list for a port
	AllowIP(port int, protocol string, ip string) error

	// RemoveRule removes blocking rules for a port
	RemoveRule(port int, protocol string) error

	// ListRules returns all rules managed by fwctl
	ListRules() ([]Rule, error)

	// GetStatus returns the firewall status
	GetStatus() (Status, error)
}

// HexFilterBackend defines interface for hex filtering (iptables only)
type HexFilterBackend interface {
	// AddHexFilter adds a hex pattern filter rule (experimental)
	AddHexFilter(pattern string, port int, protocol string, comment string) error

	// RemoveHexFilter removes a hex filter rule by ID or pattern
	RemoveHexFilter(idOrPattern string) error

	// ListHexFilters returns all hex filter rules
	ListHexFilters() ([]HexRule, error)
}

// ErrProtectedPort is returned when trying to block a protected port without force
type ErrProtectedPort struct {
	Port int
}

func (e ErrProtectedPort) Error() string {
	return fmt.Sprintf("port %d is protected (SSH/Nginx), use --force to override", e.Port)
}

// ErrBackendNotAvailable is returned when the backend is not available
type ErrBackendNotAvailable struct {
	Name string
}

func (e ErrBackendNotAvailable) Error() string {
	return fmt.Sprintf("firewall backend '%s' is not available on this system", e.Name)
}

// ErrHexFilterNotSupported is returned when hex filter is not supported
type ErrHexFilterNotSupported struct {
	Backend string
}

func (e ErrHexFilterNotSupported) Error() string {
	return fmt.Sprintf("hex filter is only supported by iptables backend, current: %s", e.Backend)
}

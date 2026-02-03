package firewall

import (
	"os/exec"
	"strings"
)

// Detect returns the best available firewall backend
// If Docker is running, use iptables for best compatibility
// Otherwise, use the first available backend (firewalld > ufw > iptables)
func Detect() Backend {
	// Check if Docker is running
	if IsDockerRunning() {
		iptables := NewIPTables()
		if iptables.IsAvailable() {
			return iptables
		}
	}

	// No Docker, use priority order: firewalld > ufw > iptables
	backends := []func() Backend{
		func() Backend { return NewFirewalld() },
		func() Backend { return NewUFW() },
		func() Backend { return NewIPTables() },
	}

	for _, create := range backends {
		backend := create()
		if backend.IsAvailable() {
			return backend
		}
	}
	return nil
}

// IsDockerRunning checks if Docker daemon is running (exported)
func IsDockerRunning() bool {
	// Check if docker command exists
	if !commandExists("docker") {
		return false
	}

	// Check if docker daemon is running
	output, err := runCommand("docker", "info")
	if err != nil {
		return false
	}

	return strings.Contains(output, "Server Version")
}

// GetBackend returns a specific backend by name
func GetBackend(name string) Backend {
	switch name {
	case "iptables":
		return NewIPTables()
	case "ufw":
		return NewUFW()
	case "firewalld":
		return NewFirewalld()
	default:
		return nil
	}
}

// ListAvailable returns all available backends
func ListAvailable() []Backend {
	var available []Backend

	backends := []func() Backend{
		func() Backend { return NewFirewalld() },
		func() Backend { return NewUFW() },
		func() Backend { return NewIPTables() },
	}

	for _, create := range backends {
		backend := create()
		if backend.IsAvailable() {
			available = append(available, backend)
		}
	}
	return available
}

// commandExists checks if a command exists in PATH
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runCommand executes a command and returns output
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

package ui

import (
	"fmt"
	"strings"

	"fwctl/internal/config"
	"fwctl/internal/firewall"
	"fwctl/internal/scanner"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	selectedStyle   = lipgloss.NewStyle().Background(lipgloss.Color("240")).Bold(true)
	openStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))  // Green
	blockedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // Red
	protectedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("226")) // Yellow
	headerStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	helpStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type PortItem struct {
	Port      int
	Protocol  string
	Process   string
	PID       int
	Blocked   bool
	Protected bool
	Note      string
	AllowedIPs []string
}

type Model struct {
	ports    []PortItem
	cursor   int
	backend  firewall.Backend
	message  string
	quitting bool
}

func NewModel(ports []scanner.PortInfo, rules []firewall.Rule, backend firewall.Backend) Model {
	// Build blocked ports map
	blockedPorts := make(map[int][]string)
	for _, r := range rules {
		if r.Action == "BLOCK" {
			blockedPorts[r.Port] = r.AllowedIPs
		}
	}

	// Convert to PortItems
	items := make([]PortItem, len(ports))
	for i, p := range ports {
		blocked := false
		var allowedIPs []string
		if ips, ok := blockedPorts[p.Port]; ok {
			blocked = true
			allowedIPs = ips
		}

		note := ""
		protected := config.IsProtectedPort(p.Port)
		if protected {
			note = config.GetProtectedPortName(p.Port)
		}

		items[i] = PortItem{
			Port:       p.Port,
			Protocol:   p.Protocol,
			Process:    p.Process,
			PID:        p.PID,
			Blocked:    blocked,
			Protected:  protected,
			Note:       note,
			AllowedIPs: allowedIPs,
		}
	}

	return Model{
		ports:   items,
		cursor:  0,
		backend: backend,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.ports)-1 {
				m.cursor++
			}

		case " ": // Spacebar to toggle
			if len(m.ports) > 0 {
				port := &m.ports[m.cursor]

				// Check if protected
				if port.Protected && !port.Blocked {
					m.message = fmt.Sprintf("⚠ Port %d (%s) is protected and cannot be blocked", port.Port, port.Note)
					return m, nil
				}

				if port.Blocked {
					// Unblock
					err := m.backend.RemoveRule(port.Port, port.Protocol)
					if err != nil {
						m.message = fmt.Sprintf("✗ Failed to unblock port %d: %v", port.Port, err)
					} else {
						port.Blocked = false
						port.AllowedIPs = nil
						m.message = fmt.Sprintf("✓ Port %d unblocked", port.Port)
					}
				} else {
					// Block (localhost only)
					err := m.backend.BlockPort(port.Port, port.Protocol, nil)
					if err != nil {
						m.message = fmt.Sprintf("✗ Failed to block port %d: %v", port.Port, err)
					} else {
						port.Blocked = true
						m.message = fmt.Sprintf("✓ Port %d blocked (localhost only)", port.Port)
					}
				}
			}
		}
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("  ◆ Interactive Port Manager"))
	b.WriteString(fmt.Sprintf(" [Backend: %s]\n", m.backend.Name()))
	b.WriteString("  " + strings.Repeat("─", 70) + "\n\n")

	// Column headers
	header := fmt.Sprintf("  %-6s %-6s %-14s %-8s %-10s %s",
		"PORT", "PROTO", "PROCESS", "PID", "STATUS", "NOTE")
	b.WriteString(headerStyle.Render(header) + "\n")
	b.WriteString(fmt.Sprintf("  %-6s %-6s %-14s %-8s %-10s %s\n",
		"────", "─────", "───────", "───", "──────", "────"))

	// Port list
	for i, port := range m.ports {
		// Status
		status := openStyle.Render("● OPEN")
		if port.Blocked {
			status = blockedStyle.Render("● BLOCKED")
		}

		// Note
		note := port.Note
		if port.Blocked && len(port.AllowedIPs) > 0 {
			note = "Allow: " + strings.Join(port.AllowedIPs, ", ")
		}
		if port.Protected && !port.Blocked {
			note = protectedStyle.Render(note)
		}

		// Format row
		row := fmt.Sprintf("  %-6d %-6s %-14s %-8d %-10s %s",
			port.Port, port.Protocol, truncate(port.Process, 14), port.PID, status, note)

		// Highlight selected row
		if i == m.cursor {
			row = selectedStyle.Render(row)
		}

		b.WriteString(row + "\n")
	}

	// Footer
	b.WriteString("\n  " + strings.Repeat("─", 70) + "\n")

	// Message
	if m.message != "" {
		b.WriteString("  " + m.message + "\n")
	}

	// Help
	b.WriteString(helpStyle.Render("  ↑/↓: Navigate | Space: Toggle Block/Unblock | q: Quit") + "\n")

	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// RunInteractive starts the interactive UI
func RunInteractive(ports []scanner.PortInfo, rules []firewall.Rule, backend firewall.Backend) error {
	m := NewModel(ports, rules, backend)
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

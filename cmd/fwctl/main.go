package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"fwctl/internal/config"
	"fwctl/internal/firewall"
	"fwctl/internal/scanner"
	"fwctl/internal/ui"
)

var (
	backendFlag string
	forceFlag   bool
	allowIPs    []string
)

// Docker warning message
const dockerWarning = "Docker detected: For UFW/Firewalld to control Docker ports, use 127.0.0.1:host:container mapping"

// Color functions
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// showDockerWarning displays Docker compatibility warning for UFW/Firewalld
func showDockerWarning(backendName string) {
	if (backendName == "ufw" || backendName == "firewalld") && firewall.IsDockerRunning() {
		fmt.Printf("\n  %s %s\n", yellow("⚠"), yellow(dockerWarning))
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "fwctl",
		Short: "Universal firewall control tool",
		Long: `
  ╔═══════════════════════════════════════════════════════════╗
  ║                      fwctl v1.0                           ║
  ║         Universal Firewall Control Tool                   ║
  ║     Supports: iptables | UFW | Firewalld                  ║
  ╚═══════════════════════════════════════════════════════════╝

  Note: When Docker is running, iptables is recommended for best
  compatibility. UFW/Firewalld cannot control Docker ports directly.
  To use UFW/Firewalld with Docker, map ports as 127.0.0.1:host:container`,
	}

	rootCmd.PersistentFlags().StringVar(&backendFlag, "backend", "", "Specify firewall backend (iptables, ufw, firewalld)")

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(blockCmd())
	rootCmd.AddCommand(allowCmd())
	rootCmd.AddCommand(unblockCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(hexCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getBackend() firewall.Backend {
	if backendFlag != "" {
		backend := firewall.GetBackend(backendFlag)
		if backend == nil {
			fmt.Fprintf(os.Stderr, "%s Unknown backend '%s'\n", red("✗"), backendFlag)
			os.Exit(1)
		}
		if !backend.IsAvailable() {
			fmt.Fprintf(os.Stderr, "%s Backend '%s' is not available\n", red("✗"), backendFlag)
			os.Exit(1)
		}
		return backend
	}

	backend := firewall.Detect()
	if backend == nil {
		fmt.Fprintf(os.Stderr, "%s No firewall backend available\n", red("✗"))
		os.Exit(1)
	}
	return backend
}

func scanCmd() *cobra.Command {
	var interactive bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan open ports and their associated processes",
		Run: func(cmd *cobra.Command, args []string) {
			backend := getBackend()
			rules, _ := backend.ListRules()
			blockedPorts := make(map[int][]string)
			for _, r := range rules {
				blockedPorts[r.Port] = r.AllowedIPs
			}

			s := scanner.New()
			ports, err := s.ScanPorts()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Error scanning ports: %v\n", red("✗"), err)
				os.Exit(1)
			}

			if len(ports) == 0 {
				fmt.Printf("%s No listening ports found\n", yellow("!"))
				return
			}

			// Sort by port number
			sort.Slice(ports, func(i, j int) bool {
				return ports[i].Port < ports[j].Port
			})

			// Interactive mode
			if interactive {
				if err := ui.RunInteractive(ports, rules, backend); err != nil {
					fmt.Fprintf(os.Stderr, "%s Error: %v\n", red("✗"), err)
					os.Exit(1)
				}
				return
			}

			// Non-interactive mode (original output)
			fmt.Println()
			fmt.Printf("  %s Port Scan Results [Backend: %s]\n", bold("◆"), cyan(backend.Name()))
			fmt.Println()

			// Build table data
			var rows [][]string
			for _, p := range ports {
				process := p.Process
				if process == "" {
					process = "-"
				}
				if len(process) > 14 {
					process = process[:13] + "…"
				}

				pid := "-"
				if p.PID > 0 {
					pid = strconv.Itoa(p.PID)
				}

				// Determine status
				var status, note string
				if allowedIPs, blocked := blockedPorts[p.Port]; blocked {
					status = "● BLOCKED"
					if len(allowedIPs) > 0 {
						note = "Allow: " + strings.Join(allowedIPs, ", ")
					} else {
						note = "localhost only"
					}
				} else {
					status = "● OPEN"
					note = ""
				}

				// Protected port note
				if p.Protected {
					if note != "" {
						note += " | "
					}
					note += "Protected: " + config.GetProtectedPortName(p.Port)
				}

				rows = append(rows, []string{
					strconv.Itoa(p.Port),
					p.Protocol,
					process,
					pid,
					status,
					note,
				})
			}

			// Create styled table
			headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
			evenRowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
			oddRowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

			t := table.New().
				Border(lipgloss.NormalBorder()).
				BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
				Headers("PORT", "PROTO", "PROCESS", "PID", "STATUS", "NOTE").
				Rows(rows...).
				StyleFunc(func(row, col int) lipgloss.Style {
					if row == table.HeaderRow {
						return headerStyle
					}
					// Color STATUS column
					if col == 4 && row >= 0 && row < len(rows) {
						if strings.Contains(rows[row][4], "BLOCKED") {
							return lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // Red
						}
						return lipgloss.NewStyle().Foreground(lipgloss.Color("42")) // Green
					}
					// Color NOTE column for protected ports
					if col == 5 && row >= 0 && row < len(rows) {
						if strings.Contains(rows[row][5], "Protected") {
							return lipgloss.NewStyle().Foreground(lipgloss.Color("226")) // Yellow
						}
					}
					if row%2 == 0 {
						return evenRowStyle
					}
					return oddRowStyle
				})

			fmt.Println(t)

			// Summary
			fmt.Println()
			openCount := len(ports) - len(blockedPorts)
			fmt.Printf("  Total: %d ports | %s %d open | %s %d blocked\n",
				len(ports),
				green("●"), openCount,
				red("●"), len(blockedPorts))

			// Docker warning for UFW/Firewalld
			showDockerWarning(backend.Name())
			fmt.Println()
		},
	}

	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode (use arrow keys to navigate, space to toggle)")

	return cmd
}

func blockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "block <port>",
		Short: "Block a port (allow only localhost and specified IPs)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			port, err := strconv.Atoi(args[0])
			if err != nil || port < 1 || port > 65535 {
				fmt.Fprintf(os.Stderr, "%s Invalid port number\n", red("✗"))
				os.Exit(1)
			}

			// Check process protection by scanning the port
			s := scanner.New()
			ports, _ := s.ScanPorts()
			var processName string
			for _, p := range ports {
				if p.Port == port {
					processName = p.Process
					break
				}
			}

			// Check protection level based on process name
			protLevel := config.GetProtectionLevel(processName)
			procDesc := config.GetProcessDescription(processName)
			if procDesc == "" {
				procDesc = processName
			}

			if protLevel == config.ProtectionStrict {
				// SSHD - RED warning, requires whitelist
				if len(allowIPs) == 0 && !forceFlag {
					fmt.Fprintf(os.Stderr, "%s %s\n", red("✗ CRITICAL:"), red(fmt.Sprintf("Port %d is running %s", port, procDesc)))
					fmt.Fprintf(os.Stderr, "%s Blocking SSH without whitelist IPs will lock you out!\n", red("  "))
					fmt.Fprintf(os.Stderr, "  Use: fwctl block %d --allow <your-ip>\n", port)
					fmt.Fprintf(os.Stderr, "  Or use --force to override (dangerous!)\n")
					os.Exit(1)
				}
				if forceFlag && len(allowIPs) == 0 {
					fmt.Fprintf(os.Stderr, "%s %s\n", red("⚠ WARNING:"), red("Blocking SSH without whitelist - you may lose access!"))
				}
			} else if protLevel == config.ProtectionWarn {
				// Nginx/Apache - YELLOW warning
				fmt.Printf("%s Port %d is running %s\n", yellow("⚠ WARNING:"), port, yellow(procDesc))
			}

			backend := getBackend()
			fmt.Printf("%s Using backend: %s\n", cyan("▶"), backend.Name())

			if err := backend.BlockPort(port, "tcp", allowIPs); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to block port: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Printf("%s Port %d blocked successfully\n", green("✓"), port)
			if len(allowIPs) > 0 {
				fmt.Printf("  Allowed IPs: %s\n", strings.Join(allowIPs, ", "))
			}
			fmt.Printf("  Localhost access: %s\n", green("always allowed"))
		},
	}

	cmd.Flags().BoolVar(&forceFlag, "force", false, "Force blocking protected ports")
	cmd.Flags().StringArrayVar(&allowIPs, "allow", []string{}, "IP addresses to allow")

	return cmd
}

func allowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "allow <port> <ip>",
		Short: "Allow an IP address to access a blocked port",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			port, err := strconv.Atoi(args[0])
			if err != nil || port < 1 || port > 65535 {
				fmt.Fprintf(os.Stderr, "%s Invalid port number\n", red("✗"))
				os.Exit(1)
			}

			ip := args[1]
			if !isValidIP(ip) {
				fmt.Fprintf(os.Stderr, "%s Invalid IP address\n", red("✗"))
				os.Exit(1)
			}

			backend := getBackend()
			fmt.Printf("%s Using backend: %s\n", cyan("▶"), backend.Name())

			if err := backend.AllowIP(port, "tcp", ip); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to allow IP: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Printf("%s IP %s allowed to access port %d\n", green("✓"), ip, port)
		},
	}
}

func unblockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unblock <port>",
		Short: "Remove blocking rules for a port",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			port, err := strconv.Atoi(args[0])
			if err != nil || port < 1 || port > 65535 {
				fmt.Fprintf(os.Stderr, "%s Invalid port number\n", red("✗"))
				os.Exit(1)
			}

			backend := getBackend()
			fmt.Printf("%s Using backend: %s\n", cyan("▶"), backend.Name())

			if err := backend.RemoveRule(port, "tcp"); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to unblock port: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Printf("%s Port %d unblocked\n", green("✓"), port)
		},
	}
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all firewall rules managed by fwctl",
		Run: func(cmd *cobra.Command, args []string) {
			backend := getBackend()

			rules, err := backend.ListRules()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Error listing rules: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Println()
			fmt.Printf("  %s Firewall Rules [Backend: %s]\n", bold("◆"), cyan(backend.Name()))
			fmt.Println("  " + strings.Repeat("─", 60))

			if len(rules) == 0 {
				fmt.Printf("\n  %s No rules configured\n\n", yellow("!"))
				return
			}

			fmt.Println()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
				bold("PORT"), bold("PROTO"), bold("STATUS"), bold("ALLOWED IPs"))
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
				"────", "─────", "──────", "───────────")

			for _, r := range rules {
				allowedIPs := "localhost only"
				if len(r.AllowedIPs) > 0 {
					allowedIPs = strings.Join(r.AllowedIPs, ", ")
				}

				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
					bold(strconv.Itoa(r.Port)),
					r.Protocol,
					red("● BLOCKED"),
					allowedIPs,
				)
			}
			w.Flush()
			fmt.Println()
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show firewall status",
		Run: func(cmd *cobra.Command, args []string) {
			available := firewall.ListAvailable()

			fmt.Println()
			fmt.Printf("  %s Firewall Status\n", bold("◆"))
			fmt.Println("  " + strings.Repeat("─", 40))
			fmt.Println()

			if len(available) == 0 {
				fmt.Printf("  %s No firewall backends available\n\n", red("✗"))
				return
			}

			for _, b := range available {
				status, err := b.GetStatus()
				if err != nil {
					fmt.Printf("  %s %s: %s\n", red("●"), b.Name(), red("error"))
					continue
				}

				activeStr := red("inactive")
				if status.Active {
					activeStr = green("active")
				}

				fmt.Printf("  %s %-12s %s  (%d rules)\n",
					green("●"), b.Name()+":", activeStr, status.RuleCount)
			}

			backend := firewall.Detect()
			if backend != nil {
				fmt.Printf("\n  Default: %s\n", cyan(backend.Name()))
			}

			// Docker warning
			if firewall.IsDockerRunning() {
				fmt.Printf("\n  %s %s\n", yellow("⚠"), yellow("Docker detected: UFW/Firewalld cannot control Docker ports directly"))
				fmt.Printf("    %s Use iptables backend, or map ports as 127.0.0.1:host:container\n", yellow("→"))
			}
			fmt.Println()
		},
	}
}

func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// ============================================================================
// Hex Filter Commands (Experimental)
// ============================================================================

func hexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hex",
		Short: "[Experimental] Hex pattern filter for iptables",
		Long: `
  ╔═══════════════════════════════════════════════════════════╗
  ║          Hex Filter - Experimental Feature                ║
  ╚═══════════════════════════════════════════════════════════╝

  Filter and DROP packets containing specific hex patterns.
  Only supported with iptables backend.

  Hex Pattern Format:
    |XX XX XX XX|  - hex bytes separated by spaces
    |deadbeef|     - continuous hex string

  Examples:
    fwctl hex add "|48 45 4c 4c 4f|"              # Block "HELLO"
    fwctl hex add "|de ad be ef|" --port 8080    # Block on specific port
    fwctl hex add "|ff ff|" -p udp --port 53     # Block UDP DNS pattern
    fwctl hex list                                # List all hex rules
    fwctl hex remove 1                            # Remove rule by ID
    fwctl hex remove "|de ad be ef|"              # Remove by pattern

  Use Cases:
    - Block specific protocol signatures
    - Filter malicious payloads
    - Block application-layer patterns`,
	}

	cmd.AddCommand(hexAddCmd())
	cmd.AddCommand(hexListCmd())
	cmd.AddCommand(hexRemoveCmd())

	return cmd
}

func hexAddCmd() *cobra.Command {
	var port int
	var protocol string
	var comment string

	cmd := &cobra.Command{
		Use:   "add <hex-pattern>",
		Short: "Add a hex pattern filter rule",
		Long: `Add a hex pattern filter to DROP matching packets.

Examples:
  fwctl hex add "|48 45 4c 4c 4f|"              # Block packets containing "HELLO"
  fwctl hex add "|de ad be ef|" --port 8080    # Block only on port 8080
  fwctl hex add "|ff ff|" -p udp               # Block UDP packets with pattern`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pattern := args[0]

			// Validate pattern format
			if !strings.HasPrefix(pattern, "|") || !strings.HasSuffix(pattern, "|") {
				fmt.Fprintf(os.Stderr, "%s Invalid hex pattern format\n", red("✗"))
				fmt.Fprintf(os.Stderr, "  Pattern must be enclosed in |pipes|, e.g., \"|de ad be ef|\"\n")
				os.Exit(1)
			}

			backend := getBackend()
			if backend.Name() != "iptables" {
				fmt.Fprintf(os.Stderr, "%s Hex filter only supported with iptables backend\n", red("✗"))
				fmt.Fprintf(os.Stderr, "  Current backend: %s\n", backend.Name())
				fmt.Fprintf(os.Stderr, "  Use: fwctl --backend iptables hex add ...\n")
				os.Exit(1)
			}

			iptables, ok := backend.(*firewall.IPTables)
			if !ok {
				fmt.Fprintf(os.Stderr, "%s Failed to get iptables backend\n", red("✗"))
				os.Exit(1)
			}

			fmt.Printf("%s [Experimental] Adding hex filter...\n", yellow("⚠"))
			fmt.Printf("  Pattern: %s\n", cyan(pattern))
			if port > 0 {
				fmt.Printf("  Port: %d\n", port)
			}
			if protocol != "" {
				fmt.Printf("  Protocol: %s\n", protocol)
			}

			if err := iptables.AddHexFilter(pattern, port, protocol, comment); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to add hex filter: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Printf("%s Hex filter added successfully\n", green("✓"))
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "Filter only on specific port")
	cmd.Flags().StringVarP(&protocol, "proto", "p", "", "Protocol (tcp/udp)")
	cmd.Flags().StringVarP(&comment, "comment", "c", "", "Rule comment")

	return cmd
}

func hexListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all hex filter rules",
		Run: func(cmd *cobra.Command, args []string) {
			backend := getBackend()
			if backend.Name() != "iptables" {
				fmt.Fprintf(os.Stderr, "%s Hex filter only supported with iptables backend\n", red("✗"))
				os.Exit(1)
			}

			iptables, ok := backend.(*firewall.IPTables)
			if !ok {
				fmt.Fprintf(os.Stderr, "%s Failed to get iptables backend\n", red("✗"))
				os.Exit(1)
			}

			rules, err := iptables.ListHexFilters()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to list hex filters: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Println()
			fmt.Printf("  %s Hex Filter Rules [Experimental]\n", bold("◆"))
			fmt.Println("  " + strings.Repeat("─", 60))

			if len(rules) == 0 {
				fmt.Printf("\n  %s No hex filter rules configured\n\n", yellow("!"))
				return
			}

			fmt.Println()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				bold("ID"), bold("PATTERN"), bold("PORT"), bold("PROTO"), bold("COMMENT"))
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				"──", "───────", "────", "─────", "───────")

			for _, r := range rules {
				portStr := "*"
				if r.Port > 0 {
					portStr = strconv.Itoa(r.Port)
				}
				protoStr := "*"
				if r.Protocol != "" && r.Protocol != "all" {
					protoStr = r.Protocol
				}

				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
					bold(strconv.Itoa(r.ID)),
					cyan(r.Pattern),
					portStr,
					protoStr,
					r.Comment,
				)
			}
			w.Flush()
			fmt.Println()
		},
	}
}

func hexRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id-or-pattern>",
		Short: "Remove a hex filter rule by ID or pattern",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			idOrPattern := args[0]

			backend := getBackend()
			if backend.Name() != "iptables" {
				fmt.Fprintf(os.Stderr, "%s Hex filter only supported with iptables backend\n", red("✗"))
				os.Exit(1)
			}

			iptables, ok := backend.(*firewall.IPTables)
			if !ok {
				fmt.Fprintf(os.Stderr, "%s Failed to get iptables backend\n", red("✗"))
				os.Exit(1)
			}

			if err := iptables.RemoveHexFilter(idOrPattern); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to remove hex filter: %v\n", red("✗"), err)
				os.Exit(1)
			}

			fmt.Printf("%s Hex filter removed successfully\n", green("✓"))
		},
	}
}

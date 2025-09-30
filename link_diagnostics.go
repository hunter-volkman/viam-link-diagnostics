package link_diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.viam.com/rdk/components/sensor"
	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/resource"
)

var Model = resource.NewModel("hunter", "link-diagnostics", "sensor")

func init() {
	resource.RegisterComponent(sensor.API, Model,
		resource.Registration[sensor.Sensor, *Config]{
			Constructor: NewSensor,
		},
	)
}

// Config defines the sensor configuration
type Config struct {
	Iface          string `json:"iface"`
	RefreshSecs    int    `json:"refresh_secs,omitempty"`
	InternetHost   string `json:"internet_host,omitempty"`
	PingSamples    int    `json:"ping_samples,omitempty"`
	PingTimeoutSec int    `json:"ping_timeout_sec,omitempty"`
	TestDNS        bool   `json:"test_dns,omitempty"`
	TestTCPPorts   bool   `json:"test_tcp_ports,omitempty"`
}

// Validate ensures config has sensible defaults
func (cfg *Config) Validate(path string) ([]string, error) {
	// Apply defaults
	cfg.applyDefaults()
	return nil, nil
}

// applyDefaults sets reasonable defaults for any missing config values
func (cfg *Config) applyDefaults() {
	if cfg.RefreshSecs <= 0 {
		cfg.RefreshSecs = 5
	}
	if cfg.InternetHost == "" {
		cfg.InternetHost = "8.8.8.8"
	}
	if cfg.PingSamples <= 0 {
		cfg.PingSamples = 3
	}
	if cfg.PingTimeoutSec <= 0 {
		cfg.PingTimeoutSec = 1
	}
	// Default to enabling extended tests
	if !cfg.TestDNS {
		cfg.TestDNS = true
	}
	if !cfg.TestTCPPorts {
		cfg.TestTCPPorts = true
	}
}

type connectivitySensor struct {
	resource.AlwaysRebuild
	name   resource.Name
	logger logging.Logger
	cfg    *Config

	mu           sync.RWMutex
	lastReading  map[string]interface{}
	lastReadTime time.Time
}

// NewSensor creates a new link diagnostics sensor
func NewSensor(ctx context.Context, deps resource.Dependencies, conf resource.Config, logger logging.Logger) (sensor.Sensor, error) {
	cfg, err := resource.NativeConfig[*Config](conf)
	if err != nil {
		return nil, err
	}

	// ALWAYS apply defaults, don't trust Validate() was called
	cfg.applyDefaults()

	logger.Infow("Link diagnostics sensor configured",
		"iface", cfg.Iface,
		"internet_host", cfg.InternetHost,
		"ping_samples", cfg.PingSamples,
		"refresh_secs", cfg.RefreshSecs)

	return &connectivitySensor{
		name:   conf.ResourceName(),
		logger: logger,
		cfg:    cfg,
	}, nil
}

func (s *connectivitySensor) Name() resource.Name {
	return s.name
}

// Readings returns the current network diagnostics
func (s *connectivitySensor) Readings(ctx context.Context, extra map[string]interface{}) (map[string]interface{}, error) {
	// Check cache first
	s.mu.RLock()
	if s.lastReading != nil && time.Since(s.lastReadTime) < time.Duration(s.cfg.RefreshSecs)*time.Second {
		reading := make(map[string]interface{})
		for k, v := range s.lastReading {
			reading[k] = v
		}
		reading["age_ms"] = time.Since(s.lastReadTime).Milliseconds()
		s.mu.RUnlock()
		return reading, nil
	}
	s.mu.RUnlock()

	// Collect fresh reading
	reading := s.collectDiagnostics(ctx)

	// Update cache
	s.mu.Lock()
	s.lastReading = reading
	s.lastReadTime = time.Now()
	s.mu.Unlock()

	reading["age_ms"] = int64(0)
	return reading, nil
}

// collectDiagnostics gathers all network diagnostic information
func (s *connectivitySensor) collectDiagnostics(ctx context.Context) map[string]interface{} {
	r := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// 1. Determine network interface
	iface := s.getActiveInterface()
	r["iface"] = iface
	r["iface_type"] = s.getInterfaceType(iface)

	// 2. Collect basic network configuration
	s.collectNetworkConfig(ctx, iface, r)

	// 3. Collect WiFi-specific info if applicable
	if r["iface_type"] == "wifi" {
		s.collectWiFiInfo(ctx, iface, r)
	}

	// 4. Test connectivity
	s.testConnectivity(ctx, r)

	return r
}

// getActiveInterface returns the active network interface name
func (s *connectivitySensor) getActiveInterface() string {
	// Use configured interface if specified
	if s.cfg.Iface != "" && s.cfg.Iface != "auto" {
		return s.cfg.Iface
	}

	// Auto-detect default interface
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return "unknown"
	}

	// Extract interface from: default via X.X.X.X dev wlan0
	re := regexp.MustCompile(`dev\s+(\S+)`)
	if match := re.FindStringSubmatch(string(out)); len(match) > 1 {
		return match[1]
	}

	return "unknown"
}

// getInterfaceType determines if interface is wifi or ethernet
func (s *connectivitySensor) getInterfaceType(iface string) string {
	if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl") {
		return "wifi"
	}
	return "ethernet"
}

// collectNetworkConfig gathers IP, gateway, DNS, and other network settings
func (s *connectivitySensor) collectNetworkConfig(ctx context.Context, iface string, r map[string]interface{}) {
	// Get interface details (IP, MAC, MTU, state)
	if out := s.execCommand(ctx, 1*time.Second, "ip", "addr", "show", iface); out != nil {
		output := string(out)

		// MAC address
		if match := regexp.MustCompile(`link/ether\s+([0-9a-fA-F:]+)`).FindStringSubmatch(output); len(match) > 1 {
			r["mac_address"] = strings.ToLower(match[1])
		}

		// IPv4 address with subnet
		if match := regexp.MustCompile(`inet\s+(\S+)`).FindStringSubmatch(output); len(match) > 1 {
			parts := strings.Split(match[1], "/")
			r["ipv4"] = parts[0]
			if len(parts) > 1 {
				r["subnet_bits"] = parts[1]
			}
		}

		// MTU
		if match := regexp.MustCompile(`mtu\s+(\d+)`).FindStringSubmatch(output); len(match) > 1 {
			if mtu, err := strconv.Atoi(match[1]); err == nil {
				r["mtu"] = mtu
			}
		}

		// Link state
		if match := regexp.MustCompile(`state\s+(\S+)`).FindStringSubmatch(output); len(match) > 1 {
			r["link_state"] = match[1]
		}
	}

	// Get default gateway
	if out := s.execCommand(ctx, 1*time.Second, "ip", "route", "list", "default"); out != nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "dev "+iface) {
				if match := regexp.MustCompile(`via\s+(\S+)`).FindStringSubmatch(line); len(match) > 1 {
					r["gateway_ip"] = match[1]
					r["default_route"] = true
					break
				}
			}
		}
	}

	// Get DNS servers
	if out := s.execCommand(ctx, 500*time.Millisecond, "grep", "^nameserver", "/etc/resolv.conf"); out != nil {
		var dns []string
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "nameserver" {
				dns = append(dns, parts[1])
			}
		}
		if len(dns) > 0 {
			r["dns_servers"] = strings.Join(dns, ",")
		}
	}

	// Get packet statistics
	s.collectInterfaceStats(ctx, iface, r)
}

// collectInterfaceStats reads packet and error counts from /sys
func (s *connectivitySensor) collectInterfaceStats(ctx context.Context, iface string, r map[string]interface{}) {
	statsPath := fmt.Sprintf("/sys/class/net/%s/statistics/", iface)

	// Read various statistics
	stats := map[string]string{
		"tx_packets": "tx_packets",
		"rx_packets": "rx_packets",
		"tx_errors":  "tx_errors",
		"rx_errors":  "rx_errors",
		"tx_dropped": "tx_dropped",
		"rx_dropped": "rx_dropped",
	}

	for key, file := range stats {
		if out := s.execCommand(ctx, 200*time.Millisecond, "cat", statsPath+file); out != nil {
			if val, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
				r[key] = val
			}
		}
	}

	// Calculate drop rates
	if rxPackets, ok := r["rx_packets"].(int64); ok {
		if rxDropped, ok := r["rx_dropped"].(int64); ok && rxPackets > 0 {
			dropRate := float64(rxDropped) / float64(rxPackets) * 100
			r["rx_drop_rate_pct"] = dropRate
		}
	}

	if txPackets, ok := r["tx_packets"].(int64); ok {
		if txDropped, ok := r["tx_dropped"].(int64); ok && txPackets > 0 {
			total := txPackets + txDropped
			dropRate := float64(txDropped) / float64(total) * 100
			r["tx_drop_rate_pct"] = dropRate
		}
	}

	// Calculate error rates
	if rxPackets, ok := r["rx_packets"].(int64); ok {
		if rxErrors, ok := r["rx_errors"].(int64); ok && rxPackets > 0 {
			errorRate := float64(rxErrors) / float64(rxPackets) * 100
			r["rx_error_rate_pct"] = errorRate
		}
	}

	if txPackets, ok := r["tx_packets"].(int64); ok {
		if txErrors, ok := r["tx_errors"].(int64); ok && txPackets > 0 {
			errorRate := float64(txErrors) / float64(txPackets) * 100
			r["tx_error_rate_pct"] = errorRate
		}
	}
}

// collectWiFiInfo gathers WiFi-specific information
func (s *connectivitySensor) collectWiFiInfo(ctx context.Context, iface string, r map[string]interface{}) {
	// Get WiFi link info
	if out := s.execCommand(ctx, 1*time.Second, "iw", "dev", iface, "link"); out != nil {
		output := string(out)

		if strings.Contains(output, "Not connected") {
			r["wifi_connected"] = false
			return
		}

		r["wifi_connected"] = true

		// SSID
		if match := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(output); len(match) > 1 {
			r["ssid"] = strings.TrimSpace(match[1])
		}

		// BSSID (access point MAC)
		if match := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`).FindStringSubmatch(output); len(match) > 1 {
			r["bssid"] = match[1]
		}

		// Signal strength
		if match := regexp.MustCompile(`signal:\s*(-?\d+)\s*dBm`).FindStringSubmatch(output); len(match) > 1 {
			if rssi, err := strconv.Atoi(match[1]); err == nil {
				r["rssi_dbm"] = rssi
				// Calculate quality percentage (rough estimate)
				quality := s.calculateSignalQuality(rssi)
				r["link_quality_pct"] = quality
			}
		}

		// Frequency and channel
		if match := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(output); len(match) > 1 {
			if freq, err := strconv.Atoi(match[1]); err == nil {
				r["freq_mhz"] = freq
				r["band_ghz"] = float64(freq) / 1000.0
				r["channel"] = s.frequencyToChannel(freq)
			}
		}

		// Bitrates
		if match := regexp.MustCompile(`tx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(output); len(match) > 1 {
			if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
				r["tx_bitrate_mbps"] = rate
			}
		}
		if match := regexp.MustCompile(`rx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(output); len(match) > 1 {
			if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
				r["rx_bitrate_mbps"] = rate
			}
		}
	}
}

// testConnectivity performs ping tests to gateway and internet
func (s *connectivitySensor) testConnectivity(ctx context.Context, r map[string]interface{}) {
	// Test gateway connectivity
	if gw, ok := r["gateway_ip"].(string); ok && gw != "" {
		latency, loss := s.pingHost(ctx, gw)
		if latency >= 0 {
			r["latency_gw_ms"] = latency
		}
		r["loss_gw_pct"] = loss
	}

	// Test internet connectivity
	latency, loss := s.pingHost(ctx, s.cfg.InternetHost)
	if latency >= 0 {
		r["latency_inet_ms"] = latency
	}
	r["loss_inet_pct"] = loss

	// Determine overall connectivity status
	r["route"] = s.determineConnectivityStatus(r)

	// Extended tests if enabled
	if s.cfg.TestDNS {
		s.testDNS(ctx, r)
	}
	if s.cfg.TestTCPPorts {
		s.testTCPPorts(ctx, r)
	}
}

// pingHost performs ICMP ping test to a target host
func (s *connectivitySensor) pingHost(ctx context.Context, target string) (latency float64, loss float64) {
	if target == "" {
		return -1, 100
	}

	// Calculate appropriate timeout for the ping operation
	timeout := time.Duration(s.cfg.PingSamples*s.cfg.PingTimeoutSec+2) * time.Second

	out := s.execCommand(ctx, timeout,
		"ping", "-c", strconv.Itoa(s.cfg.PingSamples),
		"-W", strconv.Itoa(s.cfg.PingTimeoutSec),
		target)

	if out == nil {
		// Ping failed, try TCP fallback
		return s.tcpPing(target)
	}

	output := string(out)

	// Parse average latency from: min/avg/max/mdev = X.X/Y.Y/Z.Z/A.A ms
	latency = -1
	if match := regexp.MustCompile(`min/avg/max/mdev = [\d.]+/([\d.]+)/`).FindStringSubmatch(output); len(match) > 1 {
		if avg, err := strconv.ParseFloat(match[1], 64); err == nil {
			latency = avg
		}
	}

	// Parse packet loss from: X% packet loss
	loss = 100
	if match := regexp.MustCompile(`(\d+)% packet loss`).FindStringSubmatch(output); len(match) > 1 {
		if pct, err := strconv.ParseFloat(match[1], 64); err == nil {
			loss = pct
		}
	}

	// If we parsed latency but not loss, assume 0% loss
	if latency >= 0 && loss == 100 {
		loss = 0
	}

	return latency, loss
}

// tcpPing attempts TCP connection as fallback when ICMP is blocked
func (s *connectivitySensor) tcpPing(target string) (latency float64, loss float64) {
	ports := []string{"53", "443", "80"} // DNS, HTTPS, HTTP

	var totalLatency float64
	var successCount int

	for i := 0; i < s.cfg.PingSamples; i++ {
		for _, port := range ports {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, port), 1*time.Second)
			if err == nil {
				conn.Close()
				totalLatency += float64(time.Since(start).Milliseconds())
				successCount++
				break // Success, no need to try other ports
			}
		}
	}

	if successCount > 0 {
		avgLatency := totalLatency / float64(successCount)
		loss := float64(s.cfg.PingSamples-successCount) / float64(s.cfg.PingSamples) * 100
		return avgLatency, loss
	}

	return -1, 100
}

// testDNS performs DNS resolution test
func (s *connectivitySensor) testDNS(ctx context.Context, r map[string]interface{}) {
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	start := time.Now()
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx2, "google.com")
	elapsed := time.Since(start).Milliseconds()

	if err == nil && len(addrs) > 0 {
		r["dns_working"] = true
		r["dns_latency_ms"] = elapsed
	} else {
		r["dns_working"] = false
	}
}

// testTCPPorts tests connectivity to common TCP ports
func (s *connectivitySensor) testTCPPorts(ctx context.Context, r map[string]interface{}) {
	// Test HTTPS on a reliable web server
	if reachable, latency := s.testTCPPort(ctx, "google.com", "443"); reachable {
		r["tcp_443_reachable"] = true
		r["tcp_443_latency_ms"] = latency
	} else {
		r["tcp_443_reachable"] = false
	}

	// Test DNS port on the configured DNS server
	if reachable, latency := s.testTCPPort(ctx, s.cfg.InternetHost, "53"); reachable {
		r["tcp_53_reachable"] = true
		r["tcp_53_latency_ms"] = latency
	} else {
		r["tcp_53_reachable"] = false
	}
}

// testTCPPort tests connectivity to a specific TCP port
func (s *connectivitySensor) testTCPPort(ctx context.Context, host, port string) (bool, float64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
	elapsed := time.Since(start).Seconds() * 1000

	if err == nil {
		conn.Close()
		return true, elapsed
	}
	return false, 0
}

// determineConnectivityStatus evaluates overall connectivity
func (s *connectivitySensor) determineConnectivityStatus(r map[string]interface{}) string {
	// Check gateway connectivity
	gwLoss, gwOk := r["loss_gw_pct"].(float64)
	if !gwOk || gwLoss > 50 {
		return "None"
	}

	// Check internet connectivity
	inetLoss, inetOk := r["loss_inet_pct"].(float64)
	if !inetOk || inetLoss > 50 {
		return "LAN"
	}

	return "Internet"
}

// calculateSignalQuality converts RSSI to quality percentage
func (s *connectivitySensor) calculateSignalQuality(rssi int) int {
	// Excellent: > -50 dBm
	// Good: -50 to -60 dBm
	// Fair: -60 to -70 dBm
	// Weak: < -70 dBm

	if rssi >= -30 {
		return 100
	} else if rssi >= -67 {
		return 100 - ((-30 - rssi) * 100 / 37) // Linear scale from 100% to ~20%
	} else if rssi >= -90 {
		return 20 - ((-67 - rssi) * 20 / 23) // Linear scale from 20% to 0%
	}
	return 0
}

// frequencyToChannel converts WiFi frequency to channel number
func (s *connectivitySensor) frequencyToChannel(freq int) int {
	// 2.4 GHz band
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq-2412)/5 + 1
	}

	// 5 GHz band
	if freq >= 5180 && freq <= 5825 {
		return (freq-5180)/5 + 36
	}

	return 0
}

// execCommand is a helper to execute commands with timeout
func (s *connectivitySensor) execCommand(ctx context.Context, timeout time.Duration, name string, args ...string) []byte {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx2, name, args...).CombinedOutput()
	if err != nil {
		return nil
	}
	return out
}

// runSpeedTest performs internet speed test
func (s *connectivitySensor) runSpeedTest(ctx context.Context) (map[string]interface{}, error) {
	if _, err := exec.LookPath("speedtest-cli"); err != nil {
		return map[string]interface{}{
			"error": "speedtest-cli not installed",
		}, nil
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "speedtest-cli", "--json").Output()
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("speedtest failed: %v", err),
		}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("failed to parse speedtest output: %v", err),
		}, nil
	}

	speedResult := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if download, ok := result["download"].(float64); ok {
		speedResult["download_mbps"] = download / 1_000_000
	}
	if upload, ok := result["upload"].(float64); ok {
		speedResult["upload_mbps"] = upload / 1_000_000
	}
	if ping, ok := result["ping"].(float64); ok {
		speedResult["ping_ms"] = ping
	}
	if server, ok := result["server"].(map[string]interface{}); ok {
		if sponsor, ok := server["sponsor"].(string); ok {
			speedResult["server"] = sponsor
		}
		if location, ok := server["name"].(string); ok {
			speedResult["location"] = location
		}
	}

	return speedResult, nil
}

// runTraceroute executes traceroute to a target host
func (s *connectivitySensor) runTraceroute(ctx context.Context, target string) (map[string]interface{}, error) {
	// Check if traceroute is installed
	if _, err := exec.LookPath("traceroute"); err != nil {
		return map[string]interface{}{
			"error": "traceroute not installed",
			"hint":  "Install with: sudo apt-get install traceroute",
		}, nil
	}

	// Validate target
	if target == "" {
		target = s.cfg.InternetHost
	}

	// Run traceroute with reasonable limits
	out := s.execCommand(ctx, 10*time.Second,
		"traceroute",
		"-w", "1", // 1 second timeout per hop
		"-m", "10", // max 10 hops
		target)

	if out == nil {
		return map[string]interface{}{
			"error":     "traceroute failed",
			"target":    target,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	return map[string]interface{}{
		"target":    target,
		"output":    string(out),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DoCommand handles custom commands
func (s *connectivitySensor) DoCommand(ctx context.Context, cmd map[string]interface{}) (map[string]interface{}, error) {
	if cmdName, ok := cmd["command"].(string); ok {
		switch cmdName {
		case "ping":
			// Allow custom ping target
			target := s.cfg.InternetHost
			if t, ok := cmd["target"].(string); ok && t != "" {
				target = t
			}
			latency, loss := s.pingHost(ctx, target)
			return map[string]interface{}{
				"target":     target,
				"latency_ms": latency,
				"loss_pct":   loss,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			}, nil

		case "traceroute":
			target := s.cfg.InternetHost
			if t, ok := cmd["target"].(string); ok && t != "" {
				target = t
			}
			return s.runTraceroute(ctx, target)

		case "debug":
			// Force fresh reading without cache
			return s.collectDiagnostics(ctx), nil

		case "speedtest":
			// Run speed test
			return s.runSpeedTest(ctx)

		default:
			return nil, fmt.Errorf("unknown command: %s", cmdName)
		}
	}
	return nil, fmt.Errorf("no command specified")
}

// Close cleans up resources
func (s *connectivitySensor) Close(context.Context) error {
	return nil
}

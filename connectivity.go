package connectivity

import (
	"context"
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

var Model = resource.NewModel("hunter", "connectivity", "sensor")

func init() {
	resource.RegisterComponent(sensor.API, Model,
		resource.Registration[sensor.Sensor, *Config]{
			Constructor: NewSensor,
		},
	)
}

type Config struct {
	Iface          string `json:"iface"`
	RefreshSecs    int    `json:"refresh_secs,omitempty"`
	InternetHost   string `json:"internet_host,omitempty"`
	PingSamples    int    `json:"ping_samples,omitempty"`
	PingTimeoutSec int    `json:"ping_timeout_sec,omitempty"`
}

func (cfg *Config) Validate(path string) ([]string, error) {
	// Set reasonable defaults
	if cfg.RefreshSecs <= 0 {
		cfg.RefreshSecs = 5
	}
	if cfg.InternetHost == "" {
		cfg.InternetHost = "1.1.1.1"
	}
	if cfg.PingSamples <= 0 {
		cfg.PingSamples = 3
	}
	if cfg.PingTimeoutSec <= 0 {
		cfg.PingTimeoutSec = 1
	}
	return nil, nil
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

func NewSensor(ctx context.Context, deps resource.Dependencies, conf resource.Config, logger logging.Logger) (sensor.Sensor, error) {
	cfg, err := resource.NativeConfig[*Config](conf)
	if err != nil {
		return nil, err
	}

	return &connectivitySensor{
		name:   conf.ResourceName(),
		logger: logger,
		cfg:    cfg,
	}, nil
}

func (s *connectivitySensor) Name() resource.Name {
	return s.name
}

func (s *connectivitySensor) Readings(ctx context.Context, extra map[string]interface{}) (map[string]interface{}, error) {
	// Check cache
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
	reading := s.collectSimple(ctx)

	// Update cache
	s.mu.Lock()
	s.lastReading = reading
	s.lastReadTime = time.Now()
	s.mu.Unlock()

	reading["age_ms"] = int64(0)
	return reading, nil
}

func (s *connectivitySensor) collectSimple(ctx context.Context) map[string]interface{} {
	r := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"iface":     s.getInterface(),
	}

	iface := r["iface"].(string)

	// Detect interface type
	if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl") {
		r["iface_type"] = "wifi"
	} else {
		r["iface_type"] = "ethernet"
	}

	// Get basic network info using simple commands
	s.getNetworkInfo(ctx, iface, r)

	// Get Wi-Fi info if applicable
	if r["iface_type"] == "wifi" {
		s.getWiFiInfo(ctx, iface, r)
	}

	// Do connectivity tests
	s.testConnectivity(ctx, r)

	return r
}

func (s *connectivitySensor) getInterface() string {
	if s.cfg.Iface != "" && s.cfg.Iface != "auto" {
		return s.cfg.Iface
	}

	// Simple: parse ip route for default interface
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return "unknown"
	}

	// Parse: default via X.X.X.X dev wlan0
	re := regexp.MustCompile(`dev\s+(\S+)`)
	if match := re.FindStringSubmatch(string(out)); len(match) > 1 {
		return match[1]
	}

	return "unknown"
}

func (s *connectivitySensor) getNetworkInfo(ctx context.Context, iface string, r map[string]interface{}) {
	// Get IP address
	ctx2, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "ip", "addr", "show", iface).Output()
	if err == nil {
		// Parse IPv4
		if match := regexp.MustCompile(`inet\s+(\S+)`).FindStringSubmatch(string(out)); len(match) > 1 {
			// Remove /XX subnet mask
			if ip := strings.Split(match[1], "/")[0]; ip != "" {
				r["ipv4"] = ip
			}
		}

		// Parse IPv6 (exclude link-local fe80::)
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet6") && !strings.Contains(line, "fe80::") {
				if match := regexp.MustCompile(`inet6\s+(\S+)`).FindStringSubmatch(line); len(match) > 1 {
					if ip := strings.Split(match[1], "/")[0]; ip != "" {
						r["ipv6"] = ip
						break
					}
				}
			}
		}
	}

	// Get gateway - try specific interface first
	ctx3, cancel2 := context.WithTimeout(ctx, 1*time.Second)
	defer cancel2()

	out, err = exec.CommandContext(ctx3, "ip", "route", "list", "default").Output()
	if err == nil && len(out) > 0 {
		// Look for gateway on our interface
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

	// Get DNS servers - convert to interface{} array for protobuf compatibility
	ctx4, cancel3 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel3()

	out, err = exec.CommandContext(ctx4, "grep", "^nameserver", "/etc/resolv.conf").Output()
	if err == nil {
		var dns []interface{}
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "nameserver" {
				dns = append(dns, parts[1])
			}
		}
		if len(dns) > 0 {
			r["dns_servers"] = dns
		}
	}

	// NetworkManager state (optional)
	ctx5, cancel4 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel4()

	out, err = exec.CommandContext(ctx5, "nmcli", "-t", "-f", "GENERAL.STATE", "dev", "show", iface).Output()
	if err == nil {
		// Parse GENERAL.STATE:100 (connected)
		if match := regexp.MustCompile(`STATE:.*\((.*?)\)`).FindStringSubmatch(string(out)); len(match) > 1 {
			r["nm_state"] = match[1]
		}
	}
}

func (s *connectivitySensor) getWiFiInfo(ctx context.Context, iface string, r map[string]interface{}) {
	// Try iw first
	ctx2, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "iw", "dev", iface, "link").Output()
	if err == nil && !strings.Contains(string(out), "Not connected") {
		output := string(out)

		// SSID
		if match := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(output); len(match) > 1 {
			r["ssid"] = strings.TrimSpace(match[1])
		}

		// BSSID
		if match := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`).FindStringSubmatch(output); len(match) > 1 {
			r["bssid"] = match[1]
		}

		// Signal
		if match := regexp.MustCompile(`signal:\s*(-?\d+)\s*dBm`).FindStringSubmatch(output); len(match) > 1 {
			if rssi, err := strconv.Atoi(match[1]); err == nil {
				r["rssi_dbm"] = rssi
				// Convert to quality %
				quality := 100
				if rssi < -30 {
					quality = int((float64(rssi+90) / 60.0) * 100)
					if quality < 0 {
						quality = 0
					}
				}
				r["link_quality_pct"] = quality
			}
		}

		// Frequency/Channel
		if match := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(output); len(match) > 1 {
			if freq, err := strconv.Atoi(match[1]); err == nil {
				r["band_ghz"] = float64(freq) / 1000.0
				// Calculate channel (simplified)
				if freq >= 2412 && freq <= 2484 {
					r["channel"] = (freq-2412)/5 + 1
				} else if freq >= 5180 && freq <= 5825 {
					r["channel"] = (freq-5180)/5 + 36
				}
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

	// Try station dump for more details
	ctx3, cancel2 := context.WithTimeout(ctx, 1*time.Second)
	defer cancel2()

	out, err = exec.CommandContext(ctx3, "iw", "dev", iface, "station", "dump").Output()
	if err == nil {
		output := string(out)

		// TX retries
		if match := regexp.MustCompile(`tx failed:\s*(\d+)`).FindStringSubmatch(output); len(match) > 1 {
			if retries, err := strconv.Atoi(match[1]); err == nil {
				r["tx_retries"] = retries
			}
		}

		// Connected time
		if match := regexp.MustCompile(`connected time:\s*(\d+)\s*seconds`).FindStringSubmatch(output); len(match) > 1 {
			if secs, err := strconv.Atoi(match[1]); err == nil {
				assocTime := time.Now().Add(-time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
				r["last_assoc_ts"] = assocTime
			}
		}
	}
}

func (s *connectivitySensor) testConnectivity(ctx context.Context, r map[string]interface{}) {
	// Test gateway if we have one
	if gw, ok := r["gateway_ip"].(string); ok && gw != "" {
		latency, loss := s.ping(ctx, gw)
		if latency != nil {
			r["latency_gw_ms"] = *latency
		}
		if loss != nil {
			r["loss_gw_pct"] = *loss
		}
	}

	// Test internet
	latency, loss := s.ping(ctx, s.cfg.InternetHost)
	if latency != nil {
		r["latency_inet_ms"] = *latency
	}
	if loss != nil {
		r["loss_inet_pct"] = *loss
	}

	// Determine route
	r["route"] = s.determineRoute(r)
}

func (s *connectivitySensor) ping(ctx context.Context, target string) (*float64, *float64) {
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "ping", "-c", strconv.Itoa(s.cfg.PingSamples), "-W", "1", target)
	out, _ := cmd.Output() // Ignore error - parse output either way

	if len(out) == 0 {
		// Try TCP fallback
		return s.tcpPing(target)
	}

	output := string(out)

	// Parse average latency
	var latency *float64
	if match := regexp.MustCompile(`min/avg/max/mdev = [\d.]+/([\d.]+)/`).FindStringSubmatch(output); len(match) > 1 {
		if avg, err := strconv.ParseFloat(match[1], 64); err == nil {
			latency = &avg
		}
	}

	// Parse packet loss
	var loss *float64
	if match := regexp.MustCompile(`(\d+)% packet loss`).FindStringSubmatch(output); len(match) > 1 {
		if pct, err := strconv.ParseFloat(match[1], 64); err == nil {
			loss = &pct
		}
	}

	// If we got output but no loss percentage, assume 0% if we have latency
	if latency != nil && loss == nil {
		zero := 0.0
		loss = &zero
	}

	return latency, loss
}

func (s *connectivitySensor) tcpPing(target string) (*float64, *float64) {
	// Try common ports
	for _, port := range []string{"53", "80", "443"} {
		var totalMs float64
		var successes int

		for i := 0; i < s.cfg.PingSamples; i++ {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, port), 1*time.Second)
			if err == nil {
				conn.Close()
				totalMs += float64(time.Since(start).Milliseconds())
				successes++
			}
		}

		if successes > 0 {
			avg := totalMs / float64(successes)
			loss := float64(s.cfg.PingSamples-successes) / float64(s.cfg.PingSamples) * 100
			return &avg, &loss
		}
	}

	// Total failure
	loss := 100.0
	return nil, &loss
}

func (s *connectivitySensor) determineRoute(r map[string]interface{}) string {
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

func (s *connectivitySensor) DoCommand(ctx context.Context, cmd map[string]interface{}) (map[string]interface{}, error) {
	if cmdName, ok := cmd["command"].(string); ok && cmdName == "debug" {
		// Force fresh reading without cache
		return s.collectSimple(ctx), nil
	}
	return nil, fmt.Errorf("unknown command")
}

func (s *connectivitySensor) Close(context.Context) error {
	return nil
}

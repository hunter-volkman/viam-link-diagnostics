package connectivity

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

	"github.com/vishvananda/netlink"
	"go.viam.com/rdk/components/sensor"
	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/resource"
)

var (
	Model            = resource.NewModel("hunter", "connectivity", "sensor")
	errUnimplemented = fmt.Errorf("unimplemented")
)

func init() {
	resource.RegisterComponent(sensor.API, Model,
		resource.Registration[sensor.Sensor, *Config]{
			Constructor: newConnectivitySensor,
		},
	)
}

// Config defines module attributes
type Config struct {
	Iface               string `json:"iface"`                           // "auto" or specific interface
	PingSamples         int    `json:"ping_samples,omitempty"`          // ICMP count (default 3)
	PingTimeoutSec      int    `json:"ping_timeout_sec,omitempty"`      // Per destination timeout (default 3)
	InternetHost        string `json:"internet_host,omitempty"`         // Target for internet probe (default 1.1.1.1)
	RefreshSecs         int    `json:"refresh_secs,omitempty"`          // Cache TTL (default 5)
	NMCli               bool   `json:"nmcli,omitempty"`                 // Try NetworkManager (default true)
	EnableWebRTCSignals bool   `json:"enable_webrtc_signals,omitempty"` // Future use
	MaxReadingsTimeMs   int    `json:"max_readings_time_ms,omitempty"`  // Total GetReadings budget (default 1200)
}

// Validate ensures config is valid
func (cfg *Config) Validate(path string) ([]string, error) {
	// Set defaults
	if cfg.PingSamples <= 0 {
		cfg.PingSamples = 3
	}
	if cfg.PingTimeoutSec <= 0 {
		cfg.PingTimeoutSec = 3
	}
	if cfg.InternetHost == "" {
		cfg.InternetHost = "1.1.1.1"
	}
	if cfg.RefreshSecs <= 0 {
		cfg.RefreshSecs = 5
	}
	if cfg.MaxReadingsTimeMs <= 0 {
		cfg.MaxReadingsTimeMs = 1200
	}
	return nil, nil
}

// Reading represents all link health metrics
type Reading struct {
	// Common fields
	Timestamp     string   `json:"timestamp"`
	Iface         string   `json:"iface"`
	IfaceType     string   `json:"iface_type"` // "wifi" or "ethernet"
	DefaultRoute  bool     `json:"default_route"`
	IPv4          *string  `json:"ipv4"`
	IPv6          *string  `json:"ipv6"`
	GatewayIP     *string  `json:"gateway_ip"`
	DNSServers    []string `json:"dns_servers"`
	Route         string   `json:"route"`    // "LAN", "WAN", or "Internet"
	NMState       *string  `json:"nm_state"` // NetworkManager state
	LatencyGwMs   *float64 `json:"latency_gw_ms"`
	LossGwPct     *float64 `json:"loss_gw_pct"`
	LatencyInetMs *float64 `json:"latency_inet_ms"`
	LossInetPct   *float64 `json:"loss_inet_pct"`
	AgeMs         int64    `json:"age_ms"`

	// Wi-Fi only fields (null on Ethernet)
	SSID           *string  `json:"ssid"`
	BSSID          *string  `json:"bssid"`
	RSSIDbm        *int     `json:"rssi_dbm"`
	LinkQualityPct *int     `json:"link_quality_pct"`
	TxBitrateMbps  *float64 `json:"tx_bitrate_mbps"`
	RxBitrateMbps  *float64 `json:"rx_bitrate_mbps"`
	Channel        *int     `json:"channel"`
	BandGHz        *float64 `json:"band_ghz"`
	TxRetries      *int     `json:"tx_retries"`
	LastAssocTs    *string  `json:"last_assoc_ts"`
}

type connectivitySensor struct {
	resource.AlwaysRebuild
	name   resource.Name
	logger logging.Logger
	cfg    *Config

	cacheMu       sync.RWMutex
	cachedReading *Reading
	cacheTime     time.Time

	cancelCtx  context.Context
	cancelFunc func()
}

func newConnectivitySensor(ctx context.Context, deps resource.Dependencies, rawConf resource.Config, logger logging.Logger) (sensor.Sensor, error) {
	conf, err := resource.NativeConfig[*Config](rawConf)
	if err != nil {
		return nil, err
	}

	return NewSensor(ctx, deps, rawConf.ResourceName(), conf, logger)
}

// NewSensor creates a new connectivity sensor instance
func NewSensor(ctx context.Context, deps resource.Dependencies, name resource.Name, conf *Config, logger logging.Logger) (sensor.Sensor, error) {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())

	s := &connectivitySensor{
		name:       name,
		logger:     logger,
		cfg:        conf,
		cancelCtx:  cancelCtx,
		cancelFunc: cancelFunc,
	}

	return s, nil
}

func (s *connectivitySensor) Name() resource.Name {
	return s.name
}

func (s *connectivitySensor) Readings(ctx context.Context, extra map[string]interface{}) (map[string]interface{}, error) {
	// Check cache
	s.cacheMu.RLock()
	if s.cachedReading != nil && time.Since(s.cacheTime) < time.Duration(s.cfg.RefreshSecs)*time.Second {
		reading := *s.cachedReading
		reading.AgeMs = time.Since(s.cacheTime).Milliseconds()
		s.cacheMu.RUnlock()
		return structToMap(reading)
	}
	s.cacheMu.RUnlock()

	// Collect new reading with timeout
	timeout := time.Duration(s.cfg.MaxReadingsTimeMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reading := s.collectReading(ctx)

	// Update cache
	s.cacheMu.Lock()
	s.cachedReading = reading
	s.cacheTime = time.Now()
	s.cacheMu.Unlock()

	return structToMap(*reading)
}

func (s *connectivitySensor) collectReading(ctx context.Context) *Reading {
	reading := &Reading{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Route:     "Internet", // default assumption
		AgeMs:     0,
	}

	// Determine interface
	iface := s.cfg.Iface
	if iface == "" || iface == "auto" {
		iface = s.getDefaultInterface()
	}
	reading.Iface = iface

	// Detect interface type
	if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl") {
		reading.IfaceType = "wifi"
	} else if strings.HasPrefix(iface, "eth") || strings.HasPrefix(iface, "en") {
		reading.IfaceType = "ethernet"
	} else {
		// Try to detect from sysfs
		reading.IfaceType = s.detectInterfaceType(iface)
	}

	// Collect network info FIRST (not in parallel to avoid race conditions)
	s.collectNetworkInfo(ctx, reading)

	// Then collect Wi-Fi info if applicable
	if reading.IfaceType == "wifi" {
		s.collectWiFiInfo(ctx, reading)
	}

	// Then get NetworkManager state if enabled
	if s.cfg.NMCli {
		reading.NMState = s.getNMState(ctx, iface)
	}

	// Finally do probes
	if reading.GatewayIP != nil && *reading.GatewayIP != "" {
		latency, loss := s.probe(ctx, *reading.GatewayIP)
		reading.LatencyGwMs = latency
		reading.LossGwPct = loss
	}

	// Internet probe
	latency, loss := s.probe(ctx, s.cfg.InternetHost)
	reading.LatencyInetMs = latency
	reading.LossInetPct = loss

	// Determine route based on probe results
	reading.Route = determineRoute(reading.LossGwPct, reading.LossInetPct)

	return reading
}

func (s *connectivitySensor) getDefaultInterface() string {
	// Try netlink first
	routes, err := netlink.RouteList(nil, 4)
	if err == nil {
		for _, route := range routes {
			// Default route has nil or 0.0.0.0/0 destination
			if route.Dst == nil || (route.Dst != nil && route.Dst.String() == "0.0.0.0/0") {
				if route.LinkIndex > 0 {
					link, err := netlink.LinkByIndex(route.LinkIndex)
					if err == nil {
						return link.Attrs().Name
					}
				}
			}
		}
	}

	// Fallback to ip command
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err == nil {
		// Parse: default via 192.168.1.1 dev wlan0
		parts := strings.Fields(string(out))
		for i, part := range parts {
			if part == "dev" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return "unknown"
}

func (s *connectivitySensor) detectInterfaceType(iface string) string {
	// Check /sys/class/net/<iface>/wireless existence
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "test", "-d", fmt.Sprintf("/sys/class/net/%s/wireless", iface))
	if err := cmd.Run(); err == nil {
		return "wifi"
	}
	return "ethernet"
}

func (s *connectivitySensor) collectNetworkInfo(ctx context.Context, reading *Reading) {
	iface := reading.Iface

	// Get interface details via netlink for addresses
	link, err := netlink.LinkByName(iface)
	if err == nil {
		// Get addresses
		addrs, err := netlink.AddrList(link, 0)
		if err == nil {
			for _, addr := range addrs {
				if addr.IP.To4() != nil && reading.IPv4 == nil {
					ipStr := addr.IP.String()
					reading.IPv4 = &ipStr
				} else if addr.IP.To16() != nil && addr.IP.To4() == nil && reading.IPv6 == nil {
					ipStr := addr.IP.String()
					reading.IPv6 = &ipStr
				}
			}
		}
	}

	// Always use shell command for gateway - it's more reliable
	ctx2, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "ip", "route", "show", "default", "dev", iface)
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		output := string(out)
		// Parse: default via 10.1.1.1 dev wlan0
		if match := regexp.MustCompile(`default\s+via\s+([0-9.]+)`).FindStringSubmatch(output); len(match) > 1 {
			gwStr := match[1]
			reading.GatewayIP = &gwStr
			reading.DefaultRoute = true
		}
	}

	// Get DNS servers from resolv.conf
	reading.DNSServers = s.getDNSServers()
}

func (s *connectivitySensor) collectNetworkInfoFallback(ctx context.Context, reading *Reading) {
	iface := reading.Iface

	// Get IP addresses using ip command
	ctx2, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "ip", "addr", "show", iface)
	out, err := cmd.Output()
	if err == nil {
		output := string(out)

		// Parse IPv4: inet 10.1.5.204/20
		if match := regexp.MustCompile(`inet\s+([0-9.]+)/\d+`).FindStringSubmatch(output); len(match) > 1 && reading.IPv4 == nil {
			ipv4 := match[1]
			reading.IPv4 = &ipv4
		}

		// Parse IPv6: inet6 fe80::...
		if match := regexp.MustCompile(`inet6\s+([0-9a-f:]+)/\d+`).FindStringSubmatch(output); len(match) > 1 && reading.IPv6 == nil {
			ipv6 := match[1]
			reading.IPv6 = &ipv6
		}
	}

	// Get default route and gateway
	ctx3, cancel2 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel2()

	// Try to get default route for this specific interface
	cmd = exec.CommandContext(ctx3, "ip", "route", "show", "default", "dev", iface)
	out, err = cmd.Output()
	if err == nil && len(out) > 0 {
		output := string(out)
		// Parse: default via 10.1.1.1 dev wlan0
		if match := regexp.MustCompile(`default\s+via\s+([0-9.]+)`).FindStringSubmatch(output); len(match) > 1 {
			gwStr := match[1]
			reading.GatewayIP = &gwStr
			reading.DefaultRoute = true
			s.logger.Debugw("found gateway via shell", "gateway", gwStr, "interface", iface)
		}
	}

	// If that didn't work, try without specifying device
	if reading.GatewayIP == nil {
		ctx4, cancel3 := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel3()

		cmd = exec.CommandContext(ctx4, "ip", "route", "show", "default")
		out, err = cmd.Output()
		if err == nil {
			output := string(out)
			// Check if it's for our interface
			if strings.Contains(output, "dev "+iface) {
				if match := regexp.MustCompile(`default\s+via\s+([0-9.]+)`).FindStringSubmatch(output); len(match) > 1 {
					gwStr := match[1]
					reading.GatewayIP = &gwStr
					reading.DefaultRoute = true
				}
			}
		}
	}
}

func (s *connectivitySensor) getDNSServers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(ctx, "grep", "^nameserver", "/etc/resolv.conf").Output()
	if err != nil {
		return []string{}
	}

	var servers []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "nameserver" {
			servers = append(servers, parts[1])
		}
	}
	return servers
}

func (s *connectivitySensor) getNMState(ctx context.Context, iface string) *string {
	cmd := exec.CommandContext(ctx, "nmcli", "-t", "-f", "GENERAL.STATE", "dev", "show", iface)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse GENERAL.STATE:100 (connected)
	state := strings.TrimSpace(string(out))
	parts := strings.Split(state, ":")
	if len(parts) >= 2 {
		// Extract the state description between parentheses
		re := regexp.MustCompile(`\((.*?)\)`)
		matches := re.FindStringSubmatch(parts[1])
		if len(matches) > 1 {
			result := matches[1]
			return &result
		}
		// Fallback to raw value
		return &parts[1]
	}
	return nil
}

func (s *connectivitySensor) collectWiFiInfo(ctx context.Context, reading *Reading) {
	iface := reading.Iface
	s.logger.Debugw("starting Wi-Fi collection", "interface", iface)

	// Get link info via iw
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "link")
	out, err := cmd.Output()
	if err != nil {
		s.logger.Debugw("iw link failed, trying fallback", "error", err)

		// Try iwconfig as fallback
		cmd2 := exec.CommandContext(ctx, "iwconfig", iface)
		out2, err2 := cmd2.Output()
		if err2 == nil {
			s.logger.Debugw("using iwconfig fallback")
			s.parseIwconfig(string(out2), reading)
		} else {
			s.logger.Debugw("iwconfig also failed", "error", err2)
		}
		return
	}

	linkInfo := string(out)
	s.logger.Debugw("got iw link output", "length", len(linkInfo))

	// Check if actually connected
	if strings.Contains(linkInfo, "Not connected") {
		s.logger.Debugw("Wi-Fi interface not connected", "iface", iface)
		return
	}

	// Parse BSSID - Connected to XX:XX:XX:XX:XX:XX
	if match := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		bssid := match[1]
		reading.BSSID = &bssid
		s.logger.Debugw("parsed BSSID", "bssid", bssid)
	}

	// Parse SSID
	if match := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		ssid := strings.TrimSpace(match[1])
		reading.SSID = &ssid
		s.logger.Debugw("parsed SSID", "ssid", ssid)
	}

	// Parse frequency
	if match := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if freq, err := strconv.Atoi(match[1]); err == nil {
			channel, band := s.freqToChannelBand(freq)
			reading.Channel = &channel
			reading.BandGHz = &band
			s.logger.Debugw("parsed frequency", "freq", freq, "channel", channel, "band", band)
		}
	}

	// Parse signal
	if match := regexp.MustCompile(`signal:\s*(-?\d+)\s*dBm`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rssi, err := strconv.Atoi(match[1]); err == nil {
			reading.RSSIDbm = &rssi
			quality := s.rssiToQuality(rssi)
			reading.LinkQualityPct = &quality
			s.logger.Debugw("parsed signal", "rssi", rssi, "quality", quality)
		}
	}

	// Parse tx bitrate
	if match := regexp.MustCompile(`tx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.TxBitrateMbps = &rate
			s.logger.Debugw("parsed tx bitrate", "rate", rate)
		}
	}

	// Parse rx bitrate
	if match := regexp.MustCompile(`rx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.RxBitrateMbps = &rate
			s.logger.Debugw("parsed rx bitrate", "rate", rate)
		}
	}

	// Get station info for additional details
	if reading.BSSID != nil {
		cmd = exec.CommandContext(ctx, "iw", "dev", iface, "station", "dump")
		out, err = cmd.Output()
		if err == nil {
			stationInfo := string(out)
			s.logger.Debugw("got station info", "length", len(stationInfo))

			// Parse tx failed as retries
			if match := regexp.MustCompile(`tx failed:\s*(\d+)`).FindStringSubmatch(stationInfo); len(match) > 1 {
				if retries, err := strconv.Atoi(match[1]); err == nil {
					reading.TxRetries = &retries
					s.logger.Debugw("parsed tx retries", "retries", retries)
				}
			}

			// Parse connected time
			if match := regexp.MustCompile(`connected time:\s*(\d+)\s*seconds`).FindStringSubmatch(stationInfo); len(match) > 1 {
				if secs, err := strconv.Atoi(match[1]); err == nil {
					assocTime := time.Now().Add(-time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
					reading.LastAssocTs = &assocTime
					s.logger.Debugw("parsed connected time", "seconds", secs)
				}
			}
		}
	}
}

func (s *connectivitySensor) parseIwconfig(output string, reading *Reading) {
	// ESSID:"NetworkName"
	if match := regexp.MustCompile(`ESSID:"([^"]+)"`).FindStringSubmatch(output); len(match) > 1 {
		ssid := match[1]
		reading.SSID = &ssid
	}

	// Access Point: AA:BB:CC:DD:EE:FF
	if match := regexp.MustCompile(`Access Point:\s*([0-9A-Fa-f:]+)`).FindStringSubmatch(output); len(match) > 1 {
		bssid := match[1]
		reading.BSSID = &bssid
	}

	// Signal level=-45 dBm
	if match := regexp.MustCompile(`Signal level=(-?\d+)\s*dBm`).FindStringSubmatch(output); len(match) > 1 {
		if rssi, err := strconv.Atoi(match[1]); err == nil {
			reading.RSSIDbm = &rssi
			quality := s.rssiToQuality(rssi)
			reading.LinkQualityPct = &quality
		}
	}

	// Link Quality=65/70
	if match := regexp.MustCompile(`Link Quality=(\d+)/(\d+)`).FindStringSubmatch(output); len(match) > 2 {
		if current, err := strconv.Atoi(match[1]); err == nil {
			if max, err := strconv.Atoi(match[2]); err == nil && max > 0 {
				quality := (current * 100) / max
				reading.LinkQualityPct = &quality
			}
		}
	}

	// Frequency:5.18 GHz
	if match := regexp.MustCompile(`Frequency:([\d.]+)\s*GHz`).FindStringSubmatch(output); len(match) > 1 {
		if ghz, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.BandGHz = &ghz
			// Approximate channel from frequency
			freq := int(ghz * 1000)
			channel, _ := s.freqToChannelBand(freq)
			reading.Channel = &channel
		}
	}

	// Bit Rate=72.2 Mb/s
	if match := regexp.MustCompile(`Bit Rate[=:]([\d.]+)\s*Mb/s`).FindStringSubmatch(output); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.TxBitrateMbps = &rate
		}
	}
}

func (s *connectivitySensor) freqToChannelBand(freq int) (channel int, band float64) {
	// 2.4 GHz band
	if freq >= 2412 && freq <= 2484 {
		band = 2.4
		if freq == 2484 {
			channel = 14
		} else {
			channel = (freq-2412)/5 + 1
		}
		return
	}

	// 5 GHz band
	if freq >= 5180 && freq <= 5825 {
		band = float64(freq) / 1000.0
		// Fix channel calculation for 5GHz
		if freq >= 5180 && freq <= 5320 {
			// Channels 36-64
			channel = (freq-5180)/5 + 36
		} else if freq >= 5500 && freq <= 5720 {
			// Channels 100-144
			channel = (freq-5500)/5 + 100
		} else if freq >= 5745 && freq <= 5825 {
			// Channels 149-165
			channel = (freq-5745)/5 + 149
		}
		return
	}

	// 6 GHz band
	if freq >= 5925 && freq <= 7125 {
		band = 6.0
		channel = (freq-5925)/5 + 1
		return
	}

	return 0, 0
}

func (s *connectivitySensor) rssiToQuality(rssi int) int {
	// Convert RSSI to quality percentage
	// -30 dBm = 100%, -90 dBm = 0%
	if rssi >= -30 {
		return 100
	}
	if rssi <= -90 {
		return 0
	}
	return int((float64(rssi+90) / 60.0) * 100)
}

func (s *connectivitySensor) probe(ctx context.Context, target string) (*float64, *float64) {
	// Strip port if present
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	// Try ICMP ping first
	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(s.cfg.PingSamples),
		"-W", strconv.Itoa(s.cfg.PingTimeoutSec), target)
	out, err := cmd.Output()

	if err == nil {
		return s.parsePingOutput(string(out))
	}

	// Fallback to TCP connect timing
	var totalTime float64
	var successCount int

	for i := 0; i < s.cfg.PingSamples; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, "53"),
			time.Duration(s.cfg.PingTimeoutSec)*time.Second)
		elapsed := time.Since(start).Seconds() * 1000 // to ms

		if err == nil {
			conn.Close()
			totalTime += elapsed
			successCount++
		}

		// Small delay between probes
		time.Sleep(10 * time.Millisecond)
	}

	if successCount > 0 {
		avgLatency := totalTime / float64(successCount)
		lossPercent := float64(s.cfg.PingSamples-successCount) / float64(s.cfg.PingSamples) * 100
		return &avgLatency, &lossPercent
	}

	// Total failure
	loss := 100.0
	return nil, &loss
}

func (s *connectivitySensor) parsePingOutput(output string) (*float64, *float64) {
	// Parse RTT: rtt min/avg/max/mdev = 0.486/0.577/0.641/0.065 ms
	if match := regexp.MustCompile(`min/avg/max/mdev = [\d.]+/([\d.]+)/`).FindStringSubmatch(output); len(match) > 1 {
		if latency, err := strconv.ParseFloat(match[1], 64); err == nil {
			// Parse packet loss: 3 packets transmitted, 3 received, 0% packet loss
			if lossMatch := regexp.MustCompile(`(\d+)% packet loss`).FindStringSubmatch(output); len(lossMatch) > 1 {
				if loss, err := strconv.ParseFloat(lossMatch[1], 64); err == nil {
					return &latency, &loss
				}
			}
			// No loss info found, assume 0
			zero := 0.0
			return &latency, &zero
		}
	}

	// Check for 100% loss
	if strings.Contains(output, "100% packet loss") {
		loss := 100.0
		return nil, &loss
	}

	return nil, nil
}

func structToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *connectivitySensor) DoCommand(ctx context.Context, cmd map[string]interface{}) (map[string]interface{}, error) {
	if cmdName, ok := cmd["command"].(string); ok {
		switch cmdName {
		case "debug":
			debug := make(map[string]interface{})

			// Get config and detected interface
			debug["config"] = s.cfg
			iface := s.cfg.Iface
			if iface == "" || iface == "auto" {
				iface = s.getDefaultInterface()
			}
			debug["detected_interface"] = iface

			// Run comprehensive diagnostic commands
			commands := []struct {
				name string
				args []string
			}{
				// Network basics
				{"ip_route_default", []string{"ip", "route", "show", "default"}},
				{"ip_route_all", []string{"ip", "route", "show"}},
				{"ip_addr_show", []string{"ip", "addr", "show"}},
				{"ip_link_show", []string{"ip", "link", "show"}},

				// DNS
				{"cat_resolv_conf", []string{"cat", "/etc/resolv.conf"}},

				// System network info
				{"ls_sys_class_net", []string{"ls", "-la", "/sys/class/net/"}},
			}

			// Interface-specific commands
			if iface != "" && iface != "unknown" {
				commands = append(commands,
					struct {
						name string
						args []string
					}{"ip_addr_show_iface", []string{"ip", "addr", "show", iface}},
					struct {
						name string
						args []string
					}{"ip_route_dev", []string{"ip", "route", "show", "dev", iface}},
				)

				// Wi-Fi specific
				if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl") {
					commands = append(commands,
						struct {
							name string
							args []string
						}{"iw_dev_link", []string{"iw", "dev", iface, "link"}},
						struct {
							name string
							args []string
						}{"iw_dev_station", []string{"iw", "dev", iface, "station", "dump"}},
						struct {
							name string
							args []string
						}{"iw_dev_info", []string{"iw", "dev", iface, "info"}},
						struct {
							name string
							args []string
						}{"iwconfig", []string{"iwconfig", iface}},
					)
				}

				// NetworkManager
				commands = append(commands,
					struct {
						name string
						args []string
					}{"nmcli_dev_show", []string{"nmcli", "-t", "dev", "show", iface}},
					struct {
						name string
						args []string
					}{"nmcli_con_show", []string{"nmcli", "-t", "con", "show"}},
				)
			}

			// Execute all commands
			for _, c := range commands {
				func() {
					ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()

					out, err := exec.CommandContext(ctx2, c.args[0], c.args[1:]...).CombinedOutput()

					result := make(map[string]interface{})
					result["command"] = strings.Join(c.args, " ")
					if err != nil {
						result["error"] = err.Error()
					}
					result["output"] = string(out)

					// Truncate very long outputs
					if len(out) > 10000 {
						result["output"] = string(out[:10000]) + "\n... [truncated]"
						result["truncated"] = true
					}

					debug[c.name] = result
				}()
			}

			// Test connectivity
			pingTargets := []struct {
				name   string
				target string
			}{
				{"loopback", "127.0.0.1"},
				{"gateway", s.getGatewayForDebug()},
				{"dns_local", "10.1.1.1"},
				{"internet_primary", s.cfg.InternetHost},
				{"internet_fallback", "8.8.8.8"},
			}

			for _, pt := range pingTargets {
				if pt.target == "" {
					continue
				}

				func() {
					ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()

					// Try ICMP first
					out, err := exec.CommandContext(ctx2, "ping", "-c", "1", "-W", "1", pt.target).CombinedOutput()

					result := make(map[string]interface{})
					result["target"] = pt.target
					result["name"] = pt.name
					result["command"] = fmt.Sprintf("ping -c 1 -W 1 %s", pt.target)
					if err != nil {
						result["error"] = err.Error()
					}
					result["output"] = string(out)

					// Also try TCP connect
					tcpResult := make(map[string]interface{})
					start := time.Now()
					conn, tcpErr := net.DialTimeout("tcp", net.JoinHostPort(pt.target, "53"), 1*time.Second)
					elapsed := time.Since(start).Milliseconds()

					if tcpErr == nil {
						conn.Close()
						tcpResult["success"] = true
						tcpResult["latency_ms"] = elapsed
					} else {
						tcpResult["success"] = false
						tcpResult["error"] = tcpErr.Error()
					}
					result["tcp_test"] = tcpResult

					debug[fmt.Sprintf("ping_%s", pt.name)] = result
				}()
			}

			// Netlink diagnostics
			netlinkDebug := make(map[string]interface{})

			// Try to get routes via netlink
			if routes, err := netlink.RouteList(nil, 4); err == nil {
				var defaultRoutes []map[string]interface{}
				for _, route := range routes {
					if route.Dst == nil || (route.Dst != nil && route.Dst.String() == "0.0.0.0/0") {
						routeInfo := map[string]interface{}{
							"gateway":    "",
							"link_index": route.LinkIndex,
							"priority":   route.Priority,
							"table":      route.Table,
						}
						if route.Gw != nil {
							routeInfo["gateway"] = route.Gw.String()
						}
						if route.LinkIndex > 0 {
							if link, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
								routeInfo["interface"] = link.Attrs().Name
							}
						}
						defaultRoutes = append(defaultRoutes, routeInfo)
					}
				}
				netlinkDebug["default_routes"] = defaultRoutes
			} else {
				netlinkDebug["error"] = err.Error()
			}

			debug["netlink"] = netlinkDebug

			return debug, nil

		case "clear_cache":
			s.cacheMu.Lock()
			s.cachedReading = nil
			s.cacheMu.Unlock()
			return map[string]interface{}{"status": "cache_cleared"}, nil

		case "get_config":
			return structToMap(s.cfg)

		case "test_reading":
			// Force a fresh reading without cache
			timeout := time.Duration(s.cfg.MaxReadingsTimeMs) * time.Millisecond
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			reading := s.collectReading(ctx2)
			return structToMap(*reading)
		}
	}
	return nil, errUnimplemented
}

func (s *connectivitySensor) getGatewayForDebug() string {
	// Quick gateway lookup for debug
	routes, err := netlink.RouteList(nil, 4)
	if err == nil {
		for _, route := range routes {
			if route.Dst == nil && route.Gw != nil {
				return route.Gw.String()
			}
		}
	}
	return ""
}

func determineRoute(gatewayLoss, internetLoss *float64) string {
	// No gateway = isolated
	if gatewayLoss == nil {
		return "None"
	}

	gwLoss := *gatewayLoss

	// Gateway unreachable
	if gwLoss > 50 {
		return "Limited"
	}

	// Gateway OK but no internet
	if internetLoss == nil || *internetLoss > 50 {
		return "LAN"
	}

	// Full connectivity
	return "Internet"
}

func (s *connectivitySensor) Close(context.Context) error {
	s.cancelFunc()
	return nil
}

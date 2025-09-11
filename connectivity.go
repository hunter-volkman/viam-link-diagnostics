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

	// Collect common network info in parallel
	var wg sync.WaitGroup

	// Basic network info
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.collectNetworkInfo(ctx, reading)
	}()

	// NetworkManager state
	if s.cfg.NMCli {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reading.NMState = s.getNMState(ctx, iface)
		}()
	}

	// Wi-Fi specific
	if reading.IfaceType == "wifi" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.collectWiFiInfo(ctx, reading)
		}()
	}

	wg.Wait()

	// Probes (sequential to avoid flooding)
	if reading.GatewayIP != nil && *reading.GatewayIP != "" {
		latency, loss := s.probe(ctx, *reading.GatewayIP)
		reading.LatencyGwMs = latency
		reading.LossGwPct = loss
	}

	// Internet probe
	latency, loss := s.probe(ctx, s.cfg.InternetHost)
	reading.LatencyInetMs = latency
	reading.LossInetPct = loss

	return reading
}

func (s *connectivitySensor) getDefaultInterface() string {
	// Try netlink first
	routes, err := netlink.RouteList(nil, 4)
	if err == nil {
		for _, route := range routes {
			if route.Dst == nil { // default route
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

	// macOS fallback - use route command
	out, err = exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
	if err == nil {
		// Parse macOS route output for interface
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "interface:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					return parts[1]
				}
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

	// Get interface details via netlink
	link, err := netlink.LinkByName(iface)
	if err != nil {
		s.logger.Debugw("failed to get link", "iface", iface, "error", err)
		return
	}

	// Get addresses
	addrs, err := netlink.AddrList(link, 0) // 0 = all families
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

	// Get ALL routes to find the default gateway (not interface-specific)
	routes, err := netlink.RouteList(nil, 4) // nil = all interfaces, 4 = IPv4
	if err == nil {
		for _, route := range routes {
			if route.Dst == nil && route.Gw != nil { // default route with gateway
				reading.DefaultRoute = true
				gwStr := route.Gw.String()
				reading.GatewayIP = &gwStr
				break
			}
		}
	}

	// Get DNS servers from resolv.conf
	reading.DNSServers = s.getDNSServers()
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

	// Get link info via iw
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "link")
	out, err := cmd.Output()
	if err != nil {
		s.logger.Debugw("iw link failed", "error", err)
		return
	}

	linkInfo := string(out)

	// Parse BSSID - Connected to XX:XX:XX:XX:XX:XX
	if match := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		bssid := match[1]
		reading.BSSID = &bssid
	}

	// Parse SSID - appears after "SSID:"
	if match := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		ssid := strings.TrimSpace(match[1])
		reading.SSID = &ssid
	}

	// Parse frequency
	if match := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if freq, err := strconv.Atoi(match[1]); err == nil {
			channel, band := s.freqToChannelBand(freq)
			reading.Channel = &channel
			reading.BandGHz = &band
		}
	}

	// Parse signal strength from link output
	if match := regexp.MustCompile(`signal:\s*(-?\d+)\s*dBm`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rssi, err := strconv.Atoi(match[1]); err == nil {
			reading.RSSIDbm = &rssi
			quality := s.rssiToQuality(rssi)
			reading.LinkQualityPct = &quality
		}
	}

	// Parse tx bitrate from link output
	if match := regexp.MustCompile(`tx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.TxBitrateMbps = &rate
		}
	}

	// Parse rx bitrate from link output
	if match := regexp.MustCompile(`rx bitrate:\s*([\d.]+)\s*MBit/s`).FindStringSubmatch(linkInfo); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			reading.RxBitrateMbps = &rate
		}
	}

	// Get station info for additional details
	if reading.BSSID != nil {
		cmd = exec.CommandContext(ctx, "iw", "dev", iface, "station", "dump")
		out, err = cmd.Output()
		if err == nil {
			stationInfo := string(out)

			// Parse tx failed as retries
			if match := regexp.MustCompile(`tx failed:\s*(\d+)`).FindStringSubmatch(stationInfo); len(match) > 1 {
				if retries, err := strconv.Atoi(match[1]); err == nil {
					reading.TxRetries = &retries
				}
			}

			// Parse connected time
			if match := regexp.MustCompile(`connected time:\s*(\d+)\s*seconds`).FindStringSubmatch(stationInfo); len(match) > 1 {
				if secs, err := strconv.Atoi(match[1]); err == nil {
					assocTime := time.Now().Add(-time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
					reading.LastAssocTs = &assocTime
				}
			}
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
		channel = (freq-5180)/5 + 36
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
			// Run all diagnostic commands and return raw outputs
			debug := make(map[string]interface{})

			// Get config and detected interface
			debug["config"] = s.cfg
			iface := s.cfg.Iface
			if iface == "" || iface == "auto" {
				iface = s.getDefaultInterface()
			}
			debug["detected_interface"] = iface

			// Run diagnostic commands
			commands := []struct {
				name string
				args []string
			}{
				{"ip_route_default", []string{"ip", "route", "show", "default"}},
				{"ip_addr_show", []string{"ip", "addr", "show"}},
				{"ip_link_show", []string{"ip", "link", "show"}},
				{"route_get_default", []string{"route", "-n", "get", "default"}},
				{"ifconfig_all", []string{"ifconfig"}},
				{"netstat_rn", []string{"netstat", "-rn"}},
				{"cat_resolv_conf", []string{"cat", "/etc/resolv.conf"}},
				{"ls_sys_class_net", []string{"ls", "-la", "/sys/class/net/"}},
			}

			for _, c := range commands {
				func() {
					ctx2, cancel := context.WithTimeout(context.Background(), 1*time.Second)
					defer cancel()

					out, err := exec.CommandContext(ctx2, c.args[0], c.args[1:]...).CombinedOutput()

					result := make(map[string]interface{})
					result["command"] = strings.Join(c.args, " ")
					if err != nil {
						result["error"] = err.Error()
					}
					result["output"] = string(out)
					debug[c.name] = result
				}()
			}

			// If we have a specific interface, try interface-specific commands
			if iface != "" && iface != "unknown" {
				ifaceCommands := []struct {
					name string
					args []string
				}{
					{"ifconfig_iface", []string{"ifconfig", iface}},
					{"ip_addr_show_iface", []string{"ip", "addr", "show", iface}},
				}

				// Wi-Fi specific commands
				if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl") {
					ifaceCommands = append(ifaceCommands,
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

				// NetworkManager commands
				ifaceCommands = append(ifaceCommands,
					struct {
						name string
						args []string
					}{"nmcli_dev_show", []string{"nmcli", "-t", "dev", "show", iface}},
					struct {
						name string
						args []string
					}{"nmcli_con_show", []string{"nmcli", "-t", "con", "show"}},
				)

				for _, c := range ifaceCommands {
					func() {
						ctx2, cancel := context.WithTimeout(context.Background(), 1*time.Second)
						defer cancel()

						out, err := exec.CommandContext(ctx2, c.args[0], c.args[1:]...).CombinedOutput()

						result := make(map[string]interface{})
						result["command"] = strings.Join(c.args, " ")
						if err != nil {
							result["error"] = err.Error()
						}
						result["output"] = string(out)
						debug[c.name] = result
					}()
				}
			}

			// Test ping
			pingTargets := []string{"127.0.0.1", s.cfg.InternetHost, "8.8.8.8"}
			for _, target := range pingTargets {
				func() {
					ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()

					out, err := exec.CommandContext(ctx2, "ping", "-c", "1", "-W", "1", target).CombinedOutput()

					result := make(map[string]interface{})
					result["target"] = target
					result["command"] = fmt.Sprintf("ping -c 1 -W 1 %s", target)
					if err != nil {
						result["error"] = err.Error()
					}
					result["output"] = string(out)
					debug[fmt.Sprintf("ping_%s", strings.ReplaceAll(target, ".", "_"))] = result
				}()
			}

			return debug, nil

		case "clear_cache":
			s.cacheMu.Lock()
			s.cachedReading = nil
			s.cacheMu.Unlock()
			return map[string]interface{}{"status": "cache_cleared"}, nil

		case "get_config":
			return structToMap(s.cfg)
		}
	}
	return nil, errUnimplemented
}

func (s *connectivitySensor) Close(context.Context) error {
	s.cancelFunc()
	return nil
}

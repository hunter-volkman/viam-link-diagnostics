package connectivity

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// parseIwLink extracts basic Wi-Fi connection info from 'iw dev <iface> link' output
func parseIwLink(output string) (ssid, bssid string, freq int) {
	// SSID: Network Name
	if match := regexp.MustCompile(`SSID: (.+)`).FindStringSubmatch(output); len(match) > 1 {
		ssid = strings.TrimSpace(match[1])
	}

	// Connected to aa:bb:cc:dd:ee:ff (on wlan0)
	if match := regexp.MustCompile(`Connected to ([0-9a-fA-F:]+)`).FindStringSubmatch(output); len(match) > 1 {
		bssid = strings.ToLower(match[1])
	}

	// freq: 5180
	if match := regexp.MustCompile(`freq: (\d+)`).FindStringSubmatch(output); len(match) > 1 {
		freq, _ = strconv.Atoi(match[1])
	}

	return
}

// parseIwStation extracts detailed Wi-Fi stats from 'iw dev <iface> station dump' output
func parseIwStation(output string) *wifiStats {
	stats := &wifiStats{}

	// signal: -45 dBm
	if match := regexp.MustCompile(`signal:\s+(-?\d+) dBm`).FindStringSubmatch(output); len(match) > 1 {
		if rssi, err := strconv.Atoi(match[1]); err == nil {
			stats.rssi = &rssi
		}
	}

	// tx bitrate: 144.4 MBit/s
	if match := regexp.MustCompile(`tx bitrate:\s+([\d.]+) MBit/s`).FindStringSubmatch(output); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			stats.txBitrate = &rate
		}
	}

	// rx bitrate: 173.5 MBit/s
	if match := regexp.MustCompile(`rx bitrate:\s+([\d.]+) MBit/s`).FindStringSubmatch(output); len(match) > 1 {
		if rate, err := strconv.ParseFloat(match[1], 64); err == nil {
			stats.rxBitrate = &rate
		}
	}

	// tx retries: 12
	if match := regexp.MustCompile(`tx retries:\s+(\d+)`).FindStringSubmatch(output); len(match) > 1 {
		if retries, err := strconv.Atoi(match[1]); err == nil {
			stats.txRetries = &retries
		}
	}

	// connected time: 3600 seconds
	if match := regexp.MustCompile(`connected time:\s+(\d+) seconds`).FindStringSubmatch(output); len(match) > 1 {
		if secs, err := strconv.Atoi(match[1]); err == nil {
			assocTime := time.Now().Add(-time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
			stats.lastAssoc = &assocTime
		}
	}

	return stats
}

// parseNmcliState extracts NetworkManager state from 'nmcli -t -f GENERAL.STATE dev show <iface>'
func parseNmcliState(output string) string {
	// GENERAL.STATE:100 (connected)
	state := strings.TrimSpace(output)
	parts := strings.Split(state, ":")
	if len(parts) < 2 {
		return ""
	}

	// Extract state between parentheses
	if match := regexp.MustCompile(`\((.*?)\)`).FindStringSubmatch(parts[1]); len(match) > 1 {
		return match[1]
	}

	// Fallback to numeric code
	return strings.TrimSpace(parts[1])
}

// parsePingOutput extracts latency and loss from ping command output
func parsePingOutput(output string) (latencyMs, lossPct *float64) {
	// rtt min/avg/max/mdev = 18.486/18.699/18.913/0.174 ms
	if match := regexp.MustCompile(`min/avg/max/mdev = [\d.]+/([\d.]+)/`).FindStringSubmatch(output); len(match) > 1 {
		if avg, err := strconv.ParseFloat(match[1], 64); err == nil {
			latencyMs = &avg
		}
	}

	// 3 packets transmitted, 3 received, 0% packet loss
	if match := regexp.MustCompile(`(\d+)% packet loss`).FindStringSubmatch(output); len(match) > 1 {
		if loss, err := strconv.ParseFloat(match[1], 64); err == nil {
			lossPct = &loss
		}
	}

	// Handle 100% loss case
	if latencyMs == nil && strings.Contains(output, "100% packet loss") {
		loss := 100.0
		lossPct = &loss
	}

	// If we have latency but no explicit loss, assume 0%
	if latencyMs != nil && lossPct == nil {
		zero := 0.0
		lossPct = &zero
	}

	return
}

// parseResolvConf extracts nameserver IPs from /etc/resolv.conf content
func parseResolvConf(content string) []string {
	var servers []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Basic IP validation
				if strings.Contains(parts[1], ".") || strings.Contains(parts[1], ":") {
					servers = append(servers, parts[1])
				}
			}
		}
	}

	return servers
}

// parseIpRoute extracts gateway IP from 'ip route show default' output
func parseIpRoute(output string) string {
	// default via 192.168.1.1 dev wlan0 proto dhcp metric 600
	parts := strings.Fields(output)
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// freqToChannelBand converts Wi-Fi frequency (MHz) to channel number and band (GHz)
func freqToChannelBand(freq int) (channel int, band float64) {
	switch {
	case freq >= 2412 && freq <= 2484:
		// 2.4 GHz band
		band = 2.4
		if freq == 2484 {
			channel = 14 // Japan
		} else {
			channel = (freq-2412)/5 + 1
		}

	case freq >= 5180 && freq <= 5825:
		// 5 GHz band
		band = float64(freq) / 1000.0
		channel = (freq-5180)/5 + 36

	case freq >= 5925 && freq <= 7125:
		// 6 GHz band
		band = 6.0
		channel = (freq-5925)/5 + 1

	default:
		// Unknown frequency
		band = float64(freq) / 1000.0
		channel = 0
	}

	return
}

// rssiToQuality converts RSSI (dBm) to quality percentage (0-100)
func rssiToQuality(rssi int) int {
	// Map RSSI range [-90, -30] to quality [0, 100]
	// -30 dBm or better = 100%
	// -90 dBm or worse = 0%
	switch {
	case rssi >= -30:
		return 100
	case rssi <= -90:
		return 0
	default:
		// Linear interpolation
		return int((float64(rssi+90) / 60.0) * 100)
	}
}

// wifiStats holds parsed Wi-Fi statistics
type wifiStats struct {
	rssi      *int
	txBitrate *float64
	rxBitrate *float64
	txRetries *int
	lastAssoc *string
}

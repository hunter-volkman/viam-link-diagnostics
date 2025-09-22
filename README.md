# Link Diagnostics Module 

A Viam `sensor` component for network connectivity monitoring and diagnostics.

## Model hunter:link-diagnostics:sensor

This model implements the `rdk:component:sensor` API to provide real-time network diagnostics including Wi-Fi signal quality, connectivity tests, packet loss statistics, and network performance metrics.

### Configuration
The following attribute template can be used to configure this model:

```json
{
  "iface": "auto",
  "refresh_secs": 5,
  "internet_host": "8.8.8.8",
  "ping_samples": 3,
  "ping_timeout_sec": 1,
  "test_dns": true,
  "test_tcp_ports": true
}
```

#### Attributes

The following attributes are available for this model:

| Name          | Type   | Inclusion | Description                |
|---------------|--------|-----------|----------------------------|
| `iface` | string  | Optional  | Network interface to monitor ("auto" for automatic detection). Defaults to `"auto"`. |
| `refresh_secs` | integer | Optional  | Cache duration in seconds before refreshing readings. Defaults to `5`. |
| `internet_host` | string | Optional  | Target host for internet connectivity tests. Defaults to `"8.8.8.8"`. |
| `ping_samples` | integer | Optional  | Number of ping samples to send for latency/loss calculation. Defaults to `3`. |
| `ping_timeout_sec` | integer | Optional  | Timeout per ping sample in seconds. Defaults to `1`. |
| `test_dns` | boolean | Optional  | Enable DNS resolution testing. Defaults to `true`. |
| `test_tcp_ports` | boolean | Optional  | Enable TCP port connectivity testing. Defaults to `true`. |

#### Example Configuration

```json
{
  "iface": "wlan0",
  "refresh_secs": 10,
  "internet_host": "1.1.1.1",
  "ping_samples": 5,
  "test_dns": true,
  "test_tcp_ports": true
}
```

### Readings

#### Network Configuration
* `iface` - Active network interface name
* `iface_type` - Interface type ("wifi" or "ethernet")
* `ipv4` - IPv4 address
* `subnet_bits` - Subnet mask in CIDR notation
* `gateway_ip` - Default gateway address
* `dns_servers` - Comma-separated list of DNS servers
* `mac_address` - Interface MAC address
* `mtu` - Maximum transmission unit size
* `link_state` - Interface state ("UP" or "DOWN")

#### Wi-Fi Metrics (when applicable)
* `wifi_connected` - Wi-Fi connection status
* `ssid` - Connected network name
* `bssid` - Access point MAC address
* `rssi_dbm` - Signal strength in dBm
* `link_quality_pct` - Signal quality percentage
* `channel` - Wi-Fi channel number
* `band_ghz` - Frequency band (2.4 or 5)
* `freq_mhz` - Exact frequency in MHz
* `tx_bitrate_mbps` - Transmit bitrate in Mbps
* `rx_bitrate_mbps` - Receive bitrate in Mbps

#### Connectivity Tests
* `latency_gw_ms` - Latency to gateway in milliseconds
* `loss_gw_pct` - Packet loss to gateway percentage
* `latency_inet_ms` - Latency to internet in milliseconds
* `loss_inet_pct` - Packet loss to internet percentage
* `route` - Connectivity status ("Internet", "LAN", or "None")
* `dns_working` - DNS resolution status
* `dns_latency_ms` - DNS lookup time in milliseconds
* `tcp_443_reachable` - HTTPS port connectivity
* `tcp_53_reachable` - DNS port connectivity

#### Network Statistics
* `tx_packets` - Total transmitted packets
* `rx_packets` - Total received packets
* `tx_dropped` - Dropped transmit packets
* `rx_dropped` - Dropped receive packets
* `tx_errors` - Transmit errors
* `rx_errors` - Receive errors
* `rx_drop_rate_pct` - Receive packet drop rate percentage
* `tx_drop_rate_pct` - Transmit packet drop rate percentage
* `rx_error_rate_pct` - Receive error rate percentage
* `tx_error_rate_pct` - Transmit error rate percentage

### DoCommand

The sensor supports the following commands via the `do_command` method:

#### ping
Test connectivity to a specific target with ICMP ping.

```json
{
  "command": "ping",
  "target": "google.com"
}
```

**Response:**
```json
{
  "target": "google.com",
  "latency_ms": 7.278,
  "loss_pct": 0,
  "timestamp": "2025-09-22T20:22:22Z"
}
```

#### traceroute
Trace the network path to a target host.

```json
{
  "command": "traceroute",
  "target": "8.8.8.8"
}
```

**Response:**
```json
{
  "target": "8.8.8.8",
  "output": "traceroute to 8.8.8.8, 10 hops max...",
  "timestamp": "2025-09-22T20:23:36Z"
}
```

#### speedtest
Run an internet speed test.

```json
{
  "command": "speedtest"
}
```

**Response:**
```json
{
  "download_mbps": 52.68,
  "upload_mbps": 100.25,
  "ping_ms": 12.865,
  "server": "Optimum Online",
  "location": "Hicksville, NY",
  "timestamp": "2025-09-22T20:25:03Z"
}
```

#### debug
Get uncached diagnostic readings.

```json
{
  "command": "debug"
}
```

### Installation
1. Ensure required system tools are installed:
```bash
sudo apt-get install iproute2 iw traceroute speedtest-cli
```
2. Add the module (to your Viam configuration).

### Use Cases
* Network connectivity monitoring
* Wi-Fi signal quality tracking
* Internet reliability testing
* Network troubleshooting and diagnostics
* Automated connectivity alerts
* Network performance logging
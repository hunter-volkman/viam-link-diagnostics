package connectivity

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"
)

// probeTarget measures latency and loss to a target host
func (s *connectivitySensor) probeTarget(ctx context.Context, target string) (*float64, *float64) {
	// Remove port if present
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	// Try ICMP first (most accurate)
	if latency, loss := s.probeICMP(ctx, target); latency != nil || loss != nil {
		return latency, loss
	}

	// Fallback to TCP timing
	return s.probeTCP(ctx, target)
}

// probeICMP uses ping command for ICMP echo requests
func (s *connectivitySensor) probeICMP(ctx context.Context, target string) (*float64, *float64) {
	// Build ping command with timeout
	args := []string{
		"-c", strconv.Itoa(s.cfg.PingSamples), // count
		"-W", strconv.Itoa(s.cfg.PingTimeoutSec), // timeout per packet
		target,
	}

	cmd := exec.CommandContext(ctx, "ping", args...)
	output, err := cmd.Output()

	if err != nil {
		// Check if it's just 100% packet loss (ping returns exit code 1)
		if output != nil && len(output) > 0 {
			latency, loss := parsePingOutput(string(output))
			if loss != nil {
				return latency, loss
			}
		}
		// ICMP not available or blocked
		return nil, nil
	}

	return parsePingOutput(string(output))
}

// probeTCP measures latency using TCP connect timing
func (s *connectivitySensor) probeTCP(ctx context.Context, target string) (*float64, *float64) {
	// Try common ports in order of likelihood
	ports := []string{"53", "80", "443"}

	for _, port := range ports {
		latency, loss := s.probeTCPPort(ctx, target, port)
		if latency != nil || loss != nil {
			return latency, loss
		}
	}

	// All ports failed
	loss := 100.0
	return nil, &loss
}

// probeTCPPort measures latency to a specific TCP port
func (s *connectivitySensor) probeTCPPort(ctx context.Context, target, port string) (*float64, *float64) {
	var totalMs float64
	var successes int

	addr := net.JoinHostPort(target, port)
	timeout := time.Duration(s.cfg.PingTimeoutSec) * time.Second

	for i := 0; i < s.cfg.PingSamples; i++ {
		start := time.Now()

		// Use deadline from context if shorter
		dialCtx := ctx
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining < timeout {
				timeout = remaining
			}
		}

		conn, err := (&net.Dialer{
			Timeout: timeout,
		}).DialContext(dialCtx, "tcp", addr)

		elapsed := time.Since(start)

		if err == nil {
			conn.Close()
			totalMs += float64(elapsed.Milliseconds())
			successes++
		}

		// Small delay between probes to avoid rate limiting
		if i < s.cfg.PingSamples-1 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	if successes == 0 {
		return nil, nil // Try next port
	}

	avgLatency := totalMs / float64(successes)
	lossPct := float64(s.cfg.PingSamples-successes) / float64(s.cfg.PingSamples) * 100

	return &avgLatency, &lossPct
}

// probeGateway measures connectivity to the default gateway
func (s *connectivitySensor) probeGateway(ctx context.Context, gatewayIP string) (*float64, *float64) {
	if gatewayIP == "" {
		return nil, nil
	}

	// Gateway probes should be fast - reduce timeout
	savedTimeout := s.cfg.PingTimeoutSec
	s.cfg.PingTimeoutSec = 1
	defer func() { s.cfg.PingTimeoutSec = savedTimeout }()

	return s.probeTarget(ctx, gatewayIP)
}

// probeInternet measures connectivity to internet hosts
func (s *connectivitySensor) probeInternet(ctx context.Context) (*float64, *float64) {
	// Primary target
	if latency, loss := s.probeTarget(ctx, s.cfg.InternetHost); latency != nil {
		return latency, loss
	}

	// Fallback to Google DNS if primary fails
	if s.cfg.InternetHost != "8.8.8.8" {
		if latency, loss := s.probeTarget(ctx, "8.8.8.8"); latency != nil {
			return latency, loss
		}
	}

	// Try Cloudflare as last resort
	if s.cfg.InternetHost != "1.1.1.1" {
		return s.probeTarget(ctx, "1.1.1.1")
	}

	// Total internet failure
	loss := 100.0
	return nil, &loss
}

// determineRoute classifies the network path based on probes
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

// checkICMPAvailable tests if ICMP ping is available (non-root)
func checkICMPAvailable() bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", "127.0.0.1")
	err := cmd.Run()
	return err == nil
}

// selectProbeMethod returns the best available probe method
func (s *connectivitySensor) selectProbeMethod() string {
	if checkICMPAvailable() {
		return "icmp"
	}
	return "tcp"
}

// ProbeResult holds probe measurements
type ProbeResult struct {
	Target    string
	LatencyMs *float64
	LossPct   *float64
	Method    string // "icmp" or "tcp"
	Timestamp time.Time
}

// runParallelProbes executes gateway and internet probes concurrently
func (s *connectivitySensor) runParallelProbes(ctx context.Context, gatewayIP string) (gwResult, inetResult ProbeResult) {
	type result struct {
		isGateway bool
		probe     ProbeResult
	}

	results := make(chan result, 2)

	// Gateway probe
	if gatewayIP != "" {
		go func() {
			latency, loss := s.probeGateway(ctx, gatewayIP)
			results <- result{
				isGateway: true,
				probe: ProbeResult{
					Target:    gatewayIP,
					LatencyMs: latency,
					LossPct:   loss,
					Method:    s.selectProbeMethod(),
					Timestamp: time.Now(),
				},
			}
		}()
	} else {
		// No gateway to probe
		results <- result{isGateway: true, probe: ProbeResult{}}
	}

	// Internet probe
	go func() {
		latency, loss := s.probeInternet(ctx)
		results <- result{
			isGateway: false,
			probe: ProbeResult{
				Target:    s.cfg.InternetHost,
				LatencyMs: latency,
				LossPct:   loss,
				Method:    s.selectProbeMethod(),
				Timestamp: time.Now(),
			},
		}
	}()

	// Collect results
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.isGateway {
				gwResult = r.probe
			} else {
				inetResult = r.probe
			}
		case <-ctx.Done():
			// Context cancelled, return what we have
			return
		}
	}

	return
}

// formatProbeError creates a descriptive error for probe failures
func formatProbeError(target string, method string, err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("probe to %s via %s failed: %v", target, method, err)
}

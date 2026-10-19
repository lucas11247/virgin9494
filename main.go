package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort            = "8080"
	fallbackSelfMemMB      = 128
	fallbackXrayMemMB      = 550
	defaultGOMAXPROCS      = 2
	gatewayMemPercent      = 12
	xrayMemPercent         = 55
	httpDrainTimeout       = 10 * time.Second
	edgeKeepAlivePeriod    = 15 * time.Second
	drainPropagationWindow = 500 * time.Millisecond
	tcpUserTimeoutOpt      = 18
)

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, xrayMB int) {
	gwMB, xrayMB = fallbackSelfMemMB, fallbackXrayMemMB
	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		xrayMB = totalMB * xrayMemPercent / 100

		allowedMB := totalMB * 67 / 100
		if gwMB < 32 {
			gwMB = 32
		}
		if xrayMB < 64 {
			xrayMB = 64
		}
		if total := gwMB + xrayMB; total > allowedMB && allowedMB >= 96 {
			gwMB = allowedMB * gatewayMemPercent / 67
			xrayMB = allowedMB * xrayMemPercent / 67
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	xrayMB = getEnvInt("BERMUDA_XRAY_MEM_MB", xrayMB)
	return gwMB, xrayMB
}

func applyMemoryCeiling(selfMB int) {
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
		return 0, false
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n <= 0 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimRight(h, "/")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isRailwayManagedDomain(h string) bool {
	return h != "" && (strings.Contains(h, "railway.app") || strings.HasSuffix(h, ".railway.internal"))
}

func isRailwayPublicDomain(h string) bool {
	return h != "" && strings.Contains(h, "railway.app") && !strings.HasSuffix(h, ".railway.internal")
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "eqdc") || strings.Contains(s, "iad"):
		return "us-east4"
	case strings.Contains(s, "europe") || strings.Contains(s, "amsterdam") || strings.Contains(s, "drams") || strings.Contains(s, "ams") || strings.Contains(s, "fra"):
		return "europe-west4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc"):
		return "us-west"
	case strings.Contains(s, "asia") || strings.Contains(s, "singapore") || strings.Contains(s, "eqsg") || strings.Contains(s, "ap-"):
		return "asia-southeast1"
	default:
		return "europe-west4"
	}
}

func resolveInfrastructureDomains() (railwayDomain, customDomain string) {
	staticURL := cleanHost(getEnv("RAILWAY_STATIC_URL", ""))
	publicDomain := cleanHost(getEnv("RAILWAY_PUBLIC_DOMAIN", ""))
	explicitRailway := cleanHost(getEnv("RAILWAY_DEFAULT_DOMAIN", getEnv("BERMUDA_RAILWAY_DOMAIN", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{explicitRailway, staticURL, publicDomain} {
		if isRailwayPublicDomain(candidate) {
			railwayDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, staticURL, explicitRailway} {
		if candidate != "" && !isRailwayManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return railwayDomain, customDomain
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cfCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(23 * time.Second)

	if cfCancel != nil {
		cfCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status flipped to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP server listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-8*time.Second), time.Now().Add(15*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP server drain timeout (%v); forcing listener closure", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP server listener drained successfully")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active WebSocket/hijacked tunnels to conclude...")
		tunnelDeadline := minTime(hardDeadline.Add(-8*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Force-closing remaining hijacked sockets and backend pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Tearing down child Xray process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Stealth Gateway...")

	gwMB, xrayMB := deriveMemoryBudget()
	applyMemoryCeiling(gwMB)
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(xrayMB))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(procs))
	log.Printf("[Runtime] Dynamic memory ceiling: Gateway=%dMiB, Xray=%dMiB (GOGC=100) | GOMAXPROCS=%d",
		gwMB, xrayMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("PORT", defaultPort)
	railwayDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("REGION", ""))
	if rawRegion == "" {
		rawRegion = getEnv("RAILWAY_REPLICA_REGION", "")
	}
	if rawRegion == "" {
		rawRegion = getEnv("RAILWAY_REGION", "")
	}
	region := normalizeRegion(rawRegion)

	sup := NewSupervisor()
	if err := sup.PreflightContext(sigCtx); err != nil {
		log.Printf("[Gateway] Warning: Supervisor preflight issue: %v. Continuing to start...", err)
	}

	cfToken := getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", ""))
	cfZoneID := getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", ""))
	var cf *CloudflareClient
	cfCtx, cfCancel := context.WithCancel(sigCtx)
	defer cfCancel()

	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if railwayDomain != "" {
			cf.SetRailwayOrigin(railwayDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}

		probeCtx, probeCancel := context.WithTimeout(cfCtx, 8*time.Second)
		if cfDomain, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDomain != "" {
			log.Printf("[Cloudflare] Auto-resolved Zone Domain: %s", cfDomain)
			if customDomain == "" || strings.HasSuffix(cfDomain, "."+customDomain) {
				customDomain = cfDomain
				cf.SetPreferredDomain(customDomain)
			}
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()

		if discoveredRW := cf.GetRailwayOrigin(); discoveredRW != "" {
			if railwayDomain == "" || (!isFullRailwayServiceDomain(railwayDomain) && isFullRailwayServiceDomain(discoveredRW)) {
				railwayDomain = discoveredRW
			}
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	sup.SetInfrastructureDomains(railwayDomain, customDomain, region)

	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = railwayDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Infrastructure Topology: RailwayDomain=%q | CloudflareDomain=%q | Region=%q",
		railwayDomain, customDomain, region)

	if customDomain != "" {
		log.Printf("[Supervisor] » Cloudflare Portal Link: %s", buildPortalURL(customDomain, sup.MasterKey()))
	}
	if railwayDomain != "" {
		log.Printf("[Supervisor] » Railway Portal Link   : %s", buildPortalURL(railwayDomain, sup.MasterKey()))
	}

	gw := NewGateway(sup, cf, railwayDomain, customDomain, region)

	if cf != nil {
		cf.SetTopologyCallback(func(rwDom, cfDom string) {
			sup.SetInfrastructureDomains(rwDom, cfDom, region)
			gw.SetInfrastructureDomains(rwDom, cfDom, region)
		})
		go cf.Tune(cfCtx)
	}

	supCtx, supCancel := context.WithCancel(context.Background())

	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	lc := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000); e != nil {
					controlErr = e
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", srv.Addr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind listener on %s: %v", srv.Addr, err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("[Gateway] Edge listener active on :%s (PID %d, GOMAXPROCS=%d)", port, os.Getpid(), procs)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server failure: %v", err)
		teardown(srv, gw, sup, supCancel, cfCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Supervisor halted unexpectedly: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cfCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal intercepted. Commencing graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cfCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Stealth Gateway shutdown complete. Ports released cleanly. Exit 0.")
}

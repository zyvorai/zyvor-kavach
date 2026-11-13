package edr

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Agentless syslog listener (observation only). OPT-IN: nothing is bound unless
// KAVACH_SYSLOG lists explicit listen addresses AND KAVACH_SYSLOG_ALLOW lists source CIDRs.
//
//	KAVACH_SYSLOG=udp:10.0.0.5:514,tcp:10.0.0.5:514,tls:10.0.0.5:6514
//	KAVACH_SYSLOG_ALLOW=10.1.0.0/16,192.0.2.7
//	KAVACH_SYSLOG_TLS_CERT / KAVACH_SYSLOG_TLS_KEY   (required for tls: listeners)
//	KAVACH_SYSLOG_MAX_CONNS (64)  KAVACH_SYSLOG_RATE (msgs/s per source, 200)
//
// The listener never writes anything back to a sender. Plaintext syslog is unauthenticated and
// unencrypted: the allowlist is only an address filter and UDP sources can be spoofed.

const (
	syslogQueueCap     = 4096
	syslogMaxSources   = 4096
	syslogSampleCap    = 50
	syslogIdleTimeout  = 60 * time.Second
	syslogDefMaxConns  = 64
	syslogDefRate      = 200.0
	syslogMaxOctetLen  = 5 // digits
	syslogTrackedLast  = 1024
	syslogEnvListen    = "KAVACH_SYSLOG"
	syslogEnvAllow     = "KAVACH_SYSLOG_ALLOW"
	syslogPlainWarning = "WARNING: syslog over udp/tcp is plaintext and unauthenticated; sender addresses can be spoofed (UDP) and content can be read or altered on the path. Prefer tls: listeners and a restricted network."
)

// SyslogConfig is the validated listener configuration.
type SyslogConfig struct {
	Listens   []SyslogListen
	Allow     []*net.IPNet
	AllowText []string
	TLSCert   string
	TLSKey    string
	MaxConns  int
	Rate      float64 // messages per second per source
	Burst     float64
}

// SyslogListen is one explicit listen address.
type SyslogListen struct{ Proto, Addr string } // Proto: udp, tcp, tls

// ParseSyslogConfig validates the env-style strings. It refuses an empty allowlist and any
// listen entry without an explicit host:port.
func ParseSyslogConfig(listen, allow string) (*SyslogConfig, error) {
	c := &SyslogConfig{MaxConns: syslogDefMaxConns, Rate: syslogDefRate}
	for _, it := range strings.Split(listen, ",") {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		i := strings.IndexByte(it, ':')
		if i < 0 {
			return nil, fmt.Errorf("syslog listen %q: want proto:host:port", it)
		}
		proto, addr := strings.ToLower(it[:i]), it[i+1:]
		if proto != "udp" && proto != "tcp" && proto != "tls" {
			return nil, fmt.Errorf("syslog listen %q: proto must be udp, tcp or tls", it)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("syslog listen %q: an explicit host:port is required (no default bind; bare ports are refused)", it)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
			return nil, fmt.Errorf("syslog listen %q: bad port", it)
		}
		c.Listens = append(c.Listens, SyslogListen{proto, addr})
	}
	if len(c.Listens) == 0 {
		return nil, errors.New("syslog: no listen addresses")
	}
	for _, it := range strings.Split(allow, ",") {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if !strings.Contains(it, "/") {
			ip := net.ParseIP(it)
			if ip == nil {
				return nil, fmt.Errorf("syslog allowlist entry %q is not an IP or CIDR", it)
			}
			if ip.To4() != nil {
				it += "/32"
			} else {
				it += "/128"
			}
		}
		_, n, err := net.ParseCIDR(it)
		if err != nil {
			return nil, fmt.Errorf("syslog allowlist entry %q: %v", it, err)
		}
		c.Allow = append(c.Allow, n)
		c.AllowText = append(c.AllowText, n.String())
	}
	if len(c.Allow) == 0 {
		return nil, errors.New("syslog: refusing to start with an empty source allowlist (set KAVACH_SYSLOG_ALLOW)")
	}
	return c, nil
}

func (c *SyslogConfig) allowed(ip net.IP) bool {
	for _, n := range c.Allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type syslogBucket struct {
	tokens float64
	last   time.Time
}

type syslogItem struct {
	sender string
	line   string
	recv   time.Time
}

// SyslogSink receives normalised events (in production: the shared telemetry/network ingest path).
type SyslogSink func(ev SyslogEvent)

// SyslogListener owns sockets, counters and the bounded queue.
type SyslogListener struct {
	cfg   *SyslogConfig
	sink  SyslogSink
	now   func() time.Time
	queue chan syslogItem

	mu       sync.Mutex
	received int64
	parsed   map[string]int64
	noEvent  int64
	unparsed int64
	events   map[string]int64
	dropped  map[string]int64
	rateLim  int64
	lastSeen map[string]time.Time
	buckets  map[string]*syslogBucket
	samples  []string
	conns    int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	lns    []io.Closer
	addrs  []string
	connMu sync.Mutex
	open   map[net.Conn]struct{}
	closed bool
}

// NewSyslogListener builds (but does not start) a listener.
func NewSyslogListener(cfg *SyslogConfig, sink SyslogSink) *SyslogListener {
	ctx, cancel := context.WithCancel(context.Background())
	if cfg.Burst == 0 {
		cfg.Burst = cfg.Rate * 2
	}
	return &SyslogListener{cfg: cfg, sink: sink, now: time.Now, queue: make(chan syslogItem, syslogQueueCap),
		parsed: map[string]int64{}, events: map[string]int64{}, dropped: map[string]int64{}, lastSeen: map[string]time.Time{},
		buckets: map[string]*syslogBucket{}, ctx: ctx, cancel: cancel, open: map[net.Conn]struct{}{}}
}

// Start binds all listeners; on any error nothing stays bound.
func (l *SyslogListener) Start() error {
	var tlsCfg *tls.Config
	for _, a := range l.cfg.Listens {
		if a.Proto == "tls" {
			if l.cfg.TLSCert == "" || l.cfg.TLSKey == "" {
				return errors.New("syslog: tls listener needs KAVACH_SYSLOG_TLS_CERT and KAVACH_SYSLOG_TLS_KEY")
			}
			cert, err := tls.LoadX509KeyPair(l.cfg.TLSCert, l.cfg.TLSKey)
			if err != nil {
				return fmt.Errorf("syslog tls: %w", err)
			}
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		}
	}
	for _, a := range l.cfg.Listens {
		switch a.Proto {
		case "udp":
			pc, err := net.ListenPacket("udp", a.Addr)
			if err != nil {
				l.Close()
				return err
			}
			l.lns = append(l.lns, pc)
			l.addrs = append(l.addrs, "udp:"+pc.LocalAddr().String())
			l.wg.Add(1)
			go l.serveUDP(pc)
		default:
			ln, err := net.Listen("tcp", a.Addr)
			if err != nil {
				l.Close()
				return err
			}
			if a.Proto == "tls" {
				ln = tls.NewListener(ln, tlsCfg)
			}
			l.lns = append(l.lns, ln)
			l.addrs = append(l.addrs, a.Proto+":"+ln.Addr().String())
			l.wg.Add(1)
			go l.serveTCP(ln, a.Proto == "tls")
		}
	}
	if len(l.cfg.Listens) > 0 && !hasProto(l.cfg.Listens, "tls") {
		log.Printf("syslog: %s", syslogPlainWarning)
	}
	l.wg.Add(1)
	go l.consume()
	return nil
}

func hasProto(ls []SyslogListen, p string) bool {
	for _, l := range ls {
		if l.Proto == p {
			return true
		}
	}
	return false
}

// Addrs returns the bound addresses ("udp:127.0.0.1:5140").
func (l *SyslogListener) Addrs() []string { return append([]string(nil), l.addrs...) }

// Close stops listeners, closes connections and waits for all goroutines.
func (l *SyslogListener) Close() {
	l.connMu.Lock()
	if l.closed {
		l.connMu.Unlock()
		return
	}
	l.closed = true
	for c := range l.open {
		_ = c.Close()
	}
	l.connMu.Unlock()
	l.cancel()
	for _, c := range l.lns {
		_ = c.Close()
	}
	l.wg.Wait()
}

func (l *SyslogListener) drop(reason string) {
	l.mu.Lock()
	l.dropped[reason]++
	l.mu.Unlock()
}

// admit applies the per-source rate limit and bounded queue. Returns after enqueue or drop.
func (l *SyslogListener) admit(sender, line string) {
	now := l.now()
	l.mu.Lock()
	l.received++
	b := l.buckets[sender]
	if b == nil {
		if len(l.buckets) >= syslogMaxSources {
			l.dropped["source_table_full"]++
			l.mu.Unlock()
			return
		}
		b = &syslogBucket{tokens: l.cfg.Burst, last: now}
		l.buckets[sender] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.cfg.Rate
	if b.tokens > l.cfg.Burst {
		b.tokens = l.cfg.Burst
	}
	b.last = now
	if b.tokens < 1 {
		l.rateLim++
		l.dropped["rate_limited"]++
		l.mu.Unlock()
		return
	}
	b.tokens--
	if _, ok := l.lastSeen[sender]; ok || len(l.lastSeen) < syslogTrackedLast {
		l.lastSeen[sender] = now
	}
	l.mu.Unlock()
	select {
	case l.queue <- syslogItem{sender, line, now}:
	default:
		l.drop("queue_full")
	}
}

func (l *SyslogListener) serveUDP(pc net.PacketConn) {
	defer l.wg.Done()
	buf := make([]byte, syslogMaxMsg+1)
	for {
		n, ra, err := pc.ReadFrom(buf)
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		ip := addrIP(ra)
		if ip == nil || !l.cfg.allowed(ip) {
			l.drop("not_allowed")
			continue
		}
		if n > syslogMaxMsg {
			l.drop("oversize")
			continue
		}
		l.admit(ip.String(), strings.TrimRight(string(buf[:n]), "\r\n\x00"))
	}
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(h)
}

func (l *SyslogListener) serveTCP(ln net.Listener, isTLS bool) {
	defer l.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		ip := addrIP(c.RemoteAddr())
		if ip == nil || !l.cfg.allowed(ip) {
			l.drop("not_allowed")
			_ = c.Close()
			continue
		}
		l.mu.Lock()
		if l.conns >= l.cfg.MaxConns {
			l.dropped["max_conns"]++
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.conns++
		l.mu.Unlock()
		l.connMu.Lock()
		if l.closed {
			l.connMu.Unlock()
			_ = c.Close()
			return
		}
		l.open[c] = struct{}{}
		l.connMu.Unlock()
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() {
				_ = c.Close()
				l.connMu.Lock()
				delete(l.open, c)
				l.connMu.Unlock()
				l.mu.Lock()
				l.conns--
				l.mu.Unlock()
			}()
			l.readConn(c, ip.String())
		}()
	}
}

// readConn reads frames (RFC 6587 octet-counting or LF-terminated non-transparent framing,
// detected per frame by a leading digit). It never writes to the connection.
func (l *SyslogListener) readConn(c net.Conn, sender string) {
	br := bufio.NewReaderSize(c, 16<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(syslogIdleTimeout))
		line, ok := readSyslogFrame(br, func() { _ = c.SetReadDeadline(time.Now().Add(syslogIdleTimeout)) }, l.drop)
		if line != "" {
			l.admit(sender, line)
		}
		if !ok {
			return
		}
	}
}

// readSyslogFrame returns the next frame. ok=false means the connection should be closed.
func readSyslogFrame(br *bufio.Reader, _ func(), drop func(string)) (string, bool) {
	first, err := br.ReadByte()
	if err != nil {
		return "", false
	}
	var prefix []byte
	if first >= '0' && first <= '9' {
		digits := []byte{first}
		for len(digits) <= syslogMaxOctetLen {
			b, err := br.ReadByte()
			if err != nil {
				return "", false
			}
			if b == ' ' {
				n, _ := strconv.Atoi(string(digits))
				if n <= 0 {
					drop("bad_frame")
					return "", false
				}
				if n > syslogMaxMsg {
					drop("oversize") // cannot resync without reading n bytes; close instead
					return "", false
				}
				msg := make([]byte, n)
				if _, err := io.ReadFull(br, msg); err != nil {
					return "", false
				}
				return strings.TrimRight(string(msg), "\r\n\x00"), true
			}
			digits = append(digits, b)
			if b < '0' || b > '9' {
				break
			}
		}
		prefix = digits // not octet-counting: a plain line that happens to start with digits
	} else {
		prefix = []byte{first}
	}
	if first == '\n' {
		return "", true
	}
	// Non-transparent framing: up to LF; oversize lines are counted, discarded to LF.
	buf := append([]byte(nil), prefix...)
	over := false
	for {
		b, err := br.ReadByte()
		if err != nil {
			if len(buf) > 0 && !over && err == io.EOF {
				return strings.TrimRight(string(buf), "\r\x00"), false
			}
			return "", false
		}
		if b == '\n' {
			break
		}
		if len(buf) >= syslogMaxMsg {
			over = true
			continue
		}
		buf = append(buf, b)
	}
	if over {
		drop("oversize")
		return "", true
	}
	return strings.TrimRight(string(buf), "\r\x00"), true
}

// consume parses queued lines and hands normalised events to the sink.
func (l *SyslogListener) consume() {
	defer l.wg.Done()
	for {
		select {
		case <-l.ctx.Done():
			return
		case it := <-l.queue:
			l.process(it)
		}
	}
}

func (l *SyslogListener) process(it syslogItem) {
	m, ok := ParseSyslog(it.line, it.recv)
	if !ok {
		l.mu.Lock()
		l.unparsed++
		if len(l.samples) >= syslogSampleCap {
			l.samples = l.samples[1:]
		}
		l.samples = append(l.samples, RedactSyslog(it.line))
		l.mu.Unlock()
		return
	}
	evs := NormaliseSyslog(m, it.sender, it.recv)
	l.mu.Lock()
	l.parsed[m.Format]++
	if len(evs) == 0 {
		l.noEvent++
	}
	for _, e := range evs {
		l.events[e.Type]++
	}
	l.mu.Unlock()
	if l.sink != nil {
		for _, e := range evs {
			l.sink(e)
		}
	}
}

// SyslogStatus is the /v1/syslog/status payload.
type SyslogStatus struct {
	Enabled      bool                 `json:"enabled"`
	Listeners    []string             `json:"listeners"`
	Allowlist    []string             `json:"allowlist"`
	Limits       map[string]any       `json:"limits"`
	Received     int64                `json:"received"`
	ParsedBy     map[string]int64     `json:"parsed_by_format"`
	ParsedNoEvt  int64                `json:"parsed_without_event"`
	Unparsed     int64                `json:"unparsed"`
	EventsBy     map[string]int64     `json:"events_by_type"`
	DroppedBy    map[string]int64     `json:"dropped_by_reason"`
	RateLimited  int64                `json:"rate_limited"`
	QueueLen     int                  `json:"queue_len"`
	LastBySource map[string]time.Time `json:"last_message_by_source"`
	Warning      string               `json:"warning,omitempty"`
	Error        string               `json:"error,omitempty"`
	Note         string               `json:"note"`
}

func cp(m map[string]int64) map[string]int64 {
	o := make(map[string]int64, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// Status snapshots counters.
func (l *SyslogListener) Status() SyslogStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	last := make(map[string]time.Time, len(l.lastSeen))
	for k, v := range l.lastSeen {
		last[k] = v.UTC()
	}
	return SyslogStatus{Enabled: true, Listeners: l.Addrs(), Allowlist: l.cfg.AllowText,
		Limits: map[string]any{"max_message_bytes": syslogMaxMsg, "max_connections": l.cfg.MaxConns, "rate_per_source_per_sec": l.cfg.Rate,
			"burst": l.cfg.Burst, "queue_capacity": syslogQueueCap, "idle_read_deadline_sec": int(syslogIdleTimeout / time.Second)},
		Received: l.received, ParsedBy: cp(l.parsed), ParsedNoEvt: l.noEvent, Unparsed: l.unparsed, EventsBy: cp(l.events),
		DroppedBy: cp(l.dropped), RateLimited: l.rateLim, QueueLen: len(l.queue), LastBySource: last,
		Warning: func() string {
			if hasProto(l.cfg.Listens, "udp") || hasProto(l.cfg.Listens, "tcp") {
				return syslogPlainWarning
			}
			return ""
		}(),
		Note: "Observation only; nothing is ever written back to senders. Events are ingested as host syslog:<name>."}
}

// Samples returns redacted recent unparsed lines (oldest first).
func (l *SyslogListener) Samples() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.samples...)
}

// ---- wiring into the shared ingest path ----

// storeSink feeds normalised events through the same code POST /v1/events/{type} uses after
// validation: TelemetryStore.Add + Store.IngestTelemetry for auth/dns, Store.IngestNetwork for flows.
func storeSink(store *Store) SyslogSink {
	return func(ev SyslogEvent) {
		switch {
		case ev.Tel != nil:
			if ev.Tel.Validate(ev.Type) != nil {
				return
			}
			defaultTelemetryMu.RLock()
			ts := DefaultTelemetry
			defaultTelemetryMu.RUnlock()
			if ts == nil {
				return
			}
			if ts.Add(ev.Type, []TelemetryEvent{*ev.Tel}) != nil {
				return
			}
			if _, _, err := store.IngestTelemetry(ev.Type, []TelemetryEvent{*ev.Tel}, contentTelemetryBudget); err != nil {
				log.Printf("syslog: findings persist: %v", err)
			}
		case ev.Net != nil:
			if _, err := store.IngestNetwork(*ev.Net); err != nil {
				log.Printf("syslog: network ingest: %v", err)
			}
		}
	}
}

var (
	syslogMu       sync.Mutex
	syslogActive   *SyslogListener
	syslogStartErr string
)

// StopSyslog closes the running listener (if any). Called from RegisterSyslog's shutdown helper
// and tests; the server binary has no graceful-shutdown hook, so process exit also releases it.
func StopSyslog() {
	syslogMu.Lock()
	l := syslogActive
	syslogActive = nil
	syslogMu.Unlock()
	if l != nil {
		l.Close()
	}
}

// RegisterSyslog mounts the endpoints and, when KAVACH_SYSLOG is set, starts the listener.
func RegisterSyslog(mux *http.ServeMux, token string, store *Store) {
	if spec := strings.TrimSpace(os.Getenv(syslogEnvListen)); spec != "" {
		cfg, err := ParseSyslogConfig(spec, os.Getenv(syslogEnvAllow))
		if err == nil {
			cfg.TLSCert, cfg.TLSKey = os.Getenv("KAVACH_SYSLOG_TLS_CERT"), os.Getenv("KAVACH_SYSLOG_TLS_KEY")
			if v, e := strconv.Atoi(os.Getenv("KAVACH_SYSLOG_MAX_CONNS")); e == nil && v > 0 && v <= 4096 {
				cfg.MaxConns = v
			}
			if v, e := strconv.ParseFloat(os.Getenv("KAVACH_SYSLOG_RATE"), 64); e == nil && v > 0 && v <= 100000 {
				cfg.Rate = v
			}
			l := NewSyslogListener(cfg, storeSink(store))
			if err = l.Start(); err == nil {
				syslogMu.Lock()
				syslogActive = l
				syslogMu.Unlock()
				RegisterStopper("syslog", func(context.Context) error { StopSyslog(); return nil })
				log.Printf("syslog: listening on %v, allowlist %v", l.Addrs(), cfg.AllowText)
			}
		}
		if err != nil {
			syslogStartErr = err.Error()
			log.Printf("syslog: NOT started: %v", err)
		}
	}
	registerSyslogRoutes(mux, token)
}

func registerSyslogRoutes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/syslog/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		syslogMu.Lock()
		l := syslogActive
		errText := syslogStartErr
		syslogMu.Unlock()
		if l == nil {
			writeJSON(w, SyslogStatus{Enabled: false, Listeners: []string{}, Allowlist: []string{}, Error: errText,
				Note: "Disabled by default. Set KAVACH_SYSLOG (explicit proto:host:port list) and KAVACH_SYSLOG_ALLOW (source CIDRs)."})
			return
		}
		writeJSON(w, l.Status())
	})
	mux.HandleFunc("GET /v1/syslog/samples", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		syslogMu.Lock()
		l := syslogActive
		syslogMu.Unlock()
		s := []string{}
		if l != nil {
			s = l.Samples()
		}
		writeJSON(w, map[string]any{"count": len(s), "samples": s, "note": "Unparsed lines only, redacted of obvious secrets, truncated to 512 chars, newest last."})
	})
	mux.HandleFunc("POST /v1/syslog/parse", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, syslogMaxMsg+1024)
		var in struct {
			Line   string `json:"line"`
			Sender string `json:"sender"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Line == "" || len(in.Line) > syslogMaxMsg {
			http.Error(w, `{"error":"body must be {\"line\": \"<=8KiB syslog line\"}"}`, http.StatusBadRequest)
			return
		}
		sender := in.Sender
		if net.ParseIP(sender) == nil {
			sender = "pasted"
		}
		now := time.Now()
		m, ok := ParseSyslog(in.Line, now)
		evs := []SyslogEvent{}
		if ok {
			evs = NormaliseSyslog(m, sender, now)
		}
		writeJSON(w, map[string]any{"parsed": ok, "message": m, "events": evs, "ingested": false,
			"note": "Dry run: nothing was ingested."})
	})
}

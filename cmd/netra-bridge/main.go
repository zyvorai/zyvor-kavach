// netra-bridge is an opt-in, normalized-JSONL bridge. It does not read Netra internal state.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/zyvor-kavach/internal/edr"
)

func run(ctx context.Context, reader io.Reader, endpoint, token string, client *http.Client) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	line := 0
	for scanner.Scan() {
		line++
		b := bytes.TrimSpace(scanner.Bytes())
		if len(b) == 0 {
			continue
		}
		var n edr.NetworkEvent
		if err := json.Unmarshal(b, &n); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if n.Host == "" || n.PID <= 0 || n.Time.IsZero() || n.Destination == "" {
			return fmt.Errorf("line %d: host, pid, time, destination required", line)
		}
		if n.Source == "" {
			n.Source = "netra-bridge"
		}
		payload, _ := json.Marshal(n)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/network-events", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("line %d: API HTTP %d; input may need replay", line, resp.StatusCode)
		}
	}
	return scanner.Err()
}
func main() {
	endpoint := flag.String("url", "http://127.0.0.1:8099", "EDR API address")
	flag.Parse()
	token := os.Getenv("KAVACH_TOKEN")
	if len(token) < 8 {
		log.Fatal("KAVACH_TOKEN must be at least 8 characters")
	}
	parsed, err := url.Parse(*endpoint)
	if err != nil || parsed.Host == "" || !(parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
		log.Fatal("HTTPS required except loopback")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if err := run(context.Background(), os.Stdin, strings.TrimRight(*endpoint, "/"), token, client); err != nil {
		log.Fatal(err)
	}
}

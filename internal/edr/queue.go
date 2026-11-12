package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Queue is an on-disk, bounded, at-least-once outbox. Files are removed only on server ACK.
type Queue struct {
	Dir   string
	Limit int
}

func (q Queue) Enqueue(e Event) error {
	if q.Limit < 1 {
		return errors.New("queue limit must be positive")
	}
	if err := os.MkdirAll(q.Dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		return err
	}
	count := 0
	for _, v := range entries {
		if strings.HasSuffix(v.Name(), ".json") {
			count++
		}
	}
	if count >= q.Limit {
		return errors.New("event queue full; refuse to drop events silently")
	}
	if e.ID == "" {
		e.ID = eventID(e)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), e.ID[:min(16, len(e.ID))])
	temp, err := os.CreateTemp(q.Dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err = temp.Write(b); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), filepath.Join(q.Dir, name))
}
func (q Queue) Flush(ctx context.Context, endpoint, token string, client *http.Client) (int, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	entries, err := os.ReadDir(q.Dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	names := []string{}
	for _, v := range entries {
		if strings.HasSuffix(v.Name(), ".json") {
			names = append(names, v.Name())
		}
	}
	sort.Strings(names)
	sent := 0
	for _, name := range names {
		path := filepath.Join(q.Dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			return sent, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/events", strings.NewReader(string(b)))
		if err != nil {
			return sent, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return sent, err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return sent, fmt.Errorf("ingest returned %d", resp.StatusCode)
		}
		if err := os.Remove(path); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (q Queue) Pending() (int, error) {
	entries, err := os.ReadDir(q.Dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n, nil
}
func SendHeartbeat(ctx context.Context, endpoint, token, host, sensor string, queued int, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	body, err := json.Marshal(map[string]any{"host": host, "sensor": sensor, "queued": queued})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/agents/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 204 {
		return fmt.Errorf("heartbeat returned %d", resp.StatusCode)
	}
	return nil
}

func RunAgent(ctx context.Context, scanner *Scanner, endpoint, token string, interval time.Duration, q Queue) error {
	return RunAgentWithOptions(ctx, scanner, endpoint, token, interval, q, nil, "")
}

func RunAgentWithOptions(ctx context.Context, scanner *Scanner, endpoint, token string, interval time.Duration, q Queue, client *http.Client, fileRoot string) error {
	if interval < time.Second {
		return errors.New("interval must be >=1s")
	}
	kernel, err := WatchExec(ctx)
	if err != nil {
		kernel = nil
	} // kernel connector is optional; polling remains active
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	retry := time.NewTicker(2 * time.Second)
	var files *FileScanner
	if fileRoot != "" {
		files = NewFileScanner(fileRoot, scanner.Host)
		_, err := files.Scan(time.Now())
		if err != nil {
			return err
		}
	}
	fileTicker := time.NewTicker(3 * time.Second)
	defer fileTicker.Stop()
	defer retry.Stop()
	collect := func() error {
		for _, e := range scanner.Scan(time.Now()) {
			if err := q.Enqueue(e); err != nil {
				return err
			}
		}
		return nil
	}
	if err := collect(); err != nil {
		return err
	}
	_, _ = q.Flush(ctx, endpoint, token, client)
	if count, err := q.Pending(); err == nil {
		_ = SendHeartbeat(ctx, endpoint, token, scanner.Host, string(ProbeSensor()), count, client)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			count, err := q.Pending()
			if err == nil {
				_ = SendHeartbeat(ctx, endpoint, token, scanner.Host, string(ProbeSensor()), count, client)
			}
		case pid, ok := <-kernel:
			if !ok {
				kernel = nil
				continue
			}
			if e, found := scanner.ScanPID(pid, time.Now()); found {
				if err := q.Enqueue(e); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := collect(); err != nil {
				return err
			}
		case <-fileTicker.C:
			if files != nil {
				if events, err := files.Scan(time.Now()); err == nil {
					for _, e := range events {
						if err := SendFileEvent(ctx, endpoint, token, e, client); err != nil { // file events need durable delivery; never drop silently
							_ = SpoolFileEvent(q.Dir+"-files", e)
						}
					}
				}
			}
		case <-retry.C:
			if files != nil {
				_ = FlushFileEvents(ctx, q.Dir+"-files", endpoint, token, client)
			}
			_, _ = q.Flush(ctx, endpoint, token, client)
		}
	}
}

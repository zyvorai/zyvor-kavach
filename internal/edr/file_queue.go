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

func SendFileEvent(ctx context.Context, endpoint, token string, e FileEvent, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/file-events", bytes.NewReader(payload))
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 {
		return fmt.Errorf("file ingestion status %d", resp.StatusCode)
	}
	return nil
}
func SpoolFileEvent(dir string, e FileEvent) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) >= 10000 {
		return errors.New("file event spool full")
	}
	if e.ID == "" {
		e.ID = fileID(e)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), e.ID[:min(16, len(e.ID))])))
}
func FlushFileEvents(ctx context.Context, dir, endpoint, token string, client *http.Client) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	names := []string{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var e FileEvent
		if json.Unmarshal(b, &e) != nil {
			return errors.New("corrupt spool")
		}
		if err = SendFileEvent(ctx, endpoint, token, e, client); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

package edr

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Synthetic traces. They encode OUR reading of how families and benign tools
// behave at the file-metadata level; they overstate real accuracy.

type rdGen struct {
	r    *rand.Rand
	host string
	t0   time.Time
	ev   []FileEvent
}

func newGen(seed int64, host string) *rdGen {
	return &rdGen{r: rand.New(rand.NewSource(seed)), host: host, t0: time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)}
}

func (g *rdGen) add(at time.Time, op, p string, size int64) {
	g.ev = append(g.ev, FileEvent{Time: at, Host: g.host, Path: p, Operation: op, Size: size})
}

var rdUserExt = []string{".docx", ".xlsx", ".pdf", ".jpg", ".png", ".txt", ".pptx", ".sql", ".mp4", ".csv"}

type rdFile struct {
	p    string
	size int64
}

// victimFiles seeds a history (baseline create events 2h before the attack).
func (g *rdGen) victimFiles(n, dirs int) []rdFile {
	var out []rdFile
	for i := 0; i < n; i++ {
		f := rdFile{fmt.Sprintf("/home/u/Documents/d%02d/file%04d%s", i%dirs, i, rdUserExt[g.r.Intn(len(rdUserExt))]), int64(2000 + g.r.Intn(2_000_000))}
		out = append(out, f)
		g.add(g.t0.Add(-2*time.Hour+time.Duration(i)*time.Millisecond), "create", f.p, f.size)
	}
	return out
}

func (g *rdGen) step(rate float64) time.Duration {
	return time.Duration(float64(time.Second) / rate * (0.7 + 0.6*g.r.Float64()))
}

type rdScenario struct {
	name string
	gen  func(g *rdGen)
}

func rdRansomScenarios() []rdScenario {
	notes := func(g *rdGen, at time.Time, dirs int) {
		for d := 0; d < dirs; d++ {
			g.add(at.Add(time.Duration(d)*time.Second), "create", fmt.Sprintf("/home/u/Documents/d%02d/HOW_TO_DECRYPT.txt", d), 1500)
		}
	}
	return []rdScenario{
		{"rename_with_extension", func(g *rdGen) {
			files := g.victimFiles(300+g.r.Intn(500), 12+g.r.Intn(20))
			ext := []string{".locked", ".lockbit", ".xk39a", ".enc"}[g.r.Intn(4)]
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(6 + 20*g.r.Float64()))
				g.add(at, "rename", f.p+ext, f.size+16)
			}
			notes(g, at, 12)
		}},
		{"inplace_overwrite_no_note", func(g *rdGen) {
			files := g.victimFiles(300+g.r.Intn(500), 12+g.r.Intn(20))
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(6 + 20*g.r.Float64()))
				g.add(at, "modify", f.p, f.size+int64(g.r.Intn(64)))
			}
		}},
		{"note_dropping_with_inplace", func(g *rdGen) {
			files := g.victimFiles(250+g.r.Intn(300), 10+g.r.Intn(20))
			at := g.t0
			for i, f := range files {
				at = at.Add(g.step(5 + 15*g.r.Float64()))
				g.add(at, "modify", f.p, f.size+16)
				if i%25 == 0 {
					g.add(at, "create", fmt.Sprintf("/home/u/Documents/d%02d/README_TO_DECRYPT_files.txt", i%10), 900)
					g.add(at, "create", fmt.Sprintf("/home/u/Documents/d%02d/HOW_TO_RECOVER_FILES.txt", (i+1)%10), 900)
				}
			}
		}},
		{"delete_original_after_encrypted_copy", func(g *rdGen) {
			files := g.victimFiles(200+g.r.Intn(400), 10+g.r.Intn(20))
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(5 + 15*g.r.Float64()))
				g.add(at, "create", f.p+".encrypted", f.size+32)
				g.add(at.Add(time.Millisecond), "delete", f.p, 0)
			}
			notes(g, at, 8)
		}},
		{"shadow_copy_wipe_then_encrypt", func(g *rdGen) {
			files := g.victimFiles(250+g.r.Intn(300), 10+g.r.Intn(15))
			at := g.t0
			for i := 0; i < 6; i++ {
				at = at.Add(2 * time.Second)
				g.add(at, "delete", fmt.Sprintf("/System Volume Information/{%d}/Volume Shadow Copy%d", i, i), 0)
			}
			for _, f := range files {
				at = at.Add(g.step(5 + 10*g.r.Float64()))
				g.add(at, "rename", f.p+".conti", f.size+16)
			}
		}},
		{"nas_share_fast_ext_only", func(g *rdGen) {
			files := g.victimFiles(500, 40)
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(40))
				g.add(at, "rename", f.p+".akira", f.size)
			}
		}},
	}
}

// Documented evasions: expected NOT to alert. Reported, not asserted as detection.
func rdEvasionScenarios() []rdScenario {
	return []rdScenario{
		{"slow_and_low", func(g *rdGen) {
			files := g.victimFiles(300, 20)
			at := g.t0
			for _, f := range files {
				at = at.Add(time.Duration(40+g.r.Intn(60)) * time.Second) // ~1 file / 80 s over ~7h
				g.add(at, "rename", f.p+".locked", f.size+16)
			}
		}},
		{"random_names_common_ext", func(g *rdGen) {
			files := g.victimFiles(400, 20)
			at := g.t0
			for i, f := range files {
				at = at.Add(g.step(10))
				g.add(at, "create", fmt.Sprintf("%s/%08x.qzv", f.p[:strings.LastIndex(f.p, "/")], g.r.Uint32()+uint32(i)), f.size)
				g.add(at.Add(time.Millisecond), "delete", f.p, 0)
			}
		}},
	}
}

func rdBenignScenarios() []rdScenario {
	return []rdScenario{
		{"backup_tool_copy", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 2500; i++ {
				at = at.Add(g.step(35))
				g.add(at, "create", fmt.Sprintf("/mnt/backup/2026-01-05/home/u/d%02d/f%d%s", i%30, i, rdUserExt[i%len(rdUserExt)]), int64(1000+g.r.Intn(500000)))
			}
			g.add(at, "create", "/mnt/backup/2026-01-05/backup.tar.gz", 90_000_000)
		}},
		{"compiler_build", func(g *rdGen) {
			g.victimFiles(0, 1)
			at := g.t0
			for i := 0; i < 900; i++ {
				at = at.Add(g.step(25))
				d := i % 6
				g.add(at, "create", fmt.Sprintf("/src/proj/build/d%d/m%d.o", d, i), int64(3000+g.r.Intn(80000)))
				if i%10 == 0 {
					g.add(at, "modify", fmt.Sprintf("/src/proj/build/d%d/.deps/m%d.d", d, i), int64(400+g.r.Intn(300)))
				}
			}
		}},
		{"package_install", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 3000; i++ {
				at = at.Add(g.step(50))
				d := fmt.Sprintf("/usr/lib/pkg%02d/sub%02d", i%40, i%7)
				g.add(at, "create", fmt.Sprintf("%s/f%d.so.1", d, i), int64(5000+g.r.Intn(400000)))
				if i%3 == 0 {
					g.add(at, "create", fmt.Sprintf("%s/g%d.dpkg-new", d, i), 300)
					g.add(at.Add(time.Millisecond), "rename", fmt.Sprintf("%s/g%d", d, i), 300)
				}
			}
		}},
		{"git_checkout", func(g *rdGen) {
			var files []rdFile
			for i := 0; i < 800; i++ {
				f := rdFile{fmt.Sprintf("/src/repo/pkg%02d/file%d.go", i%25, i), int64(1000 + g.r.Intn(30000))}
				files = append(files, f)
				g.add(g.t0.Add(-time.Hour+time.Duration(i)*time.Millisecond), "create", f.p, f.size)
			}
			at := g.t0
			for i, f := range files {
				if i%3 == 0 {
					continue
				}
				at = at.Add(g.step(30))
				if i%11 == 0 {
					g.add(at, "delete", f.p, 0)
				} else {
					g.add(at, "modify", f.p, f.size+int64(g.r.Intn(8000))-2000)
				}
			}
		}},
		{"log_rotation", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 60; i++ {
				at = at.Add(g.step(8))
				g.add(g.t0.Add(-time.Hour), "create", fmt.Sprintf("/var/log/app%02d.log", i), 1_000_000)
				g.add(at, "rename", fmt.Sprintf("/var/log/app%02d.log.1", i), 1_000_000)
				g.add(at.Add(time.Millisecond), "create", fmt.Sprintf("/var/log/app%02d.log.2.gz", i), 120_000)
				g.add(at.Add(2*time.Millisecond), "create", fmt.Sprintf("/var/log/app%02d.log", i), 0)
			}
		}},
		{"photo_import", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 600; i++ {
				at = at.Add(g.step(15))
				g.add(at, "create", fmt.Sprintf("/home/u/Pictures/2026/01/IMG_%04d.jpg", i), int64(3_000_000+g.r.Intn(4_000_000)))
			}
		}},
		{"archive_extraction", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 3500; i++ {
				at = at.Add(g.step(120))
				g.add(at, "create", fmt.Sprintf("/home/u/Downloads/proj/d%03d/f%d%s", i%200, i, rdUserExt[i%len(rdUserExt)]), int64(100+g.r.Intn(90000)))
			}
		}},
		{"ide_indexing", func(g *rdGen) {
			var files []rdFile
			for i := 0; i < 400; i++ {
				f := rdFile{fmt.Sprintf("/home/u/proj/.idea/index/d%02d/idx%d.dat", i%30, i), int64(4000 + g.r.Intn(9000))}
				files = append(files, f)
				g.add(g.t0.Add(-time.Hour+time.Duration(i)*time.Millisecond), "create", f.p, f.size)
			}
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(12))
				g.add(at, "modify", f.p, f.size+int64(g.r.Intn(6000)))
			}
		}},
		{"backup_prune_old_snapshots", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 8; i++ {
				at = at.Add(3 * time.Second)
				g.add(at, "delete", fmt.Sprintf("/data/.snapshots/daily.%d/index", i), 0)
			}
		}},
		{"photo_rename_batch", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 300; i++ {
				g.add(g.t0.Add(-time.Hour), "create", fmt.Sprintf("/home/u/Pictures/IMG_%04d.jpg", i), 3_000_000)
				at = at.Add(g.step(20))
				g.add(at, "rename", fmt.Sprintf("/home/u/Pictures/2026-01-05_%04d.jpg", i), 3_000_000)
			}
		}},
	}
}

func rdAlerts(ev []FileEvent) (alert bool, peak int) {
	for _, w := range ComputeRansomWindows(ev, DefaultRansomDetectConfig()) {
		if w.Level == "alert" {
			alert = true
		}
		if w.Score > peak {
			peak = w.Score
		}
	}
	return
}

const rdSeeds = 40

func rdRate(t *testing.T, sc []rdScenario) (map[string]int, int, int) {
	per := map[string]int{}
	hit, tot := 0, 0
	for _, s := range sc {
		for seed := int64(1); seed <= rdSeeds; seed++ {
			g := newGen(seed*7919, "h-"+s.name)
			s.gen(g)
			a, _ := rdAlerts(g.ev)
			tot++
			if a {
				hit++
				per[s.name]++
			}
		}
	}
	return per, hit, tot
}

func TestRansomDetectionRate(t *testing.T) {
	per, hit, tot := rdRate(t, rdRansomScenarios())
	for k, v := range per {
		t.Logf("detected %-40s %d/%d", k, v, rdSeeds)
	}
	rate := float64(hit) / float64(tot)
	t.Logf("overall synthetic detection rate %.3f (%d/%d)", rate, hit, tot)
	if rate < 0.95 {
		t.Fatalf("detection rate %.3f below 0.95", rate)
	}
	for _, s := range rdRansomScenarios() {
		if per[s.name] < rdSeeds*9/10 {
			t.Errorf("scenario %s detected only %d/%d", s.name, per[s.name], rdSeeds)
		}
	}
}

func TestRansomFalsePositiveRate(t *testing.T) {
	per, fp, tot := rdRate(t, rdBenignScenarios())
	for k, v := range per {
		t.Logf("false alert %-32s %d/%d", k, v, rdSeeds)
	}
	rate := float64(fp) / float64(tot)
	t.Logf("overall synthetic false-positive rate %.3f (%d/%d)", rate, fp, tot)
	if rate > 0.02 {
		t.Fatalf("false-positive rate %.3f above 0.02", rate)
	}
}

func TestRansomKnownEvasions(t *testing.T) {
	per, hit, tot := rdRate(t, rdEvasionScenarios())
	t.Logf("documented-evasion alerts %d/%d per=%v", hit, tot, per)
	if per["slow_and_low"] != 0 {
		t.Errorf("slow_and_low unexpectedly alerts; update docs/research-ransomware.md")
	}
}

func TestRansomHTTP(t *testing.T) {
	store, err := NewStore("", 100)
	if err != nil {
		t.Fatal(err)
	}
	g := newGen(1, "victim")
	rdRansomScenarios()[0].gen(g)
	store.mu.Lock()
	store.fileEvents = append(store.fileEvents, g.ev...)
	store.mu.Unlock()
	mux := http.NewServeMux()
	RegisterRansomDetect(mux, "tok", store)
	get := func(u string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", u, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if get("/v1/ransom/status", false).Code == 200 {
		t.Fatal("unauthenticated status allowed")
	}
	if rr := get("/v1/ransom/status", true); rr.Code != 200 || !strings.Contains(rr.Body.String(), "cannot_see") {
		t.Fatalf("status %d", rr.Code)
	}
	rr := get("/v1/ransom/hosts", true)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"level":"alert"`) || !strings.Contains(rr.Body.String(), "extension_churn") {
		t.Fatalf("hosts: %d %.300s", rr.Code, rr.Body.String())
	}
	if rr := get("/v1/ransom/host", true); rr.Code != 400 {
		t.Fatalf("missing host: %d", rr.Code)
	}
	if rr := get("/v1/ransom/host?host=victim", true); rr.Code != 200 || !strings.Contains(rr.Body.String(), "windows") {
		t.Fatalf("host: %d", rr.Code)
	}
	if rr := get("/v1/ransom/host?host=nope", true); rr.Code != 404 {
		t.Fatalf("unknown host: %d", rr.Code)
	}
}

package edr

// Ransomware behaviour detector (metadata only).
//
// Method: per-host sliding windows over FileEvent metadata (path, operation,
// size, time). Indicators are grouped CryptoDrop-style into PRIMARY and
// SECONDARY, each contributes points, and an alert needs a score threshold AND
// the primary/secondary rule (see rdScoreWindow). Every response carries the
// full factor list. This is report-only: it blocks nothing.
//
// It CANNOT see file contents, entropy, file-type similarity, or the writing
// process, so it cannot reproduce CryptoDrop's content indicators. See
// docs/research-ransomware.md.

import (
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RansomDetectConfig holds every threshold; GET /v1/ransom/status echoes it.
type RansomDetectConfig struct {
	Window time.Duration `json:"window_ns"`
	Stride time.Duration `json:"stride_ns"`

	// Primary indicator triggers.
	ExtChurnFiles  int     `json:"ext_churn_files"`          // files acquiring one suffix
	NoteDirs       int     `json:"note_dirs"`                // dirs with a ransom-note-named file
	BackupTouches  int     `json:"backup_touches"`           // delete/rename in shadow/backup paths
	RewriteFiles   int     `json:"rewrite_files"`            // distinct files modified in place
	RewriteDirs    int     `json:"rewrite_dirs"`             // ... across this many dirs
	RewriteUniform float64 `json:"rewrite_uniform_fraction"` // share with near-constant size
	// Secondary triggers.
	FunnelExts   int     `json:"funnel_source_exts"`
	DeleteShare  float64 `json:"delete_share"`
	DeleteMin    int     `json:"delete_min"`
	RatePerSec   float64 `json:"rate_per_sec"`
	DirsTouched  int     `json:"dirs_touched"`
	PacingMaxB   float64 `json:"pacing_max_burstiness"`
	PacingMinOps int     `json:"pacing_min_ops"`

	AlertScore int `json:"alert_score"`
	WatchScore int `json:"watch_score"`
}

// DefaultRansomDetectConfig values were chosen from the literature's qualitative
// indicators, then adjusted against the synthetic corpus; they are NOT fitted
// to real fleets.
func DefaultRansomDetectConfig() RansomDetectConfig {
	return RansomDetectConfig{
		Window: 60 * time.Second, Stride: 30 * time.Second,
		ExtChurnFiles: 20, NoteDirs: 3, BackupTouches: 3,
		RewriteFiles: 100, RewriteDirs: 5, RewriteUniform: 0.6,
		FunnelExts: 4, DeleteShare: 0.4, DeleteMin: 30, RatePerSec: 5,
		DirsTouched: 15, PacingMaxB: 0.0, PacingMinOps: 100,
		AlertScore: 50, WatchScore: 30,
	}
}

// RansomFactor is one scored indicator.
type RansomFactor struct {
	Name      string  `json:"name"`
	Kind      string  `json:"kind"` // primary | secondary
	Value     float64 `json:"value"`
	Trigger   float64 `json:"trigger"`
	Triggered bool    `json:"triggered"`
	Points    int     `json:"points"`
	Detail    string  `json:"detail,omitempty"`
}

// RansomWindow is the scored result for one window.
type RansomWindow struct {
	Start     time.Time      `json:"start"`
	End       time.Time      `json:"end"`
	Events    int            `json:"events"`
	Score     int            `json:"score"`
	Level     string         `json:"level"` // none | watch | alert
	Primaries int            `json:"primary_triggered"`
	Secondary int            `json:"secondary_triggered"`
	Factors   []RansomFactor `json:"factors"`
}

// RansomHost is the ranked per-host summary (its peak window).
type RansomHost struct {
	Host    string       `json:"host"`
	Peak    RansomWindow `json:"peak"`
	Windows int          `json:"windows"`
	Alerts  int          `json:"alert_windows"`
}

var rdAllowSuffix = map[string]bool{
	".gz": true, ".bz2": true, ".xz": true, ".zst": true, ".zip": true, ".bak": true, ".tmp": true,
	".swp": true, ".swx": true, ".orig": true, ".old": true, ".log": true, ".part": true, ".crdownload": true,
	".sav": true, ".save": true, ".new": true, ".rej": true, ".dpkg-new": true, ".dpkg-old": true,
	".pyc": true, ".bkp": true, ".backup": true, ".md5": true, ".sha256": true, ".sig": true, ".asc": true,
}

var rdDocExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields("doc docx xls xlsx ppt pptx pdf txt jpg jpeg png gif bmp tif tiff mp3 mp4 avi mov mkv rar 7z sql db mdb csv odt ods rtf psd dwg vmdk vhd vhdx pst ost html xml json") {
		rdDocExt[e] = true
	}
}

// Extensions widely reported on ransomware output. Short, illustrative list.
var rdRansomExt = map[string]bool{
	".locked": true, ".encrypted": true, ".crypt": true, ".crypted": true, ".enc": true, ".lockbit": true,
	".wncry": true, ".wnry": true, ".ryk": true, ".conti": true, ".blackcat": true, ".akira": true,
	".royal": true, ".cerber": true, ".locky": true, ".zepto": true, ".crypz": true, ".ctbl": true,
	".ecc": true, ".ezz": true, ".exx": true, ".vvv": true, ".micro": true, ".kraken": true,
	".hive": true, ".babyk": true, ".djvu": true, ".stop": true, ".petya": true,
}

var rdNoteSubstr = []string{
	"how_to_decrypt", "how-to-decrypt", "how to decrypt", "how_to_recover", "how to recover", "how_to_restore",
	"decrypt_instruction", "decrypt-instruction", "decryption_instruction", "readme_for_decrypt", "restore_my_files",
	"restore-my-files", "restore_files", "recover_files", "recover-files", "your_files_are_encrypted",
	"files_encrypted", "_readme.txt", "!readme", "!!!readme", "@please_read_me@", "help_decrypt", "ransom",
	"decrypt_your_files", "read_to_decrypt", "readme_to_decrypt", "wannadecryptor",
}

var rdBackupMarkers = []string{
	"volume shadow copy", "system volume information", "/.snapshots/", "backups.backupdb", "windowsimagebackup",
	".vbk", ".vib", "/veeam/", "/.zfs/snapshot/", "shadowcopy", "/vss/",
}

type rdEnriched struct {
	t         time.Time
	dir, base string
	op        string // create|modify|rename|delete|other
	suffix    string // acquired suffix, "" if none
	srcExt    string // original extension (for funnelling)
	note      bool
	backup    bool
	rewrite   bool // modify of a previously seen path
	uniform   bool // rewrite with near-constant size
}

func rdOp(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "renam") || strings.Contains(s, "move"):
		return "rename"
	case strings.Contains(s, "delet") || strings.Contains(s, "remov") || strings.Contains(s, "unlink"):
		return "delete"
	case strings.Contains(s, "creat") || strings.Contains(s, "new"):
		return "create"
	case strings.Contains(s, "modif") || strings.Contains(s, "write") || strings.Contains(s, "change"):
		return "modify"
	}
	return "other"
}

const rdSeenCap = 300000

// rdEnrich walks a host's time-ordered events once, deriving per-event flags
// using a seen-path map (lowercased path -> last size). Rename paths are
// assumed to be the NEW name (the only path a FileEvent carries).
func rdEnrich(fl []FileEvent) []rdEnriched {
	seen := map[string]int64{}
	out := make([]rdEnriched, 0, len(fl))
	for _, f := range fl {
		lp := strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
		e := rdEnriched{t: f.Time, dir: path.Dir(lp), base: path.Base(lp), op: rdOp(f.Operation)}
		for _, n := range rdNoteSubstr {
			if strings.Contains(e.base, n) {
				e.note = true
				break
			}
		}
		for _, m := range rdBackupMarkers {
			if strings.Contains(lp, m) {
				e.backup = true
				break
			}
		}
		ext := path.Ext(e.base)
		if (e.op == "create" || e.op == "rename") && ext != "" {
			stem := strings.TrimSuffix(lp, ext)
			inner := path.Ext(path.Base(stem))
			_, stemSeen := seen[stem]
			switch {
			case rdRansomExt[ext]:
				e.suffix, e.srcExt = ext, inner
			case rdAllowSuffix[ext]:
			case stemSeen && inner != "":
				e.suffix, e.srcExt = ext, inner // suffix appended to a previously seen file
			case inner != "" && rdDocExt[strings.TrimPrefix(inner, ".")]:
				e.suffix, e.srcExt = ext, inner // name.docx.<new>
			}
		}
		if e.op == "modify" {
			if old, ok := seen[lp]; ok {
				e.rewrite = true
				d := f.Size - old
				if d < 0 {
					d = -d
				}
				lim := old / 1000
				if lim < 1024 {
					lim = 1024
				}
				e.uniform = d <= lim
			}
		}
		if len(seen) > rdSeenCap {
			seen = map[string]int64{}
		}
		seen[lp] = f.Size
		out = append(out, e)
	}
	return out
}

func rdPoints(max int, v, trig float64) int {
	if v < trig || trig <= 0 {
		return 0
	}
	frac := math.Min(1, (v-trig)/(2*trig))
	return int(math.Round(float64(max) * (0.5 + 0.5*frac)))
}

// rdBurstiness is the Goh-Barabasi burstiness B=(s-m)/(s+m) of inter-event
// gaps: about -1 for metronomic, 0 for Poisson, toward +1 for bursty/idle.
func rdBurstiness(ts []time.Time) float64 {
	if len(ts) < 3 {
		return 0
	}
	gaps := make([]float64, 0, len(ts)-1)
	var m float64
	for i := 1; i < len(ts); i++ {
		g := ts[i].Sub(ts[i-1]).Seconds()
		gaps = append(gaps, g)
		m += g
	}
	m /= float64(len(gaps))
	var v float64
	for _, g := range gaps {
		v += (g - m) * (g - m)
	}
	s := math.Sqrt(v / float64(len(gaps)))
	if s+m == 0 {
		return -1
	}
	return (s - m) / (s + m)
}

func rdF(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

func rdScoreWindow(ev []rdEnriched, start time.Time, c RansomDetectConfig) RansomWindow {
	w := RansomWindow{Start: start, End: start.Add(c.Window), Events: len(ev), Level: "none"}
	dirs := map[string]bool{}
	sufFiles := map[string]map[string]bool{}
	sufSrc := map[string]map[string]bool{}
	noteDirs := map[string]bool{}
	rewriteFiles := map[string]bool{}
	rewriteDirs := map[string]bool{}
	var del, backup, uniform int
	var ts []time.Time
	for _, e := range ev {
		dirs[e.dir] = true
		ts = append(ts, e.t)
		if e.suffix != "" {
			if sufFiles[e.suffix] == nil {
				sufFiles[e.suffix], sufSrc[e.suffix] = map[string]bool{}, map[string]bool{}
			}
			sufFiles[e.suffix][e.dir+"/"+e.base] = true
			sufSrc[e.suffix][e.srcExt] = true
		}
		if e.note && e.op != "delete" {
			noteDirs[e.dir] = true
		}
		if e.backup && (e.op == "delete" || e.op == "rename") {
			backup++
		}
		if e.op == "delete" {
			del++
		}
		if e.rewrite {
			k := e.dir + "/" + e.base
			if !rewriteFiles[k] {
				rewriteFiles[k] = true
				rewriteDirs[e.dir] = true
				if e.uniform {
					uniform++
				}
			}
		}
	}
	bestSuf, bestN := "", 0
	for s, f := range sufFiles {
		if len(f) > bestN || (len(f) == bestN && s < bestSuf) {
			bestSuf, bestN = s, len(f)
		}
	}
	funnel := 0
	if bestSuf != "" {
		funnel = len(sufSrc[bestSuf])
	}
	rate := float64(len(ev)) / c.Window.Seconds()
	uf := 0.0
	if len(rewriteFiles) > 0 {
		uf = float64(uniform) / float64(len(rewriteFiles))
	}
	delShare := 0.0
	if len(ev) > 0 {
		delShare = float64(del) / float64(len(ev))
	}
	b := rdBurstiness(ts)

	add := func(f RansomFactor) {
		if f.Triggered {
			if f.Kind == "primary" {
				w.Primaries++
			} else {
				w.Secondary++
			}
		}
		w.Score += f.Points
		w.Factors = append(w.Factors, f)
	}
	extP := rdPoints(35, float64(bestN), float64(c.ExtChurnFiles))
	add(RansomFactor{"extension_churn", "primary", float64(bestN), float64(c.ExtChurnFiles), extP > 0, extP, "most common acquired suffix " + bestSuf})
	noteP := rdPoints(30, float64(len(noteDirs)), float64(c.NoteDirs))
	add(RansomFactor{"ransom_note_dirs", "primary", float64(len(noteDirs)), float64(c.NoteDirs), noteP > 0, noteP, "directories receiving a ransom-note-named file"})
	bkP := rdPoints(30, float64(backup), float64(c.BackupTouches))
	add(RansomFactor{"backup_shadow_destruction", "primary", float64(backup), float64(c.BackupTouches), bkP > 0, bkP, "delete/rename inside shadow-copy or backup locations"})
	rwOK := len(rewriteFiles) >= c.RewriteFiles && len(rewriteDirs) >= c.RewriteDirs && uf >= c.RewriteUniform
	rwP := 0
	if rwOK {
		rwP = rdPoints(40, float64(len(rewriteFiles)), float64(c.RewriteFiles))
	}
	add(RansomFactor{"mass_inplace_rewrite", "primary", float64(len(rewriteFiles)), float64(c.RewriteFiles), rwOK, rwP, "previously seen files modified across dirs with near-constant size (uniform fraction " + rdF(uf) + ")"})

	fP := 0
	if funnel >= c.FunnelExts && bestN >= c.ExtChurnFiles/2 {
		fP = 10
	}
	add(RansomFactor{"type_funnelling", "secondary", float64(funnel), float64(c.FunnelExts), fP > 0, fP, "distinct original extensions converted to one suffix"})
	dP := 0
	if del >= c.DeleteMin && delShare >= c.DeleteShare {
		dP = 10
	}
	add(RansomFactor{"delete_heavy", "secondary", delShare, c.DeleteShare, dP > 0, dP, "share of deletes in window"})
	rP := 0
	if rate >= c.RatePerSec {
		rP = 8
	}
	add(RansomFactor{"high_rate", "secondary", rate, c.RatePerSec, rP > 0, rP, "events per second"})
	dirP := 0
	if len(dirs) >= c.DirsTouched {
		dirP = 8
	}
	add(RansomFactor{"directory_breadth", "secondary", float64(len(dirs)), float64(c.DirsTouched), dirP > 0, dirP, "distinct directories touched"})
	pP := 0
	if len(ev) >= c.PacingMinOps && b <= c.PacingMaxB {
		pP = 4
	}
	add(RansomFactor{"machine_pacing", "secondary", b, c.PacingMaxB, pP > 0, pP, "burstiness B of inter-event gaps (<=0 is metronomic)"})

	if w.Score > 100 {
		w.Score = 100
	}
	// Rule: score threshold AND (two primaries, or one primary plus two secondaries).
	switch {
	case w.Score >= c.AlertScore && (w.Primaries >= 2 || (w.Primaries >= 1 && w.Secondary >= 2)):
		w.Level = "alert"
	case w.Score >= c.WatchScore:
		w.Level = "watch"
	}
	return w
}

// ComputeRansomWindows scores one host's events (any order) into windows.
func ComputeRansomWindows(files []FileEvent, c RansomDetectConfig) []RansomWindow {
	if len(files) == 0 {
		return nil
	}
	fl := append([]FileEvent(nil), files...)
	sort.SliceStable(fl, func(i, j int) bool { return fl[i].Time.Before(fl[j].Time) })
	en := rdEnrich(fl)
	first, last := en[0].t, en[len(en)-1].t
	var out []RansomWindow
	lo := 0
	for s := first.Truncate(c.Stride); !s.After(last); s = s.Add(c.Stride) {
		e := s.Add(c.Window)
		for lo < len(en) && en[lo].t.Before(s) {
			lo++
		}
		hi := lo
		for hi < len(en) && en[hi].t.Before(e) {
			hi++
		}
		if hi > lo {
			out = append(out, rdScoreWindow(en[lo:hi], s, c))
		}
	}
	return out
}

// ComputeRansomHosts ranks hosts by peak window score.
func ComputeRansomHosts(files []FileEvent, c RansomDetectConfig) []RansomHost {
	by := map[string][]FileEvent{}
	for _, f := range files {
		if f.Host != "" && !f.Time.IsZero() {
			by[f.Host] = append(by[f.Host], f)
		}
	}
	out := []RansomHost{}
	for h, fl := range by {
		ws := ComputeRansomWindows(fl, c)
		if len(ws) == 0 {
			continue
		}
		rh := RansomHost{Host: h, Windows: len(ws), Peak: ws[0]}
		for _, w := range ws {
			if w.Level == "alert" {
				rh.Alerts++
			}
			if w.Score > rh.Peak.Score {
				rh.Peak = w
			}
		}
		out = append(out, rh)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Peak.Score != out[j].Peak.Score {
			return out[i].Peak.Score > out[j].Peak.Score
		}
		return out[i].Host < out[j].Host
	})
	return out
}

package edr

import (
	"fmt"
	"testing"
	"time"
)

// Hard benign cases chosen to resemble ransomware at the metadata level. They are
// reported (not part of the asserted FP rate) so the doc can state known false positives.
func rdHardBenignScenarios() []rdScenario {
	return []rdScenario{
		{"image_optimizer_inplace", func(g *rdGen) {
			var files []rdFile
			for i := 0; i < 400; i++ {
				f := rdFile{fmt.Sprintf("/home/u/Pictures/d%02d/p%d.jpg", i%20, i), int64(3_000_000 + g.r.Intn(1_000_000))}
				files = append(files, f)
				g.add(g.t0.Add(-time.Hour+time.Duration(i)*time.Millisecond), "create", f.p, f.size)
			}
			at := g.t0
			for _, f := range files {
				at = at.Add(g.step(10))
				g.add(at, "modify", f.p, f.size-int64(g.r.Intn(500))) // lossless re-pack
			}
		}},
		{"snapshot_mass_prune", func(g *rdGen) {
			at := g.t0
			for i := 0; i < 400; i++ {
				at = at.Add(g.step(15))
				g.add(at, "delete", fmt.Sprintf("/data/.snapshots/old.%d/blk%d", i%8, i), 0)
			}
		}},
	}
}

func TestRansomHardBenignReport(t *testing.T) {
	per, fp, tot := rdRate(t, rdHardBenignScenarios())
	t.Logf("hard-benign false alerts %d/%d per=%v (informational)", fp, tot, per)
}

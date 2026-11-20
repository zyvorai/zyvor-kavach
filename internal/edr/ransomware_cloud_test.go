package edr

import (
	"fmt"
	"testing"
	"time"
)

func TestRansomwareRisk(t *testing.T) {
	now := time.Now()
	ev := []Event{{Time: now, Host: "a", Command: "vssadmin delete shadows /all"}}
	var fl []FileEvent
	for i := 0; i < 60; i++ {
		fl = append(fl, FileEvent{Time: now, Host: "a", Path: fmt.Sprintf("/d/f%d.docx", i), Operation: "rename"})
	}
	fl = append(fl, FileEvent{Time: now, Host: "a", Path: "/d/HOW_TO_DECRYPT.txt", Operation: "create"})
	r := ComputeRansomwareRisk(ev, fl)
	if len(r) != 1 || r[0].Score < 70 || !r[0].ReportOnly {
		t.Fatalf("bad %+v", r)
	}
	if len(ComputeRansomwareRisk(nil, nil)) != 0 {
		t.Fatal("expected none")
	}
}

func TestContainerRisk(t *testing.T) {
	ev := []Event{
		{Host: "h", Command: "docker run --privileged -v /:/host nginx:1.0"},
		{Host: "h", Command: "docker run nginx:2.0"},
		{Host: "h", Command: "kubectl exec -it pod -- sh"},
	}
	r := ComputeContainerRisk(ev)
	if len(r) != 1 {
		t.Fatal(r)
	}
	kinds := map[string]bool{}
	for _, i := range r[0].Indicators {
		kinds[i.Kind] = true
	}
	for _, k := range []string{"privileged_container", "host_mount", "container_exec", "image_drift"} {
		if !kinds[k] {
			t.Errorf("missing %s", k)
		}
	}
}

func TestLateralEdges(t *testing.T) {
	nt := []NetworkEvent{{Host: "a", Destination: "10.0.0.2:3389"}, {Host: "a", Destination: "10.0.0.2:3389"}}
	ev := []Event{{Host: "a", Command: "ssh root@b"}}
	e := ComputeLateralEdges(ev, nt)
	if len(e) != 2 || e[0].Count != 2 || e[0].Protocol != "rdp" {
		t.Fatalf("%+v", e)
	}
}

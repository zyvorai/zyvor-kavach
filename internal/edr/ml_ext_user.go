// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Model 2: per-user / per-account behaviour baseline.
//
// Identity: auth telemetry uses its `user` field; process events only carry a numeric UID and use
// the key "uid:N" (so the two sources are separate identities unless the deployment reports numeric
// users in auth events). Features, each with its own cold-start guard:
//   - logon hour (UTC) from successful auth events: unusual when the hour and both neighbours were
//     never seen, after >= 30 logons;
//   - new host: successful logon to a host never seen for the user, after >= 30 logons;
//   - rare process: executable basename never seen for the user, after >= 100 process events.
// An event is evaluated against the state BEFORE it is learned, so the first occurrence is the one
// flagged. State per user is a 24-bin histogram, a capped hashed host set and a capped basename
// count map; no command lines.

const (
	mlUserMinLogons = 30
	mlUserMinProcs  = 100
	mlUserMaxHosts  = 64
	mlUserMaxAnom   = 20
	mlUserFactorWin = time.Hour
)

type mlUserAnom struct {
	Time   int64   `json:"time_unix"`
	Kind   string  `json:"kind"` // unusual_hour | new_host | rare_process
	Detail string  `json:"detail"`
	Bits   float64 `json:"surprisal_bits,omitempty"`
	Host   string  `json:"host,omitempty"`
}

type mlUser struct {
	Logons int            `json:"logons"`
	Fails  int            `json:"failed_logons"`
	Hours  [24]int        `json:"hours"`
	Hosts  []uint64       `json:"hosts"`
	Procs  map[string]int `json:"procs"`
	ProcN  int            `json:"proc_n"`
	POther int            `json:"proc_other,omitempty"` // events whose basename did not fit under the cap
	Anom   map[string]int `json:"anomalies"`
	Recent []mlUserAnom   `json:"recent"`
}

func (e *mlExtEngine) user(key string) *mlUser {
	u := e.st.Users[key]
	if u == nil {
		if len(e.st.Users) >= mlExtMaxUsers {
			e.st.Dropped["users"]++
			return nil
		}
		u = &mlUser{Procs: map[string]int{}, Anom: map[string]int{}, Recent: []mlUserAnom{}}
		e.st.Users[key] = u
	}
	return u
}

func (u *mlUser) note(a mlUserAnom) {
	u.Anom[a.Kind]++
	u.Recent = append(u.Recent, a)
	if len(u.Recent) > mlUserMaxAnom {
		u.Recent = append([]mlUserAnom(nil), u.Recent[len(u.Recent)-mlUserMaxAnom:]...)
	}
}

func hourSurprisal(u *mlUser, h int) float64 {
	return -math.Log2((float64(u.Hours[h]) + 0.5) / (float64(u.Logons) + 12))
}

func (e *mlExtEngine) learnUserAuth(t TelemetryEvent) {
	user := strings.ToLower(strings.TrimSpace(t.User))
	if user == "" || len(user) > 64 {
		return
	}
	u := e.user(user)
	if u == nil {
		return
	}
	if t.Outcome != "success" {
		u.Fails++
		return
	}
	hr := t.Time.UTC().Hour()
	hh := mlHash(t.Host)
	known := false
	for _, x := range u.Hosts {
		if x == hh {
			known = true
			break
		}
	}
	if u.Logons >= mlUserMinLogons {
		if u.Hours[hr] == 0 && u.Hours[(hr+23)%24] == 0 && u.Hours[(hr+1)%24] == 0 {
			u.note(mlUserAnom{Time: t.Time.Unix(), Kind: "unusual_hour", Detail: "logon at " + strconv.Itoa(hr) + ":00 UTC; this and both adjacent hours never seen",
				Bits: mlRound(hourSurprisal(u, hr), 2), Host: t.Host})
		}
		if !known && len(u.Hosts) < mlUserMaxHosts {
			u.note(mlUserAnom{Time: t.Time.Unix(), Kind: "new_host", Detail: "first logon to this host (" + strconv.Itoa(len(u.Hosts)) + " hosts known)", Host: t.Host})
		}
	}
	u.Logons++
	u.Hours[hr]++
	if !known && len(u.Hosts) < mlUserMaxHosts {
		u.Hosts = append(u.Hosts, hh)
	}
}

func (e *mlExtEngine) learnUserProc(ev Event) {
	b := mlBase(ev.Executable)
	if b == "" {
		return
	}
	u := e.user("uid:" + strconv.Itoa(ev.UID))
	if u == nil {
		return
	}
	_, seen := u.Procs[b]
	if !seen && u.ProcN >= mlUserMinProcs && len(u.Procs) < mlExtMaxItems {
		u.note(mlUserAnom{Time: ev.Time.Unix(), Kind: "rare_process", Detail: "executable never seen for this user: " + b, Host: ev.Host})
	}
	u.ProcN++
	if seen || len(u.Procs) < mlExtMaxItems {
		u.Procs[b]++
	} else {
		u.POther++
	}
}

func userStatus(u *mlUser) map[string]any {
	st := func(n, min int) string {
		if n < min {
			return "not_enough_data"
		}
		return "ok"
	}
	return map[string]any{
		"logon_hour":   map[string]any{"sample_count": u.Logons, "min_samples": mlUserMinLogons, "status": st(u.Logons, mlUserMinLogons)},
		"new_host":     map[string]any{"sample_count": u.Logons, "hosts_known": len(u.Hosts), "min_samples": mlUserMinLogons, "status": st(u.Logons, mlUserMinLogons)},
		"rare_process": map[string]any{"sample_count": u.ProcN, "distinct_executables": len(u.Procs), "min_samples": mlUserMinProcs, "status": st(u.ProcN, mlUserMinProcs)},
	}
}

type mlUserRow struct {
	User      string         `json:"user"`
	Logons    int            `json:"logons"`
	Procs     int            `json:"process_events"`
	Anomalies map[string]int `json:"anomalies"`
	Status    string         `json:"status"`
}

func (e *mlExtEngine) userView(user string, limit int) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := map[string]any{"method": mlMethod, "model": "user-baseline-v1", "users_tracked": len(e.st.Users), "dropped_users": e.st.Dropped["users"],
		"min_logons": mlUserMinLogons, "min_process_events": mlUserMinProcs,
		"note": "process events are keyed uid:N, auth telemetry by its user field; an event is judged against state before it is learned"}
	if user != "" {
		user = strings.ToLower(user)
		u := e.st.Users[user]
		res["user"] = user
		if u == nil {
			res["status"], res["sample_count"] = "not_enough_data", 0
			return res
		}
		res["sub_models"] = userStatus(u)
		res["sample_count"] = u.Logons + u.ProcN
		res["failed_logons"] = u.Fails
		res["status"] = "ok"
		if u.Logons < mlUserMinLogons && u.ProcN < mlUserMinProcs {
			res["status"] = "not_enough_data"
		}
		res["logon_hours_utc"] = u.Hours
		type pc struct {
			P string `json:"executable"`
			N int    `json:"count"`
		}
		var top []pc
		for _, k := range mlSortedKeys(u.Procs) {
			top = append(top, pc{k, u.Procs[k]})
		}
		sort.SliceStable(top, func(i, j int) bool { return top[i].N > top[j].N })
		if len(top) > 10 {
			top = top[:10]
		}
		res["top_executables"] = top
		res["anomaly_counts"] = u.Anom
		res["recent_anomalies"] = u.Recent
		return res
	}
	rows := []mlUserRow{}
	for _, k := range mlSortedKeys(e.st.Users) {
		u := e.st.Users[k]
		s := "ok"
		if u.Logons < mlUserMinLogons && u.ProcN < mlUserMinProcs {
			s = "not_enough_data"
		}
		rows = append(rows, mlUserRow{k, u.Logons, u.ProcN, u.Anom, s})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := 0, 0
		for _, v := range rows[i].Anomalies {
			a += v
		}
		for _, v := range rows[j].Anomalies {
			b += v
		}
		return a > b
	})
	res["total"] = len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	res["users"] = rows
	return res
}

// userFactor: anomalies for the finding's user (uid key) within an hour before the finding.
func (e *mlExtEngine) userFactor(f Finding) (float64, string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	u := e.st.Users["uid:"+strconv.Itoa(f.Evidence.UID)]
	if u == nil || u.ProcN < mlUserMinProcs {
		return 0, "no ready per-user baseline for this finding's account", false
	}
	n := 0
	for _, a := range u.Recent {
		t := time.Unix(a.Time, 0)
		if t.After(f.Time.Add(-mlUserFactorWin)) && t.Before(f.Time.Add(10*time.Minute)) {
			n++
		}
	}
	if n == 0 {
		return 0, "account within its baseline around the finding (" + strconv.Itoa(u.ProcN) + " process events seen)", true
	}
	return math.Min(1, 0.5+0.25*float64(n-1)), strconv.Itoa(n) + " baseline deviation(s) for this account near the finding", true
}

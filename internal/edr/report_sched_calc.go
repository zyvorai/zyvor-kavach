package edr

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Scheduled reports: pure schedule arithmetic and validation. Everything is
// UTC; there is no DST handling because UTC has none.

const (
	rsMaxSchedules   = 100
	rsMaxRetention   = 100
	rsDefaultRetain  = 7
	rsMaxParamLen    = 64
	rsMaxNameLen     = 80
	rsMaxSinceHours  = 24 * 365
	rsFreqHourly     = "hourly"
	rsFreqDaily      = "daily"
	rsFreqWeekly     = "weekly"
	rsFreqMonthly    = "monthly"
	rsFormatMarkdown = "markdown"
	rsFormatJSON     = "json"
	rsFormatCSV      = "csv"
)

type rsSchedule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name,omitempty"`
	Template   string            `json:"template"`
	Params     map[string]string `json:"params,omitempty"`
	Frequency  string            `json:"frequency"`
	Hour       int               `json:"hour"`                   // daily/weekly/monthly (UTC)
	Minute     int               `json:"minute"`                 // all frequencies
	Weekday    string            `json:"weekday,omitempty"`      // weekly: sun..sat
	DayOfMonth int               `json:"day_of_month,omitempty"` // monthly: 1-31, clamped to month end
	Retention  int               `json:"retention"`
	Format     string            `json:"format"`
	Enabled    bool              `json:"enabled"`
	CreatedAt  time.Time         `json:"created_at"`
	NextRun    time.Time         `json:"next_run,omitempty"`
	LastRun    time.Time         `json:"last_run,omitempty"`
	LastStatus string            `json:"last_status,omitempty"`
	LastRunID  string            `json:"last_run_id,omitempty"`
}

var rsWeekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

func rsParseWeekday(s string) (time.Weekday, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 3 {
		return 0, false
	}
	d, ok := rsWeekdays[s[:3]]
	return d, ok
}

func rsDaysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// rsNext returns the first scheduled instant strictly after `after` (UTC).
func rsNext(s rsSchedule, after time.Time) time.Time {
	after = after.UTC()
	switch s.Frequency {
	case rsFreqHourly:
		c := after.Truncate(time.Hour).Add(time.Duration(s.Minute) * time.Minute)
		if !c.After(after) {
			c = c.Add(time.Hour)
		}
		return c
	case rsFreqDaily:
		c := time.Date(after.Year(), after.Month(), after.Day(), s.Hour, s.Minute, 0, 0, time.UTC)
		if !c.After(after) {
			c = c.AddDate(0, 0, 1)
		}
		return c
	case rsFreqWeekly:
		wd, _ := rsParseWeekday(s.Weekday)
		c := time.Date(after.Year(), after.Month(), after.Day(), s.Hour, s.Minute, 0, 0, time.UTC)
		c = c.AddDate(0, 0, (int(wd)-int(c.Weekday())+7)%7)
		if !c.After(after) {
			c = c.AddDate(0, 0, 7)
		}
		return c
	case rsFreqMonthly:
		for i := 0; i < 3; i++ {
			// time.Date normalises month overflow into the next year
			base := time.Date(after.Year(), after.Month()+time.Month(i), 1, 0, 0, 0, 0, time.UTC)
			day := s.DayOfMonth
			if dim := rsDaysIn(base.Year(), base.Month()); day > dim {
				day = dim
			}
			c := time.Date(base.Year(), base.Month(), day, s.Hour, s.Minute, 0, 0, time.UTC)
			if c.After(after) {
				return c
			}
		}
	}
	return time.Time{}
}

var rsSeverityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// rsValidateParams checks the (small, closed) parameter set.
func rsValidateParams(p map[string]string) error {
	for k, v := range p {
		if len(v) > rsMaxParamLen {
			return fmt.Errorf("param %q too long", k)
		}
		switch k {
		case "since_hours":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > rsMaxSinceHours {
				return fmt.Errorf("since_hours must be 1-%d", rsMaxSinceHours)
			}
		case "min_severity":
			if _, ok := rsSeverityRank[strings.ToLower(v)]; !ok {
				return fmt.Errorf("min_severity must be one of info, low, medium, high, critical")
			}
		default:
			return fmt.Errorf("unknown param %q (supported: since_hours, min_severity)", k)
		}
	}
	return nil
}

// rsTemplateSupportsCSV: csv rows come from the data-bearing sections, so a
// template made only of manual sections has nothing to tabulate.
func rsTemplateSupportsCSV(t ReportTemplate) bool {
	for _, s := range t.Sections {
		if s.Source != "manual" {
			return true
		}
	}
	return false
}

func rsFindTemplate(id string) (ReportTemplate, bool) {
	for _, t := range ReportTemplates() {
		if t.ID == id {
			return t, true
		}
	}
	return ReportTemplate{}, false
}

// rsNormalize validates s in place and fills defaults.
func rsNormalize(s *rsSchedule) error {
	t, ok := rsFindTemplate(s.Template)
	if !ok {
		return fmt.Errorf("unknown template %q", s.Template)
	}
	if len(s.Name) > rsMaxNameLen {
		return fmt.Errorf("name too long")
	}
	if err := rsValidateParams(s.Params); err != nil {
		return err
	}
	if s.Format == "" {
		s.Format = rsFormatMarkdown
	}
	switch s.Format {
	case rsFormatMarkdown, rsFormatJSON:
	case rsFormatCSV:
		if !rsTemplateSupportsCSV(t) {
			return fmt.Errorf("template %q has no data sections, csv is not supported", t.ID)
		}
	default:
		return fmt.Errorf("format must be markdown, json or csv")
	}
	if s.Retention == 0 {
		s.Retention = rsDefaultRetain
	}
	if s.Retention < 1 || s.Retention > rsMaxRetention {
		return fmt.Errorf("retention must be 1-%d", rsMaxRetention)
	}
	if s.Minute < 0 || s.Minute > 59 || s.Hour < 0 || s.Hour > 23 {
		return fmt.Errorf("hour must be 0-23 and minute 0-59")
	}
	switch s.Frequency {
	case rsFreqHourly:
		s.Hour = 0
	case rsFreqDaily:
	case rsFreqWeekly:
		if _, ok := rsParseWeekday(s.Weekday); !ok {
			return fmt.Errorf("weekly needs weekday (mon..sun)")
		}
		s.Weekday = strings.ToLower(s.Weekday)[:3]
	case rsFreqMonthly:
		if s.DayOfMonth < 1 || s.DayOfMonth > 31 {
			return fmt.Errorf("monthly needs day_of_month 1-31 (clamped to the last day of shorter months)")
		}
	default:
		return fmt.Errorf("frequency must be hourly, daily, weekly or monthly")
	}
	return nil
}

// rsParseHHMM parses "HH:MM".
func rsParseHHMM(v string) (h, m int, err error) {
	p := strings.Split(v, ":")
	if len(p) != 2 {
		return 0, 0, fmt.Errorf("time must be HH:MM (UTC)")
	}
	h, e1 := strconv.Atoi(p[0])
	m, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("time must be HH:MM (UTC)")
	}
	return h, m, nil
}

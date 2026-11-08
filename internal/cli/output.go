package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// printJSON pretty-prints a data payload to stdout (the --json contract: the
// `data` payload, not the {"data":...} envelope).
func (a *App) printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode JSON output: %v", err)
	}
	_, err = fmt.Fprintln(a.Stdout, string(b))
	return err
}

// writeTable renders a plain aligned table to w.
func writeTable(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		cells := make([]string, len(row))
		for i := range row {
			cells[i] = sanitizeCell(row[i])
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
}

// sanitizeCell keeps one cell on one line so table layout cannot be broken by
// server-provided strings.
func sanitizeCell(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
}

// fmtTime renders a timestamp in UTC RFC3339, or "-" for the zero value.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// fmtTimePtr renders an optional timestamp.
func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return fmtTime(*t)
}

// formatSeconds renders a duration in seconds as a human-readable duration.
func formatSeconds(secs int) string {
	if secs <= 0 {
		return "-"
	}
	return (time.Duration(secs) * time.Second).String()
}

// joinOrDash joins a string slice for table display.
func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

// yesNo renders a boolean for human output.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

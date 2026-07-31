package db

import (
	"strconv"
	"time"
)

// parseLocalEpoch converts a stored "2006-01-02 15:04:05" timestamp (written in
// the server's local time) into Unix seconds so the browser can compute relative
// time without guessing the timezone. Returns 0 for empty/unparseable values.
func parseLocalEpoch(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.Local)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func FormatBytes(bytes int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
		TB = 1 << 40
	)
	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/TB, 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/GB, 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/MB, 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/KB, 'f', 2, 64) + " KB"
	default:
		return strconv.FormatInt(bytes, 10) + " B"
	}
}

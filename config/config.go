package config

import (
	"context"
	"database/sql"
	"time"
)

type Options struct {
	Addr         string
	AdminUser    string
	AdminPass    string
	Log          string
	CertsDir     string
	IPPFile      string
	ServerConfig string
	SessionTTL   time.Duration
}

func LoadFromDB(ctx context.Context, sqldb *sql.DB) (Options, error) {
	rows, err := sqldb.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return Options{}, err
	}
	defer rows.Close()
	vals := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return Options{}, err
		}
		vals[k] = v
	}
	if err := rows.Err(); err != nil {
		return Options{}, err
	}
	return Options{
		Addr:         vals["addr"],
		AdminUser:    vals["admin_user"],
		AdminPass:    vals["admin_pass"],
		Log:          vals["openvpn_status_log"],
		CertsDir:     vals["openvpn_cert_dir"],
		IPPFile:      vals["openvpn_ipp_file"],
		ServerConfig: vals["openvpn_server_config"],
		SessionTTL:   24 * time.Hour,
	}, nil
}

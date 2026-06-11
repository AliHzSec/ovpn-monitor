package model

type Client struct {
	CommonName            string `json:"common_name"`
	RealAddress           string `json:"real_address"`
	VPNAddress            string `json:"vpn_address"`
	BytesReceived         int64  `json:"bytes_received"`
	BytesSent             int64  `json:"bytes_sent"`
	TotalTraffic          int64  `json:"total_traffic"`
	ConnectedSince        string `json:"connected_since"`
	LastSeen              string `json:"last_seen"`
	BytesReceivedReadable string `json:"bytes_received_readable"`
	BytesSentReadable     string `json:"bytes_sent_readable"`
	TotalTrafficReadable  string `json:"total_traffic_readable"`
	Online                bool   `json:"online"`
}

type LogEntry struct {
	CommonName     string
	RealAddress    string
	VPNAddress     string
	Protocol       string
	BytesReceived  int64
	BytesSent      int64
	ConnectedSince string
	ConnectedEpoch int64
}

type ClientPortalData struct {
	CommonName     string
	VPNAddress     string
	Online         bool
	ConnectedSince string
	LastSeen       string
}

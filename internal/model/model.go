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
	ConnectedSinceEpoch   int64  `json:"connected_since_epoch"`
	LastSeenEpoch         int64  `json:"last_seen_epoch"`
	BytesReceivedReadable string `json:"bytes_received_readable"`
	BytesSentReadable     string `json:"bytes_sent_readable"`
	TotalTrafficReadable  string `json:"total_traffic_readable"`
	Online                bool   `json:"online"`

	// Per-system connection state. Online (above) stays the union so existing
	// consumers keep working; these say HOW the client is currently connected
	// (a person can be online via both systems at once, e.g. PC on OpenVPN and
	// phone on WireGuard). Sources lists which systems the client is provisioned
	// in ("openvpn" = valid certificate, "wireguard" = peer in wg0.conf).
	OnlineOpenVPN   bool     `json:"online_openvpn"`
	OnlineWireGuard bool     `json:"online_wireguard"`
	Sources         []string `json:"sources"`

	// All-time per-protocol traffic split (WireGuard sessions vs everything
	// else). Populated only by the single-client detail handler.
	TrafficOpenVPN           int64  `json:"traffic_openvpn"`
	TrafficWireGuard         int64  `json:"traffic_wireguard"`
	TrafficOpenVPNReadable   string `json:"traffic_openvpn_readable"`
	TrafficWireGuardReadable string `json:"traffic_wireguard_readable"`
}

// VisitedDomain is one aggregated (client, root-domain) browsing record. Epoch
// fields are the local timestamps in Unix seconds so the browser can render
// timezone-safe relative times, matching how Client timestamps are exposed.
type VisitedDomain struct {
	Domain         string `json:"domain"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
	VisitCount     int64  `json:"visit_count"`
	FirstSeenEpoch int64  `json:"first_seen_epoch"`
	LastSeenEpoch  int64  `json:"last_seen_epoch"`
}

// WGPeerState is the persisted raw-counter snapshot for one WireGuard peer
// (one row of wg_peer_state). LastRX/LastTX are the kernel's cumulative
// counters as of the last applied poll — the baseline the next delta is
// computed against.
type WGPeerState struct {
	PubKey string
	Name   string
	LastRX int64
	LastTX int64
}

// WGPeerDelta carries one poll's outcome for one WireGuard peer into the DB
// layer. DeltaDown/DeltaUp are the byte increments to apply to the peer's
// session (client-download / client-upload orientation, matching the sessions
// table's bytes_received / bytes_sent). LastRX/LastTX are the raw kernel
// counters to persist as the new baseline in the SAME transaction, so a crash
// between poll and write can never double-apply a delta.
type WGPeerDelta struct {
	Name        string
	PubKey      string
	RealAddress string // peer endpoint ip:port, "" when the kernel has none
	VPNAddress  string // host part of the peer's first IPv4 allowed-ips entry
	DeltaDown   int64  // add to sessions.bytes_received (client downloaded)
	DeltaUp     int64  // add to sessions.bytes_sent (client uploaded)
	LastRX      int64  // raw counter: bytes the server received from the peer
	LastTX      int64  // raw counter: bytes the server sent to the peer
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

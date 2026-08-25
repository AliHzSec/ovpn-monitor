// models/types.ts — TypeScript mirrors of the Go JSON payloads.
// Field names match the json tags in internal/sysinfo/sysinfo.go and
// internal/model/model.go exactly.

export interface SystemStats {
  cpu_percent: number;
  cpu_cores: number;
  mem_total: number;
  mem_used: number;
  mem_free: number;
  swap_total: number;
  swap_used: number;
  disk_total: number;
  disk_used: number;
  disk_free: number;
  net_up_speed: number; // bytes/sec
  net_down_speed: number; // bytes/sec
  net_sent: number; // interface counter: total bytes sent since boot
  net_recv: number; // interface counter: total bytes received since boot
  vpn_total_sent: number; // all-time sum of VPN client bytes_sent from DB
  vpn_total_recv: number; // all-time sum of VPN client bytes_received from DB
  ips: string[];
  ipv6s: string[];
  tcp_count: number;
  udp_count: number;
  os_uptime: number; // seconds since system boot
  ovpn_uptime: number; // seconds since openvpn service started
  wireguard_uptime: number; // seconds since wg-quick@wg0 went active
  os_name: string; // PRETTY_NAME from /etc/os-release
  client_online: number; // currently connected VPN clients
  client_total: number; // total registered VPN clients
  kernel_version: string;
  timezone: string;
  virtualization: string;
}

export interface Client {
  common_name: string;
  real_address: string;
  vpn_address: string;
  bytes_received: number;
  bytes_sent: number;
  total_traffic: number;
  connected_since: string;
  last_seen: string;
  connected_since_epoch: number;
  last_seen_epoch: number;
  bytes_received_readable: string;
  bytes_sent_readable: string;
  total_traffic_readable: string;
  online: boolean;

  // Per-system connection state: online_openvpn / online_wireguard say HOW the
  // client is connected; sources lists the systems it is provisioned in
  // ("openvpn" = valid certificate, "wireguard" = peer in wg0.conf).
  online_openvpn: boolean;
  online_wireguard: boolean;
  sources: string[];

  // All-time per-protocol traffic split (single-client detail only).
  traffic_openvpn: number;
  traffic_wireguard: number;
  traffic_openvpn_readable: string;
  traffic_wireguard_readable: string;
}

// VisitedDomain serves both levels of the visited-domains UI: top-level rows
// (Domain is a root domain, values rolled up across its hostnames) and a root
// domain's detail rows (Domain is one hostname with its own values).
export interface VisitedDomain {
  domain: string;
  first_seen: string;
  last_seen: string;
  visit_count: number;
  first_seen_epoch: number;
  last_seen_epoch: number;
  subdomain_count?: number; // top-level rows only
  hostnames?: string; // search blob, top-level rows only
}

// POST /api/service/{name}/{action} response.
export interface ServiceActionResult {
  ok: boolean;
  active: boolean;
  error?: string;
}

// GET /api/settings/{service}/ipv6 response. "unknown" means the config file's
// IPv6 markers are missing or inconsistent and need manual attention.
export type IPv6State = 'enabled' | 'disabled' | 'unknown';

export interface IPv6StateResult {
  state: IPv6State;
}

// PUT /api/settings/{service}/ipv6 response.
export interface IPv6SetResult {
  ok: boolean;
  state: IPv6State;
  error?: string;
}

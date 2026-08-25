import { formatUptime } from '@/utils/format';
import { pickPublicIPv4, pickPublicIPv6 } from '@/utils/ip';
import type { SystemStats } from '@/models/types';

// SysInfoCard — the mock's System Info section: label/value rows separated by
// hairlines. Rows match the mock: uptime, OS, kernel, time zone.
export function SysInfoCard({ stats }: { stats: SystemStats }) {
  const rows: Array<{ k: string; v: string }> = [
    { k: 'Uptime', v: formatUptime(stats.os_uptime || 0) },
    { k: 'OS', v: stats.os_name || '—' },
    { k: 'Kernel', v: stats.kernel_version || '—' },
    { k: 'Time zone', v: stats.timezone || '—' },
  ];

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">System Info</div>
      <div className="ovp-info-body">
        {rows.map((r) => (
          <div key={r.k} className="ovp-info-row">
            <div className="ovp-info-k">{r.k}</div>
            <div className="ovp-info-v">{r.v}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

// IpCard — the mock's IP Addresses section: IPv4 block, hairline, IPv6 block.
export function IpCard({ stats }: { stats: SystemStats }) {
  const ipv4 = pickPublicIPv4(stats.ips || []);
  const ipv6 = pickPublicIPv6(stats.ipv6s || []);

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">IP Addresses</div>
      <div className="ovp-ip-body">
        <div className="ovp-ip-block">
          <div className="ovp-klabel">IPv4</div>
          <div className="ovp-ip-val">{ipv4 ?? '—'}</div>
        </div>
        <div className="ovp-ip-sep" />
        <div className="ovp-ip-block">
          <div className="ovp-klabel">IPv6</div>
          <div className="ovp-ip-val ovp-ip-val-v6">{ipv6 ?? '—'}</div>
        </div>
      </div>
    </section>
  );
}

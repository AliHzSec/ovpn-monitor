import { Card } from 'antd';
import { ClockCircleOutlined, GlobalOutlined, HddOutlined, TeamOutlined } from '@ant-design/icons';

import CopyText from '@/components/ui/CopyText';
import { formatUptime } from '@/utils/format';
import { pickPublicIPv4, pickPublicIPv6 } from '@/utils/ip';
import type { SystemStats } from '@/models/types';

interface SystemStripProps {
  stats: SystemStats;
}

// Bottom strip — a structural port of 3x-ui's pages/index/SystemStrip.tsx
// (one card, kicker-headed cells separated by hairlines), extended to the four
// fact groups this panel has: uptime, clients, system info, IP addresses.
export default function SystemStrip({ stats }: SystemStripProps) {
  const ipv4 = pickPublicIPv4(stats.ips || []);
  const ipv6 = pickPublicIPv6(stats.ipv6s || []);
  const clOnline = stats.client_online ?? 0;
  const clTotal = stats.client_total ?? 0;
  const clOffline = Math.max(0, clTotal - clOnline);

  return (
    <Card hoverable styles={{ body: { padding: 0 } }}>
      <div className="ov-strip-grid">
        <div className="ov-strip-cell">
          <div className="ov-kicker ov-kicker-icon">
            <ClockCircleOutlined />
            Uptime
          </div>
          <div className="ov-strip-split">
            <div>
              <div className="ov-strip-sub">OS</div>
              <div className="ov-strip-value">{formatUptime(stats.os_uptime || 0)}</div>
            </div>
            <span className="ov-strip-split-sep" />
            <div>
              <div className="ov-strip-sub">OpenVPN</div>
              <div className="ov-strip-value">
                {stats.ovpn_uptime > 0 ? formatUptime(stats.ovpn_uptime) : '—'}
              </div>
            </div>
            <span className="ov-strip-split-sep" />
            <div>
              <div className="ov-strip-sub">WireGuard</div>
              <div className="ov-strip-value">
                {stats.wireguard_uptime > 0 ? formatUptime(stats.wireguard_uptime) : '—'}
              </div>
            </div>
          </div>
        </div>

        <div className="ov-strip-cell">
          <div className="ov-kicker ov-kicker-icon">
            <TeamOutlined />
            Clients
          </div>
          <div className="ov-strip-split">
            <div>
              <div className="ov-strip-sub">Total</div>
              <div className="ov-strip-value">{clTotal}</div>
            </div>
            <span className="ov-strip-split-sep" />
            <div>
              <div className="ov-strip-sub">Online</div>
              <div className="ov-strip-value ov-strip-online">{clOnline}</div>
            </div>
            <span className="ov-strip-split-sep" />
            <div>
              <div className="ov-strip-sub">Offline</div>
              <div className="ov-strip-value ov-strip-offline">{clOffline}</div>
            </div>
          </div>
        </div>

        <div className="ov-strip-cell">
          <div className="ov-kicker ov-kicker-icon">
            <HddOutlined />
            System Info
          </div>
          <div className="ov-strip-facts">
            <div className="ov-strip-fact">
              <span className="ov-strip-sub">Kernel</span>
              <span className="ov-strip-fact-value">{stats.kernel_version || '—'}</span>
            </div>
            <div className="ov-strip-fact">
              <span className="ov-strip-sub">Time Zone</span>
              <span className="ov-strip-fact-value">{stats.timezone || '—'}</span>
            </div>
            <div className="ov-strip-fact">
              <span className="ov-strip-sub">Virtualization</span>
              <span className="ov-strip-fact-value">{stats.virtualization || '—'}</span>
            </div>
          </div>
        </div>

        <div className="ov-strip-cell">
          <div className="ov-kicker ov-kicker-icon">
            <GlobalOutlined />
            IP Addresses
          </div>
          <div className="ov-ip">
            <div className="ov-mono">
              {ipv4 ? <CopyText text={ipv4} /> : <span className="ov-ip-none">N/A</span>}
            </div>
            <div className="ov-mono ov-ip-v6">
              {ipv6 ? <CopyText text={ipv6} /> : <span className="ov-ip-none">N/A</span>}
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

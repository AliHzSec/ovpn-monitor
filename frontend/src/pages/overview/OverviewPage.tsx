import { Card, Skeleton } from 'antd';
import { TeamOutlined } from '@ant-design/icons';

import { useServerStats } from '@/api/queries/useServerStats';
import CopyText from '@/components/ui/CopyText';
import PageShell from '@/components/ui/PageShell';
import ServiceCard from '@/components/ui/ServiceCard';
import Sparkline from '@/components/viz/Sparkline';
import { formatBytes, formatSpeed, formatUptime } from '@/utils/format';
import { pickPublicIPv4, pickPublicIPv6 } from '@/utils/ip';

import { RingGauge } from './RingGauge';
import { useSpeedHistory } from './useSpeedHistory';
import './OverviewPage.css';

// First-load placeholder: same grid shape as the loaded page.
function OverviewSkeleton() {
  return (
    <>
      <div className="ov-row">
        <Card className="glass-card" variant="borderless">
          <Skeleton active paragraph={{ rows: 4 }} />
        </Card>
        <Card className="glass-card" variant="borderless">
          <Skeleton active paragraph={{ rows: 3 }} />
        </Card>
      </div>
      <div className="info-grid">
        {Array.from({ length: 4 }, (_, i) => (
          <Card key={i} className="glass-card info-card" variant="borderless">
            <Skeleton active paragraph={{ rows: 2 }} />
          </Card>
        ))}
      </div>
      <div className="info-grid">
        {Array.from({ length: 4 }, (_, i) => (
          <Card key={i} className="glass-card info-card" variant="borderless">
            <Skeleton active paragraph={{ rows: 2 }} />
          </Card>
        ))}
      </div>
    </>
  );
}

export default function OverviewPage() {
  const { data: stats, dataUpdatedAt, isPending } = useServerStats();
  const speedHistory = useSpeedHistory(stats, dataUpdatedAt);

  if (isPending || !stats) {
    return (
      <PageShell title="Overview" className="overview-page">
        <OverviewSkeleton />
      </PageShell>
    );
  }

  // ── Resources: CPU · RAM · Swap · Disk ──
  const cpuRatio = (stats.cpu_percent || 0) / 100;
  const ramTotal = stats.mem_total || 0;
  const ramUsed = stats.mem_used || 0;
  const ramRatio = ramTotal > 0 ? ramUsed / ramTotal : 0;
  const diskTotal = stats.disk_total || 0;
  const diskUsed = stats.disk_used || 0;
  const diskRatio = diskTotal > 0 ? diskUsed / diskTotal : 0;
  const swapTotal = stats.swap_total || 0;
  const swapUsed = stats.swap_used || 0;
  const hasSwap = swapTotal > 0;
  const swapRatio = hasSwap ? swapUsed / swapTotal : 0;
  // All four gauges share one card, so the outline reflects the WORST of them
  // (SeverityCard thresholds: warn >= 70%, critical >= 90%).
  const worst = Math.max(cpuRatio, ramRatio, diskRatio, swapRatio);
  const severity = worst >= 0.9 ? 'critical' : worst >= 0.7 ? 'warn' : 'ok';

  // ── Clients ──
  const clOnline = stats.client_online ?? 0;
  const clTotal = stats.client_total ?? 0;
  const clOffline = Math.max(0, clTotal - clOnline);
  const pctOn = clTotal ? (clOnline / clTotal) * 100 : 0;
  const pctCaption = `${pctOn % 1 === 0 ? pctOn : pctOn.toFixed(1)}% Online`;

  // ── Total VPN traffic (DB sums, NOT the interface counters) ──
  const vpnSent = stats.vpn_total_sent || 0;
  const vpnRecv = stats.vpn_total_recv || 0;

  // ── IP addresses ──
  const ipv4 = pickPublicIPv4(stats.ips || []);
  const ipv6 = pickPublicIPv6(stats.ipv6s || []);

  return (
    <PageShell title="Overview" className="overview-page">
      {/* Row 1: Server Resources (large) + Clients */}
      <div className="ov-row">
        <div className={`severity-card severity-${severity}`}>
          <Card className="glass-card resources-card" variant="borderless">
            <RingGauge label="CPU" ratio={cpuRatio} sublabel={`${stats.cpu_cores || '?'} Cores`} />
            <RingGauge
              label="RAM"
              ratio={ramRatio}
              sublabel={`${formatBytes(ramUsed)} / ${formatBytes(ramTotal)}`}
            />
            <RingGauge
              label="Swap"
              ratio={swapRatio}
              unavailable={!hasSwap}
              sublabel={hasSwap ? `${formatBytes(swapUsed)} / ${formatBytes(swapTotal)}` : 'No Swap'}
            />
            <RingGauge
              label="Disk"
              ratio={diskRatio}
              sublabel={`${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`}
            />
          </Card>
        </div>

        <Card className="glass-card clients-card" variant="borderless">
          <div className="clients-top">
            <div className="clients-main">
              <div className="clients-title-row">
                <div className="clients-icon-box">
                  <TeamOutlined />
                </div>
                <span className="clients-title">Clients</span>
              </div>
              <div className="clients-total">{clTotal}</div>
              <div className="clients-total-label">Total Clients</div>
            </div>
            <div className="clients-side">
              <div className="clients-side-stat">
                <span className="clients-side-value online">{clOnline}</span>
                <span className="clients-side-label">Online</span>
              </div>
              <div className="clients-side-stat">
                <span className="clients-side-value offline">{clOffline}</span>
                <span className="clients-side-label">Offline</span>
              </div>
            </div>
          </div>
          <div className="ratio-bar">
            <div className="ratio-bar-fill is-success" style={{ width: `${pctOn}%` }} />
          </div>
          <div className="clients-pct-caption">{pctCaption}</div>
        </Card>
      </div>

      {/* Row 2: live speed · total data · service controls */}
      <div className="info-grid">
        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            Live Speed
          </div>
          <div className="info-rows">
            <div className="info-row">
              <span className="info-row-label">Upload</span>
              <span className="info-row-value val-up">↑ {formatSpeed(stats.net_up_speed || 0)}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">Download</span>
              <span className="info-row-value val-down">
                ↓ {formatSpeed(stats.net_down_speed || 0)}
              </span>
            </div>
          </div>
          <div className="speed-sparkline">
            <Sparkline
              data={speedHistory.up}
              data2={speedHistory.down}
              name1="Upload"
              name2="Download"
              height={56}
              valueMax={null}
              yFormatter={formatSpeed}
            />
          </div>
        </Card>

        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            Total Data
          </div>
          <div className="info-rows cols-3">
            <div className="info-row">
              <span className="info-row-label">Total</span>
              <span className="info-row-value">{formatBytes(vpnSent + vpnRecv)}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">Received</span>
              <span className="info-row-value val-down">{formatBytes(vpnRecv)}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">Sent</span>
              <span className="info-row-value val-up">{formatBytes(vpnSent)}</span>
            </div>
          </div>
        </Card>

        <ServiceCard service="openvpn" title="OpenVPN" />
        <ServiceCard service="wireguard" title="WireGuard" />
      </div>

      {/* Bottom row: IP · Uptime · Connections · System Info */}
      <div className="info-grid">
        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            IP Addresses
          </div>
          <div className="info-rows">
            <div className="info-row">
              <span className="info-row-label">IPv4</span>
              {ipv4 ? (
                <CopyText text={ipv4} />
              ) : (
                <span className="info-row-value muted">N/A</span>
              )}
            </div>
            <div className="info-row">
              <span className="info-row-label">IPv6</span>
              {ipv6 ? (
                <CopyText text={ipv6} />
              ) : (
                <span className="info-row-value muted">N/A</span>
              )}
            </div>
          </div>
        </Card>

        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            Uptime
          </div>
          {/* Uptime strings run long ("14d 1h 4m 16s"); the stacked layout
              gives each one the full card width. */}
          <div className="info-rows vertical">
            <div className="info-row">
              <span className="info-row-label">
                {stats.os_name ? `OS - ${stats.os_name}` : 'OS'}
              </span>
              <span className="info-row-value">{formatUptime(stats.os_uptime || 0)}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">OpenVPN Service</span>
              {stats.ovpn_uptime > 0 ? (
                <span className="info-row-value">{formatUptime(stats.ovpn_uptime)}</span>
              ) : (
                <span className="info-row-value muted">Not Running</span>
              )}
            </div>
            <div className="info-row">
              <span className="info-row-label">WireGuard Service</span>
              {stats.wireguard_uptime > 0 ? (
                <span className="info-row-value">{formatUptime(stats.wireguard_uptime)}</span>
              ) : (
                <span className="info-row-value muted">Not Running</span>
              )}
            </div>
          </div>
        </Card>

        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot is-success" />
            Connection Stats
          </div>
          <div className="info-rows">
            <div className="info-row">
              <span className="info-row-label">TCP</span>
              <span className="info-row-value">{stats.tcp_count ?? '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">UDP</span>
              <span className="info-row-value">{stats.udp_count ?? '—'}</span>
            </div>
          </div>
        </Card>

        <Card className="glass-card info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot is-muted" />
            System Info
          </div>
          <div className="info-rows vertical">
            <div className="info-row">
              <span className="info-row-label">Kernel</span>
              <span className="info-row-value">{stats.kernel_version || '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">Time Zone</span>
              <span className="info-row-value">{stats.timezone || '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-row-label">Virtualization</span>
              <span className="info-row-value">{stats.virtualization || '—'}</span>
            </div>
          </div>
        </Card>
      </div>
    </PageShell>
  );
}

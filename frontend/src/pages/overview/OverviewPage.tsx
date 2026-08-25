import { useMemo } from 'react';
import { Card, Skeleton, theme } from 'antd';
import { DashboardOutlined, DatabaseOutlined, HddOutlined, SwapOutlined } from '@ant-design/icons';

import { useServerStats } from '@/api/queries/useServerStats';
import ServiceCard from '@/components/ui/ServiceCard';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import { formatBytes } from '@/utils/format';

import VitalTile, { USAGE_CRIT_PERCENT, USAGE_WARN_PERCENT } from './VitalTile';
import ThroughputCard from './ThroughputCard';
import ConnectionsCard from './ConnectionsCard';
import SystemStrip from './SystemStrip';
import { mean, peak, useOverviewHistory } from './useOverviewHistory';
import './OverviewPage.css';

function formatClock(ms: number): string {
  if (!ms) return '—';
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// First-load placeholder: same grid shape as the loaded page.
function OverviewSkeleton() {
  return (
    <div className="ov-page">
      <div className="ov-vitals">
        {Array.from({ length: 4 }, (_, i) => (
          <Card key={i} className="ov-tile">
            <Skeleton active paragraph={{ rows: 3 }} />
          </Card>
        ))}
      </div>
      <div className="ov-mid">
        <Card>
          <Skeleton active paragraph={{ rows: 5 }} />
        </Card>
        <Card>
          <Skeleton active paragraph={{ rows: 5 }} />
        </Card>
      </div>
    </div>
  );
}

// Overview — a structural port of 3x-ui's pages/index/IndexPage.tsx:
// action bar with service state pills, vital tiles with history charts,
// throughput + connections row, service control cards, system strip.
export default function OverviewPage() {
  const { token } = theme.useToken();
  const { isMobile } = useMediaQuery();
  const { data: stats, dataUpdatedAt, isPending } = useServerStats();
  const history = useOverviewHistory(stats, dataUpdatedAt);
  const updated = useMemo(() => formatClock(dataUpdatedAt), [dataUpdatedAt]);

  // ── Resources: CPU · RAM · Swap · Disk ──
  // Derived with safe defaults BEFORE the loading early-return below: every
  // hook (including the health useMemo) must run on every render.
  const ramTotal = stats?.mem_total || 0;
  const ramUsed = stats?.mem_used || 0;
  const ramPct = ramTotal > 0 ? (ramUsed / ramTotal) * 100 : 0;
  const diskTotal = stats?.disk_total || 0;
  const diskUsed = stats?.disk_used || 0;
  const diskPct = diskTotal > 0 ? (diskUsed / diskTotal) * 100 : 0;
  const diskFree = Math.max(0, diskTotal - diskUsed);
  const swapTotal = stats?.swap_total || 0;
  const swapUsed = stats?.swap_used || 0;
  const hasSwap = swapTotal > 0;
  const swapPct = hasSwap ? (swapUsed / swapTotal) * 100 : 0;
  const cpuPct = stats?.cpu_percent || 0;

  // Health line, as in 3x-ui's IndexPage: names the vitals past the warn /
  // critical thresholds (80% / 90%), hidden when everything is fine.
  const health = useMemo(() => {
    const items = [
      { name: 'CPU', value: cpuPct },
      { name: 'RAM', value: ramPct },
      { name: 'Swap', value: swapPct },
      { name: 'Disk', value: diskPct },
    ];
    const list = (xs: typeof items) => xs.map((i) => `${i.name} ${i.value.toFixed(0)}%`).join(', ');
    const crit = items.filter((i) => i.value >= USAGE_CRIT_PERCENT);
    if (crit.length) return { text: `Critical usage: ${list(crit)}`, color: token.colorError };
    const warm = items.filter((i) => i.value >= USAGE_WARN_PERCENT);
    if (warm.length) return { text: `High usage: ${list(warm)}`, color: token.colorWarning };
    return null;
  }, [cpuPct, ramPct, swapPct, diskPct, token.colorError, token.colorWarning]);

  if (isPending || !stats) {
    return (
      <div className="overview-page">
        <OverviewSkeleton />
      </div>
    );
  }

  const ovpnRunning = (stats.ovpn_uptime ?? 0) > 0;
  const wgRunning = (stats.wireguard_uptime ?? 0) > 0;

  const statePill = (label: string, running: boolean) => (
    <span className="ov-state" data-state={running ? 'running' : 'stop'}>
      <span
        className="ov-state-dot"
        style={{ color: running ? token.colorSuccess : token.colorTextTertiary }}
      />
      <span>{`${label} · ${running ? 'Running' : 'Stopped'}`}</span>
    </span>
  );

  return (
    <div className="overview-page">
      <div className="ov-page">
        <div className="ov-bar">
          {statePill('OpenVPN', ovpnRunning)}
          {statePill('WireGuard', wgRunning)}
          <span className="ov-bar-updated ov-mono">Updated {updated}</span>
        </div>

        {health && (
          <div className="ov-health" style={{ color: health.color }}>
            <span className="ov-health-mark" />
            {health.text}
          </div>
        )}

        <hr className="ov-rule" />

        <div className="ov-vitals">
          <VitalTile
            icon={<DashboardOutlined />}
            label="CPU"
            percent={cpuPct}
            detail={`${stats.cpu_cores || '?'} Cores`}
            footLeft={`Avg ${mean(history.series.cpu).toFixed(0)}%`}
            footRight={`Peak ${peak(history.series.cpu).toFixed(0)}%`}
            data={history.series.cpu}
            isMobile={isMobile}
          />
          <VitalTile
            icon={<DatabaseOutlined />}
            label="RAM"
            percent={ramPct}
            detail={`${formatBytes(ramUsed)} / ${formatBytes(ramTotal)}`}
            footLeft={`Avg ${mean(history.series.mem).toFixed(0)}%`}
            footRight={`Peak ${peak(history.series.mem).toFixed(0)}%`}
            data={history.series.mem}
            isMobile={isMobile}
          />
          <VitalTile
            icon={<SwapOutlined />}
            label="Swap"
            percent={swapPct}
            detail={hasSwap ? `${formatBytes(swapUsed)} / ${formatBytes(swapTotal)}` : 'No Swap'}
            footLeft={`Avg ${mean(history.series.swap).toFixed(1)}%`}
            footRight={`Peak ${peak(history.series.swap).toFixed(0)}%`}
            data={history.series.swap}
            isMobile={isMobile}
          />
          <VitalTile
            icon={<HddOutlined />}
            label="Disk"
            percent={diskPct}
            detail={`${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`}
            footLeft={`Free ${formatBytes(diskFree)}`}
            footRight={`Avg ${mean(history.series.disk).toFixed(1)}%`}
            data={history.series.disk}
            isMobile={isMobile}
          />
        </div>

        <div className="ov-mid">
          <ThroughputCard
            stats={stats}
            up={history.series.netUp}
            down={history.series.netDown}
            labels={history.labels}
            isMobile={isMobile}
          />
          <ConnectionsCard
            stats={stats}
            tcp={history.series.tcp}
            udp={history.series.udp}
            labels={history.labels}
            isMobile={isMobile}
          />
        </div>

        <div className="ov-services">
          <ServiceCard service="openvpn" title="OpenVPN" />
          <ServiceCard service="wireguard" title="WireGuard" />
        </div>

        <SystemStrip stats={stats} />
      </div>
    </div>
  );
}

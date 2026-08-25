import { useEffect, useState } from 'react';

import { useServerStats } from '@/api/queries/useServerStats';
import { formatBytes } from '@/utils/format';

import GaugeCard from './GaugeCard';
import ClientsCard from './ClientsCard';
import TrafficCard from './TrafficCard';
import SpeedCard from './SpeedCard';
import SocketsCard from './SocketsCard';
import ServicePanelCard from './ServicePanelCard';
import { IpCard, SysInfoCard } from './SystemCards';
import { useOverviewHistory } from './useOverviewHistory';
import './OverviewPage.css';

function wallClock(): string {
  return new Date().toLocaleTimeString('en-GB');
}

// First-load placeholder: same grid shape as the loaded page.
function OverviewSkeleton() {
  return (
    <div className="ovp">
      <div className="ovp-vitals">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="ovp-skel" style={{ height: 236 }} />
        ))}
      </div>
      <div className="ovp-grid2">
        <div className="ovp-skel" style={{ height: 220 }} />
        <div className="ovp-skel" style={{ height: 220 }} />
        <div className="ovp-skel" style={{ height: 220 }} />
        <div className="ovp-skel" style={{ height: 220 }} />
      </div>
    </div>
  );
}

// Overview — rebuilt to the designer's mock (VPN Monitor.dc.html): centered
// live clock, four arc-gauge resource cards, then two-column card rows for
// clients/traffic, speed/sockets and the service/system cards.
export default function OverviewPage() {
  const { data: stats, dataUpdatedAt, isPending } = useServerStats();
  const history = useOverviewHistory(stats, dataUpdatedAt);

  // The mock's clock is wall time, ticking once a second.
  const [clock, setClock] = useState(wallClock);
  useEffect(() => {
    const t = setInterval(() => setClock(wallClock()), 1000);
    return () => clearInterval(t);
  }, []);

  // ── Resources: CPU · RAM · Swap · Disk ──
  // Derived with safe defaults BEFORE the loading early-return below so every
  // hook runs on every render.
  const ramTotal = stats?.mem_total || 0;
  const ramUsed = stats?.mem_used || 0;
  const ramPct = ramTotal > 0 ? (ramUsed / ramTotal) * 100 : 0;
  const diskTotal = stats?.disk_total || 0;
  const diskUsed = stats?.disk_used || 0;
  const diskPct = diskTotal > 0 ? (diskUsed / diskTotal) * 100 : 0;
  const swapTotal = stats?.swap_total || 0;
  const swapUsed = stats?.swap_used || 0;
  const hasSwap = swapTotal > 0;
  const swapPct = hasSwap ? (swapUsed / swapTotal) * 100 : 0;
  const cpuPct = stats?.cpu_percent || 0;
  const cpuCores = stats?.cpu_cores || 0;

  if (isPending || !stats) {
    return (
      <div className="overview-page">
        <OverviewSkeleton />
      </div>
    );
  }

  return (
    <div className="overview-page">
      <div className="ovp">
        <div className="ovp-live">
          <span className="ovp-live-dot" />
          {`live · ${clock}`}
        </div>

        <div className="ovp-vitals">
          <GaugeCard
            bandKey="cpu"
            label="CPU"
            pct={cpuPct}
            detail={`${cpuCores || '?'} core${cpuCores === 1 ? '' : 's'}`}
          />
          <GaugeCard
            bandKey="ram"
            label="RAM"
            pct={ramPct}
            detail={`${formatBytes(ramUsed)} / ${formatBytes(ramTotal)}`}
          />
          <GaugeCard
            bandKey="swap"
            label="Swap"
            pct={swapPct}
            detail={hasSwap ? `${formatBytes(swapUsed)} / ${formatBytes(swapTotal)}` : 'No swap'}
          />
          <GaugeCard
            bandKey="disk"
            label="Disk"
            pct={diskPct}
            detail={`${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`}
          />
        </div>

        <div className="ovp-grid2">
          <ClientsCard online={stats.client_online ?? 0} total={stats.client_total ?? 0} />
          <TrafficCard sent={stats.vpn_total_sent || 0} received={stats.vpn_total_recv || 0} />
          <SpeedCard
            up={history.series.netUp}
            down={history.series.netDown}
            upSpeed={stats.net_up_speed || 0}
            downSpeed={stats.net_down_speed || 0}
          />
          <SocketsCard tcp={stats.tcp_count || 0} udp={stats.udp_count || 0} />
        </div>

        <div className="ovp-grid2">
          <ServicePanelCard service="openvpn" title="OpenVPN" />
          <ServicePanelCard service="wireguard" title="WireGuard" />
          <SysInfoCard stats={stats} />
          <IpCard stats={stats} />
        </div>
      </div>
    </div>
  );
}

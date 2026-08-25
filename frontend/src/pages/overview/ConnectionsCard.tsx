import { useMemo } from 'react';
import { Card, theme } from 'antd';

import Sparkline from '@/components/viz/Sparkline';
import type { SystemStats } from '@/models/types';

interface ConnectionsCardProps {
  stats: SystemStats;
  tcp: number[];
  udp: number[];
  labels: string[];
  isMobile: boolean;
}

// TCP/UDP socket counts — a structural port of 3x-ui's
// pages/index/ConnectionsCard.tsx, wired to our tcp_count/udp_count stats.
export default function ConnectionsCard({ stats, tcp, udp, labels, isMobile }: ConnectionsCardProps) {
  const { token } = theme.useToken();
  const accent = token.colorPrimary;
  const udpColor = token.colorTextTertiary;
  const tcpCount = stats.tcp_count || 0;
  const udpCount = stats.udp_count || 0;

  const referenceLines = useMemo(
    () => [
      { y: udpCount, color: udpColor, dash: '2 4' },
      { y: tcpCount, color: accent, dash: '2 4' },
    ],
    [tcpCount, udpCount, accent, udpColor],
  );

  return (
    <Card hoverable styles={{ body: { padding: 0 } }}>
      <div className="ov-wide-head ov-wide-head-stack">
        <div className="ov-kicker">Connection Stats</div>
        <div className="ov-conn-total">
          <span className="ov-tile-number">{tcpCount + udpCount}</span>
          <span className="ov-tile-unit">open sockets</span>
        </div>
      </div>

      <div className="ov-conn-legend">
        <div className="ov-legend-label">
          <span className="ov-swatch" style={{ background: accent }} />
          TCP
          <span className="ov-legend-num">{tcpCount.toLocaleString()}</span>
        </div>
        <div className="ov-legend-label">
          <span className="ov-swatch" style={{ background: udpColor }} />
          UDP
          <span className="ov-legend-num">{udpCount.toLocaleString()}</span>
        </div>
      </div>

      <div className="ov-wide-chart">
        <Sparkline
          data={tcp}
          data2={udp}
          labels={labels}
          height={isMobile ? 120 : 170}
          strokeWidth={1.5}
          fillOpacity={0.24}
          showTooltip
          showLegend={false}
          valueMax={null}
          stroke={accent}
          stroke2={udpColor}
          name1="TCP"
          name2="UDP"
          yFormatter={(v) => Math.round(v).toLocaleString()}
          referenceLines={referenceLines}
        />
      </div>
    </Card>
  );
}

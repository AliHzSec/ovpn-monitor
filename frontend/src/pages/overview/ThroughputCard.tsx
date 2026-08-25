import { useMemo } from 'react';
import { Card, theme } from 'antd';
import { ArrowDownOutlined, ArrowUpOutlined } from '@ant-design/icons';

import Sparkline from '@/components/viz/Sparkline';
import { formatBytes, formatSpeed } from '@/utils/format';
import type { SystemStats } from '@/models/types';
import { mean, peak } from './useOverviewHistory';

interface ThroughputCardProps {
  stats: SystemStats;
  up: number[];
  down: number[];
  labels: string[];
  isMobile: boolean;
}

// Live throughput — a structural port of 3x-ui's pages/index/ThroughputCard.tsx.
// The footer shows our VPN traffic totals (DB sums) where 3x-ui shows its
// interface counters; the chart/legend treatment is identical.
export default function ThroughputCard({ stats, up, down, labels, isMobile }: ThroughputCardProps) {
  const { token } = theme.useToken();
  const accent = token.colorPrimary;
  const downColor = token.colorTextTertiary;

  const referenceLines = useMemo(
    () => [
      { y: stats.net_down_speed || 0, color: downColor, dash: '2 4' },
      { y: stats.net_up_speed || 0, color: accent, dash: '2 4' },
    ],
    [stats.net_up_speed, stats.net_down_speed, accent, downColor],
  );

  const vpnSent = stats.vpn_total_sent || 0;
  const vpnRecv = stats.vpn_total_recv || 0;

  return (
    <Card hoverable styles={{ body: { padding: 0 } }}>
      <div className="ov-wide-head">
        <div>
          <div className="ov-kicker">Live Speed</div>
          <div className="ov-sub">{`All interfaces · Peak ${formatSpeed(peak(down))}`}</div>
        </div>
        <div className="ov-wide-legend">
          <div className="ov-legend-label">
            <ArrowUpOutlined style={{ color: accent }} />
            Upload
            <span className="ov-legend-num">{formatSpeed(stats.net_up_speed || 0)}</span>
          </div>
          <div className="ov-legend-label">
            <ArrowDownOutlined style={{ color: downColor }} />
            Download
            <span className="ov-legend-num">{formatSpeed(stats.net_down_speed || 0)}</span>
          </div>
        </div>
      </div>

      <div className="ov-wide-chart">
        <Sparkline
          data={up}
          data2={down}
          labels={labels}
          height={isMobile ? 140 : 186}
          strokeWidth={1.75}
          fillOpacity={0.24}
          showTooltip
          showLegend={false}
          valueMax={null}
          stroke={accent}
          stroke2={downColor}
          name1="Upload"
          name2="Download"
          yFormatter={formatSpeed}
          referenceLines={referenceLines}
        />
      </div>

      <div className="ov-wide-foot">
        <div>
          <div className="ov-kicker">VPN Sent</div>
          <div className="ov-foot-value">{formatBytes(vpnSent)}</div>
        </div>
        <span className="ov-foot-sep" />
        <div>
          <div className="ov-kicker">VPN Received</div>
          <div className="ov-foot-value">{formatBytes(vpnRecv)}</div>
        </div>
        <span className="ov-foot-sep" />
        <div>
          <div className="ov-kicker">Avg Window</div>
          <div className="ov-foot-value">
            <span className="ov-foot-part">{`↑ ${formatSpeed(mean(up))}`}</span>{' '}
            <span className="ov-foot-part">{`↓ ${formatSpeed(mean(down))}`}</span>
          </div>
        </div>
      </div>
    </Card>
  );
}

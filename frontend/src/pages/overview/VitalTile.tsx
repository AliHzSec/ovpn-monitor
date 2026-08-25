import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { Card, theme } from 'antd';

import Sparkline from '@/components/viz/Sparkline';
import { mean, peak } from './useOverviewHistory';

// Usage escalation, mirroring 3x-ui's models/status.ts thresholds and colors
// (warn at 80% #faad14, critical at 90% #ff4d4f; below warn the accent is the
// theme primary, which is 3x-ui's #1677ff under the default algorithm).
export const USAGE_WARN_PERCENT = 80;
export const USAGE_CRIT_PERCENT = 90;

export function usageColor(percent: number, primary: string, warn: string, crit: string): string {
  if (percent < USAGE_WARN_PERCENT) return primary;
  if (percent < USAGE_CRIT_PERCENT) return warn;
  return crit;
}

interface VitalTileProps {
  icon: ReactNode;
  label: string;
  percent: number;
  detail: string;
  footLeft: string;
  footRight: string;
  data: number[];
  isMobile: boolean;
}

// Resource monitor tile — a structural port of 3x-ui's pages/index/VitalTile.tsx:
// kicker head with accent icon, large percent value, detail line, avg/peak
// footer and a spline history chart with a dashed mean reference line.
export default function VitalTile({
  icon,
  label,
  percent,
  detail,
  footLeft,
  footRight,
  data,
  isMobile,
}: VitalTileProps) {
  const { token } = theme.useToken();
  const meanColor = token.colorTextTertiary;
  const statusColor = usageColor(percent, token.colorPrimary, token.colorWarning, token.colorError);

  const referenceLines = useMemo(
    () => (data.length > 1 ? [{ y: mean(data), dash: '3 4', color: meanColor }] : []),
    [data, meanColor],
  );

  return (
    <Card hoverable className="ov-tile" styles={{ body: { padding: 0 } }}>
      <div className="ov-tile-head">
        <span className="ov-tile-icon">{icon}</span>
        <span className="ov-kicker">{label}</span>
      </div>

      <div className="ov-tile-value">
        <span className="ov-tile-number">{percent.toFixed(1)}</span>
        <span className="ov-tile-unit">%</span>
      </div>

      <div className="ov-tile-detail">{detail}</div>

      <div className="ov-tile-foot">
        <span>{footLeft}</span>
        <span>{footRight}</span>
      </div>

      <div className="ov-tile-chart">
        <Sparkline
          data={data}
          height={isMobile ? 48 : 62}
          strokeWidth={1.5}
          fillOpacity={0.3}
          showGrid={false}
          showMarker={false}
          valueMax={peak(data) > 0 ? null : 100}
          stroke={statusColor}
          referenceLines={referenceLines}
          yFormatter={(v) => `${v.toFixed(0)}%`}
          name1={label}
        />
      </div>
    </Card>
  );
}

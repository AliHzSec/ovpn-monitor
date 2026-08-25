import { useEffect, useMemo, useState } from 'react';

import type { SystemStats } from '@/models/types';

// Same window size as 3x-ui's useOverviewHistory (72 samples). Unlike 3x-ui we
// have no backend history endpoint, so the window is seeded empty and fills
// purely from live updates (~one sample per WS push / poll tick).
const OVERVIEW_WINDOW = 72;

const SERIES_KEYS = ['cpu', 'mem', 'swap', 'disk', 'netUp', 'netDown', 'tcp', 'udp'] as const;

export type OverviewSeriesKey = (typeof SERIES_KEYS)[number];

export interface OverviewHistory {
  series: Record<OverviewSeriesKey, number[]>;
  labels: string[];
}

interface HistoryWindow {
  series: Record<OverviewSeriesKey, number[]>;
  times: number[];
}

function emptySeries(): Record<OverviewSeriesKey, number[]> {
  return Object.fromEntries(SERIES_KEYS.map((key) => [key, [] as number[]])) as Record<
    OverviewSeriesKey,
    number[]
  >;
}

function sampleOf(stats: SystemStats): Record<OverviewSeriesKey, number> {
  const memTotal = stats.mem_total || 0;
  const swapTotal = stats.swap_total || 0;
  const diskTotal = stats.disk_total || 0;
  return {
    cpu: stats.cpu_percent || 0,
    mem: memTotal > 0 ? ((stats.mem_used || 0) / memTotal) * 100 : 0,
    swap: swapTotal > 0 ? ((stats.swap_used || 0) / swapTotal) * 100 : 0,
    disk: diskTotal > 0 ? ((stats.disk_used || 0) / diskTotal) * 100 : 0,
    netUp: stats.net_up_speed || 0,
    netDown: stats.net_down_speed || 0,
    tcp: stats.tcp_count || 0,
    udp: stats.udp_count || 0,
  };
}

function tail<T>(values: T[]): T[] {
  return values.slice(-OVERVIEW_WINDOW);
}

export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  let total = 0;
  for (const v of values) total += v;
  return total / values.length;
}

export function peak(values: number[]): number {
  let max = 0;
  for (const v of values) if (v > max) max = v;
  return max;
}

function formatClock(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Rolling client-side history for every metric the overview charts. One point
// is appended per serverStats update — keyed on dataUpdatedAt so each WS push
// / poll refetch is exactly one sample.
export function useOverviewHistory(
  stats: SystemStats | undefined,
  dataUpdatedAt: number,
): OverviewHistory {
  const [trend, setTrend] = useState<HistoryWindow>({ series: emptySeries(), times: [] });

  useEffect(() => {
    if (!stats || dataUpdatedAt === 0) return;
    setTrend((prev) => {
      const point = sampleOf(stats);
      const next: HistoryWindow = { series: emptySeries(), times: [] };
      next.times = tail(prev.times.concat(Math.floor(Date.now() / 1000)));
      for (const key of SERIES_KEYS) {
        next.series[key] = tail(prev.series[key].concat(point[key]));
      }
      return next;
    });
    // stats is re-fetched together with dataUpdatedAt; keying on the timestamp
    // alone keeps this to one sample per push.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataUpdatedAt]);

  const labels = useMemo(() => trend.times.map(formatClock), [trend.times]);

  return useMemo(() => ({ series: trend.series, labels }), [trend.series, labels]);
}

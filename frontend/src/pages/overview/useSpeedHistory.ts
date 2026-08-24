import { useEffect, useState } from 'react';

import type { SystemStats } from '@/models/types';

const HISTORY_POINTS = 60;

export interface SpeedHistory {
  up: number[];
  down: number[];
}

// Rolling client-side history of the two live-speed metrics the dashboard
// already shows (net_up_speed / net_down_speed). One point is appended per
// serverStats update — the WebSocket bridge pushes ~every 2s, the polling
// fallback every 3s — and the buffer is capped at the last HISTORY_POINTS
// samples. Keyed on dataUpdatedAt so each WS push / refetch is one sample.
export function useSpeedHistory(
  stats: SystemStats | undefined,
  dataUpdatedAt: number,
): SpeedHistory {
  const [history, setHistory] = useState<SpeedHistory>({ up: [], down: [] });

  useEffect(() => {
    if (!stats || dataUpdatedAt === 0) return;
    setHistory((prev) => ({
      up: [...prev.up, stats.net_up_speed || 0].slice(-HISTORY_POINTS),
      down: [...prev.down, stats.net_down_speed || 0].slice(-HISTORY_POINTS),
    }));
  }, [stats, dataUpdatedAt]);

  return history;
}

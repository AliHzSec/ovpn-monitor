import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import { useWsFallback } from '@/api/websocketBridge';
import type { SystemStats } from '@/models/types';

export function useServerStats() {
  const fallback = useWsFallback();
  return useQuery({
    queryKey: keys.serverStats(),
    queryFn: () => get<SystemStats>('/api/server-stats'),
    // The WebSocket pushes fresh stats when connected; only poll as fallback.
    refetchInterval: fallback ? 3000 : false,
  });
}

// api/websocketBridge.ts — wires the /ws stats socket into React Query.
//
// While the socket is open every push becomes the ['serverStats'] cache entry
// and HTTP polling stays off. When the socket drops we flip a module-level
// fallback flag that useServerStats reads (via useSyncExternalStore) to enable
// a 3s refetchInterval until the socket reconnects.

import { useEffect, useSyncExternalStore } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { getSharedStatsSocket } from '@/api/websocket';
import { keys } from '@/api/queryKeys';

let wsFallback = true; // poll until the first successful connection
const listeners = new Set<() => void>();

function setWsFallback(value: boolean): void {
  if (wsFallback === value) return;
  wsFallback = value;
  for (const cb of listeners) cb();
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function getSnapshot(): boolean {
  return wsFallback;
}

/** True while the stats socket is down and polling must carry the updates. */
export function useWsFallback(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => true);
}

export function useWebSocketBridge(): void {
  const queryClient = useQueryClient();

  useEffect(() => {
    const socket = getSharedStatsSocket();
    socket.connect({
      onopen: () => setWsFallback(false),
      onmessage: (stats) => {
        queryClient.setQueryData(keys.serverStats(), stats);
      },
      onclose: () => setWsFallback(true),
    });
    return () => {
      socket.disconnect();
      setWsFallback(true);
    };
  }, [queryClient]);
}

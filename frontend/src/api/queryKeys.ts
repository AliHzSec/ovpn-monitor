// api/queryKeys.ts — single source of truth for React Query cache keys.
export const keys = {
  serverStats: () => ['serverStats'] as const,
  clients: (filter: string) => ['clients', filter] as const,
  client: (name: string) => ['client', name] as const,
  clientStats: (filter: string) => ['clientStats', filter] as const,
  settings: (section: string) => ['settings', section] as const,
  ipv6: (service: string) => ['ipv6', service] as const,
};

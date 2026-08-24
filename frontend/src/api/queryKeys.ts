// api/queryKeys.ts — single source of truth for React Query cache keys.
export const keys = {
  serverStats: () => ['serverStats'] as const,
  clients: (filter: string) => ['clients', filter] as const,
  client: (name: string) => ['client', name] as const,
  clientDomains: (name: string) => ['clientDomains', name] as const,
  clientDomainDetail: (name: string, root: string) =>
    ['clientDomainDetail', name, root] as const,
  clientStats: (filter: string) => ['clientStats', filter] as const,
  settings: (section: string) => ['settings', section] as const,
};

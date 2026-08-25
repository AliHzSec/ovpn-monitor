import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import type { IPv6StateResult } from '@/models/types';

// GET /api/settings/{service}/ipv6 returns the live IPv6 state parsed from the
// service's config file (never a cached DB value). Service is "wireguard" or
// "openvpn", matching the settings section keys.
export function useIPv6(service: string) {
  return useQuery({
    queryKey: keys.ipv6(service),
    queryFn: () => get<IPv6StateResult>(`/api/settings/${encodeURIComponent(service)}/ipv6`),
    enabled: service !== '',
  });
}

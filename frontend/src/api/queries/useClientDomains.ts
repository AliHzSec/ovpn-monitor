import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import type { VisitedDomain } from '@/models/types';

export function useClientDomains(name: string) {
  return useQuery({
    queryKey: keys.clientDomains(name),
    queryFn: () => get<VisitedDomain[]>(`/api/clients/${encodeURIComponent(name)}/domains`),
    enabled: name !== '',
  });
}

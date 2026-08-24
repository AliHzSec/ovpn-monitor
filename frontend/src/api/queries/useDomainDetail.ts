import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import type { VisitedDomain } from '@/models/types';

export function useDomainDetail(name: string, root: string) {
  return useQuery({
    queryKey: keys.clientDomainDetail(name, root),
    queryFn: () =>
      get<VisitedDomain[]>(
        `/api/clients/${encodeURIComponent(name)}/domains/${encodeURIComponent(root)}`,
      ),
    enabled: name !== '' && root !== '',
  });
}

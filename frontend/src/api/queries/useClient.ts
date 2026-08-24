import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import type { Client } from '@/models/types';

export function useClient(name: string) {
  return useQuery({
    queryKey: keys.client(name),
    queryFn: () => get<Client>(`/api/clients/${encodeURIComponent(name)}`),
    enabled: name !== '',
  });
}

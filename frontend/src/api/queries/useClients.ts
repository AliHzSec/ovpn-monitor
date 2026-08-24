import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import type { Client } from '@/models/types';

export function useClients(filter: string) {
  return useQuery({
    queryKey: keys.clients(filter),
    queryFn: () => get<Client[]>('/api/clients', { params: { filter } }),
  });
}

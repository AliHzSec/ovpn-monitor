import { useQuery } from '@tanstack/react-query';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';

// GET /api/settings/{section} returns a map of settings keys to their current
// values. The endpoint is added to the Go backend in a later step; the hook
// is written against that documented contract.
export function useSettings(section: string) {
  return useQuery({
    queryKey: keys.settings(section),
    queryFn: () => get<Record<string, string>>(`/api/settings/${encodeURIComponent(section)}`),
    enabled: section !== '',
  });
}

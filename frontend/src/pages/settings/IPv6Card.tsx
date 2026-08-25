import { Card, Modal, Switch, message } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { HttpError, put } from '@/api/http';
import { useIPv6 } from '@/api/queries/useIPv6';
import { keys } from '@/api/queryKeys';
import type { IPv6SetResult } from '@/models/types';

interface IPv6CardProps {
  service: 'wireguard' | 'openvpn';
  title: string;
}

// Pulls the backend's {"error": "..."} message out of a failed request so the
// toast can show what actually happened (e.g. a rollback after a failed
// restart) instead of a generic failure.
function errorMessage(error: unknown): string {
  if (error instanceof HttpError) {
    const data = error.response.data;
    if (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string') {
      return data.error;
    }
  }
  return 'Failed to update the IPv6 setting.';
}

// IPv6 settings box shown in the WireGuard and OpenVPN settings sections. The
// switch mirrors the state parsed live from the server config file; flipping
// it asks for confirmation (the restart drops every connected client for a
// few seconds), then the real state is re-fetched from the server rather than
// trusted optimistically.
export default function IPv6Card({ service, title }: IPv6CardProps) {
  const queryClient = useQueryClient();
  const ipv6Query = useIPv6(service);
  const state = ipv6Query.data?.state ?? 'unknown';

  const setMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      put<IPv6SetResult>(`/api/settings/${service}/ipv6`, { enabled }),
    onSuccess: (res) => {
      message.success(`IPv6 ${res.state === 'enabled' ? 'enabled' : 'disabled'} — ${title} restarted.`);
      queryClient.invalidateQueries({ queryKey: keys.ipv6(service) });
    },
    onError: (error) => {
      message.error(errorMessage(error));
      // Revert the switch to the real state on disk.
      queryClient.invalidateQueries({ queryKey: keys.ipv6(service) });
    },
  });

  const confirmToggle = (enabled: boolean) => {
    Modal.confirm({
      title: `${enabled ? 'Enable' : 'Disable'} IPv6?`,
      content: 'Restart required. All connected clients will be disconnected for a few seconds.',
      okText: enabled ? 'Enable' : 'Disable',
      cancelText: 'Cancel',
      onOk: () => setMutation.mutateAsync(enabled).catch(() => {}),
    });
  };

  const unknown = state === 'unknown';
  const busy = ipv6Query.isLoading || setMutation.isPending;

  return (
    <Card className="settings-card ipv6-card">
      <div className="settings-field-row">
        <div className="settings-field-label-wrap">
          <label className="settings-field-label">IPv6</label>
          <div className="settings-field-desc">
            Disable IPv6 to force all client traffic over IPv4 only.
          </div>
          {service === 'wireguard' ? (
            <div className="settings-field-desc">
              The client's tunnel adapter still shows its assigned IPv6 address — it is
              written into the client config. Disabling only removes IPv6 internet
              reachability.
            </div>
          ) : null}
          {unknown && !ipv6Query.isLoading ? (
            <div className="settings-field-note">
              {ipv6Query.isError
                ? 'Could not read the server config.'
                : 'The config file needs manual attention — its IPv6 markers are missing or inconsistent.'}
            </div>
          ) : null}
        </div>
        <div className="settings-field-input-wrap ipv6-switch-wrap">
          <Switch
            checked={state === 'enabled'}
            disabled={unknown || ipv6Query.isError}
            loading={busy}
            onChange={confirmToggle}
          />
        </div>
      </div>
    </Card>
  );
}

import { useEffect } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { Avatar, Badge, Breadcrumb, Button, Skeleton } from 'antd';
import { ArrowLeftOutlined } from '@ant-design/icons';

import { useClient } from '@/api/queries/useClient';
import { keys } from '@/api/queryKeys';
import PageShell from '@/components/ui/PageShell';
import { formatBytes, relativeTime } from '@/utils/format';

import './ClientDetailPage.css';

// Same cadence as the legacy page: client refreshes every 5s.
const CLIENT_POLL_MS = 5_000;

// readable fields come pre-formatted from the API; fall back to the raw byte
// counter exactly like the legacy fmtBytes() fallback.
function readableOr(readable: string | undefined, raw: number | undefined): string {
  return readable || formatBytes(raw ?? 0);
}

export function ClientDetailPage() {
  const { name = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const clientQuery = useClient(name);
  const client = clientQuery.data;

  useEffect(() => {
    document.title = name ? `${name} — Client Detail` : 'Client Detail';
  }, [name]);

  // Polling via invalidation keeps the shared query hooks untouched; cached
  // data stays rendered while a refetch is in flight, so there is no skeleton
  // flash after the first load.
  useEffect(() => {
    if (!name) return undefined;
    const clientTimer = window.setInterval(() => {
      void queryClient.invalidateQueries({ queryKey: keys.client(name) });
    }, CLIENT_POLL_MS);
    return () => window.clearInterval(clientTimer);
  }, [name, queryClient]);

  const online = !!client?.online;
  const timeLabel = online ? 'Connected Since' : 'Last Seen';
  const timeValue = client
    ? (online ? client.connected_since : client.last_seen || client.connected_since) || 'Never'
    : '—';
  const timeEpoch = client
    ? online
      ? client.connected_since_epoch || client.last_seen_epoch || 0
      : client.last_seen_epoch || client.connected_since_epoch || 0
    : 0;

  return (
    <PageShell
      title={name || 'Client Detail'}
      className="client-detail-page"
      actions={
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/panel/clients')}>
          Back to Clients
        </Button>
      }
    >
      <Breadcrumb
        className="client-breadcrumb"
        items={[{ title: <Link to="/panel/clients">Clients</Link> }, { title: name || '…' }]}
      />

      {/* Client header */}
      <section className="dc-card client-head-card">
        {clientQuery.isPending ? (
          <Skeleton active avatar paragraph={{ rows: 1 }} />
        ) : (
          <div className="client-head">
            <Avatar shape="circle" size={50} className="client-avatar">
              {(name.charAt(0) || '?').toUpperCase()}
            </Avatar>
            <div className="client-head-main">
              <div className="client-name">{client?.common_name || name}</div>
              <div className="badge-row">
                <Badge
                  status={online ? 'success' : 'default'}
                  text={client ? (online ? 'Online' : 'Offline') : '—'}
                />
                {/* Connection-type badges: how the client is connected right now
                    (can be both at once). Hidden while offline. */}
                {online && client?.online_openvpn ? (
                  <span className="dc-tag dc-tag-ovpn">OVPN</span>
                ) : null}
                {online && client?.online_wireguard ? (
                  <span className="dc-tag dc-tag-wg">WG</span>
                ) : null}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Connection details */}
      <div className="info-grid">
        <section className="dc-card info-card">
          <div className="dc-card-head">Addresses</div>
          <div className="info-card-body">
            {clientQuery.isPending ? (
              <Skeleton active title={false} paragraph={{ rows: 2 }} />
            ) : (
              <div className="kv">
                <div className="kv-row">
                  <span className="kv-label">Public IP</span>
                  <span className={`kv-value${online && client?.real_address ? '' : ' muted'}`}>
                    {online ? client?.real_address || '—' : '—'}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">VPN Address</span>
                  <span className={`kv-value${client?.vpn_address ? '' : ' muted'}`}>
                    {client?.vpn_address || '—'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="dc-card info-card">
          <div className="dc-card-head">Traffic</div>
          <div className="info-card-body">
            {clientQuery.isPending ? (
              <Skeleton active title={false} paragraph={{ rows: 5 }} />
            ) : (
              <div className="kv">
                <div className="kv-row">
                  <span className="kv-label">Total</span>
                  <span className="kv-value">
                    {client ? readableOr(client.total_traffic_readable, client.total_traffic) : '—'}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">Download</span>
                  <span className="kv-value recv">
                    {client ? readableOr(client.bytes_received_readable, client.bytes_received) : '—'}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">Upload</span>
                  <span className="kv-value sent">
                    {client ? readableOr(client.bytes_sent_readable, client.bytes_sent) : '—'}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">Via OpenVPN</span>
                  <span className="kv-value muted">
                    {client ? readableOr(client.traffic_openvpn_readable, client.traffic_openvpn) : '—'}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">Via WireGuard</span>
                  <span className="kv-value muted">
                    {client
                      ? readableOr(client.traffic_wireguard_readable, client.traffic_wireguard)
                      : '—'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="dc-card info-card">
          <div className="dc-card-head">Session</div>
          <div className="info-card-body">
            {clientQuery.isPending ? (
              <Skeleton active title={false} paragraph={{ rows: 2 }} />
            ) : (
              <div className="kv">
                <div className="kv-row">
                  <span className="kv-label">{timeLabel}</span>
                  <span className="kv-value">{timeValue}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">Relative</span>
                  <span className="kv-value muted">{client ? relativeTime(timeEpoch) : '—'}</span>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </PageShell>
  );
}

export default ClientDetailPage;

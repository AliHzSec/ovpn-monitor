import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import {
  Avatar,
  Badge,
  Breadcrumb,
  Button,
  Card,
  Empty,
  Input,
  Skeleton,
  Table,
  Tag,
  Tooltip,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ArrowLeftOutlined, GlobalOutlined, RightOutlined, SearchOutlined } from '@ant-design/icons';

import { useClient } from '@/api/queries/useClient';
import { useClientDomains } from '@/api/queries/useClientDomains';
import { keys } from '@/api/queryKeys';
import PageShell from '@/components/ui/PageShell';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import type { VisitedDomain } from '@/models/types';
import { formatBytes, relativeTime } from '@/utils/format';

import './ClientDetailPage.css';

const PAGE_SIZE = 25;
// Same cadence as the legacy page: client 5s, visited domains 15s.
const CLIENT_POLL_MS = 5_000;
const DOMAINS_POLL_MS = 15_000;

// readable fields come pre-formatted from the API; fall back to the raw byte
// counter exactly like the legacy fmtBytes() fallback.
function readableOr(readable: string | undefined, raw: number | undefined): string {
  return readable || formatBytes(raw ?? 0);
}

function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export function ClientDetailPage() {
  const { name = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { isMobile } = useMediaQuery();

  const clientQuery = useClient(name);
  const domainsQuery = useClientDomains(name);
  const client = clientQuery.data;

  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

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
    const domainsTimer = window.setInterval(() => {
      void queryClient.invalidateQueries({ queryKey: keys.clientDomains(name) });
    }, DOMAINS_POLL_MS);
    return () => {
      window.clearInterval(clientTimer);
      window.clearInterval(domainsTimer);
    };
  }, [name, queryClient]);

  // Kept so the domain search can also match on the client's own IPs.
  const clientIPs = useMemo(() => {
    const ips: string[] = [];
    if (client?.real_address) ips.push(String(client.real_address).split(':')[0].toLowerCase());
    if (client?.vpn_address) ips.push(String(client.vpn_address).toLowerCase());
    return ips;
  }, [client]);

  const filteredDomains = useMemo(() => {
    let data = domainsQuery.data ?? [];
    const q = search.trim().toLowerCase();
    if (q) {
      // Domain substring match, OR — if the query matches one of the client's
      // own IPs — keep the whole (already per-client) list.
      const ipMatch = clientIPs.some((ip) => ip.includes(q));
      if (!ipMatch) {
        // Rows are collapsed to root domains; `hostnames` is the space-joined
        // list of every hostname folded into the row, so subdomains stay
        // findable.
        data = data.filter(
          (d) =>
            d.domain.toLowerCase().includes(q) || (d.hostnames ?? '').toLowerCase().includes(q),
        );
      }
    }
    return data;
  }, [domainsQuery.data, search, clientIPs]);

  const columns = useMemo<ColumnsType<VisitedDomain>>(
    () => [
      {
        title: 'Domain',
        dataIndex: 'domain',
        key: 'domain',
        sorter: (a, b) => compareStrings(a.domain.toLowerCase(), b.domain.toLowerCase()),
        sortDirections: ['ascend', 'descend'],
        render: (_, d) => (
          <>
            <span className="domain-text">{d.domain}</span>
            {(d.subdomain_count ?? 0) > 1 ? (
              <span className="sub-count">{d.subdomain_count} subdomains</span>
            ) : null}
          </>
        ),
      },
      {
        title: 'First Seen',
        dataIndex: 'first_seen_epoch',
        key: 'first',
        sorter: (a, b) => (a.first_seen_epoch || 0) - (b.first_seen_epoch || 0),
        sortDirections: ['descend', 'ascend'],
        render: (_, d) => (
          <Tooltip title={d.first_seen || undefined}>
            <span className="time-cell">{relativeTime(d.first_seen_epoch)}</span>
          </Tooltip>
        ),
      },
      {
        title: 'Last Seen',
        dataIndex: 'last_seen_epoch',
        key: 'last',
        // Legacy default sort: last seen, descending.
        defaultSortOrder: 'descend',
        sorter: (a, b) => (a.last_seen_epoch || 0) - (b.last_seen_epoch || 0),
        sortDirections: ['descend', 'ascend'],
        render: (_, d) => (
          <Tooltip title={d.last_seen || undefined}>
            <span className="time-cell">{relativeTime(d.last_seen_epoch)}</span>
          </Tooltip>
        ),
      },
      {
        title: 'Visits',
        dataIndex: 'visit_count',
        key: 'count',
        align: 'right',
        sorter: (a, b) => (a.visit_count || 0) - (b.visit_count || 0),
        sortDirections: ['descend', 'ascend'],
        render: (_, d) => <span className="count-pill">{d.visit_count || 0}</span>,
      },
      {
        key: 'expand',
        width: 44,
        align: 'right',
        render: () => <RightOutlined className="row-chevron" />,
      },
    ],
    [],
  );

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

  const domainsEmpty = domainsQuery.isError ? (
    <Empty
      description={
        <>
          <span className="empty-title">Could not load domains</span>
          <span className="empty-text">Please try again.</span>
        </>
      }
    />
  ) : (
    <Empty
      description={
        <>
          <span className="empty-title">No domains recorded</span>
          <span className="empty-text">
            {search
              ? 'No domains match your search.'
              : 'This client has no visited-domain history yet.'}
          </span>
        </>
      }
    />
  );

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
      <Card className="client-head-card" variant="borderless">
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
                {online && client?.online_openvpn ? <Tag color="blue">OVPN</Tag> : null}
                {online && client?.online_wireguard ? <Tag color="#722ed1">WG</Tag> : null}
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Connection details */}
      <div className="info-grid">
        <Card className="info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            Addresses
          </div>
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
        </Card>

        <Card className="info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot" />
            Traffic
          </div>
          {clientQuery.isPending ? (
            <Skeleton active title={false} paragraph={{ rows: 5 }} />
          ) : (
            <div className="kv">
              <div className="kv-row">
                <span className="kv-label">Total</span>
                <span className="kv-value total">
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
        </Card>

        <Card className="info-card" variant="borderless">
          <div className="info-card-title">
            <span className="info-card-title-dot info-card-title-dot-success" />
            Session
          </div>
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
        </Card>
      </div>

      {/* Visited domains */}
      <Card className="domains-card" variant="borderless">
        <div className="domains-head">
          <div className="domains-title">
            <GlobalOutlined />
            Visited Domains
          </div>
          <Input
            className="domain-search"
            prefix={<SearchOutlined />}
            placeholder="Search domain or IP..."
            allowClear
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            style={isMobile ? { width: '100%' } : { width: 250 }}
          />
        </div>

        {domainsQuery.isPending ? (
          <Skeleton active title={false} paragraph={{ rows: 5 }} />
        ) : (
          <Table<VisitedDomain>
            rowKey={(d) => d.domain}
            columns={columns}
            dataSource={filteredDomains}
            scroll={{ x: true }}
            locale={{ emptyText: domainsEmpty }}
            onRow={(d) => ({
              className: 'domain-row',
              onClick: () =>
                navigate(
                  `/panel/clients/${encodeURIComponent(name)}/domains/${encodeURIComponent(d.domain)}`,
                ),
            })}
            pagination={{
              current: page,
              pageSize: PAGE_SIZE,
              showSizeChanger: false,
              hideOnSinglePage: false,
              onChange: (p) => setPage(p),
            }}
          />
        )}

        <div className="domains-footer">
          <span>
            {domainsQuery.isPending
              ? 'Loading…'
              : domainsQuery.isError && !domainsQuery.data
                ? ''
                : `${filteredDomains.length} domain${filteredDomains.length === 1 ? '' : 's'}${
                    search.trim() ? ' (filtered)' : ''
                  }`}
          </span>
        </div>
      </Card>
    </PageShell>
  );
}

export default ClientDetailPage;

// pages/clients/ClientsPage.tsx — React port of the legacy #page-clients
// section of templates/dashboard.html, restyled with antd.
//
// Behavioral note (approved fix vs. the legacy page): the legacy "Online" tab
// fetched ?filter=today and filtered client-side, so its traffic numbers were
// today's only. Here the Online tab fetches ?filter=all and filters on
// `online === true` — the server-computed live signal (OpenVPN status-log
// watcher + WireGuard handshakes) — so the traffic column shows all-time
// totals consistently across tabs.

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Badge, Empty, Input, Segmented, Skeleton, Table, Tooltip } from 'antd';
import type { TableProps } from 'antd';
import { RightOutlined, SearchOutlined } from '@ant-design/icons';

import { get } from '@/api/http';
import { keys } from '@/api/queryKeys';
import PageShell from '@/components/ui/PageShell';
import StatCard from '@/components/ui/StatCard';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import type { Client } from '@/models/types';
import { formatBytes, relativeTime } from '@/utils/format';

import './ClientsPage.css';

type FilterKey = 'online' | 'today' | 'week' | 'month' | 'all';
type SortCol = 'name' | 'status' | 'total' | 'time';

const FILTER_OPTIONS: { label: string; value: FilterKey }[] = [
  { label: 'Online', value: 'online' },
  { label: 'Today', value: 'today' },
  { label: '7 Days', value: 'week' },
  { label: '30 Days', value: 'month' },
  { label: 'All Time', value: 'all' },
];

// The Online tab is a live-status view over the full dataset, not a traffic
// period; every other tab maps 1:1 onto the server-side traffic filter.
function apiFilterFor(filter: FilterKey): string {
  return filter === 'online' ? 'all' : filter;
}

// The timestamp "Last Connected" is based on: when an online client
// connected, or when an offline client was last seen.
function relevantEpoch(c: Client): number {
  return c.online
    ? c.connected_since_epoch || c.last_seen_epoch || 0
    : c.last_seen_epoch || c.connected_since_epoch || 0;
}

export function ClientsPage() {
  const navigate = useNavigate();
  const { isMobile } = useMediaQuery();

  const [filter, setFilter] = useState<FilterKey>('online');
  const [search, setSearch] = useState('');
  const [sortCol, setSortCol] = useState<SortCol>('total');
  const [sortDir, setSortDir] = useState<1 | -1>(-1);
  const [userHasSorted, setUserHasSorted] = useState(false);

  // Same key and queryFn contract as useClients(), plus the page-specific
  // polling: 5s auto-refresh, keeping previous data visible so a refetch (or
  // a filter switch) fades subtly instead of flashing a skeleton.
  const { data, isPending, isFetching } = useQuery({
    queryKey: keys.clients(apiFilterFor(filter)),
    queryFn: () => get<Client[]>('/api/clients', { params: { filter: apiFilterFor(filter) } }),
    refetchInterval: 5000,
    placeholderData: keepPreviousData,
  });

  const clients = useMemo(() => data ?? [], [data]);
  const loaded = data !== undefined;

  // Stat cards are computed over the fetched dataset (not the search view).
  const stats = useMemo(() => {
    const total = clients.length;
    const online = clients.filter((c) => c.online).length;
    const offline = total - online;
    const pctOn = total ? Math.round((online / total) * 100) : 0;
    const pctOff = total ? Math.round((offline / total) * 100) : 0;
    const recv = clients.reduce((s, c) => s + (c.bytes_received || 0), 0);
    const sent = clients.reduce((s, c) => s + (c.bytes_sent || 0), 0);
    return { total, online, offline, pctOn, pctOff, recv, sent, traffic: recv + sent };
  }, [clients]);

  // Table view: Online-tab status filter, then search, then sort.
  const visible = useMemo(() => {
    let rows = clients.slice();
    if (filter === 'online') rows = rows.filter((c) => c.online);
    const q = search.trim().toLowerCase();
    if (q) rows = rows.filter((c) => c.common_name.toLowerCase().includes(q));

    if (!userHasSorted) {
      // Pre-user-sort default: online clients first (legacy behavior), total
      // traffic descending as the tiebreak (the default sort column).
      rows.sort(
        (a, b) =>
          (b.online ? 1 : 0) - (a.online ? 1 : 0) || b.total_traffic - a.total_traffic,
      );
    } else {
      const keyOf: Record<SortCol, (c: Client) => number | string> = {
        name: (c) => c.common_name.toLowerCase(),
        status: (c) => (c.online ? 1 : 0),
        total: (c) => c.total_traffic,
        time: (c) => relevantEpoch(c),
      };
      const key = keyOf[sortCol];
      rows.sort((a, b) => {
        const av = key(a);
        const bv = key(b);
        if (av < bv) return sortDir;
        if (av > bv) return -sortDir;
        return 0;
      });
    }
    return rows;
  }, [clients, filter, search, userHasSorted, sortCol, sortDir]);

  const visibleTraffic = useMemo(
    () =>
      visible.reduce((s, c) => s + (c.bytes_received || 0) + (c.bytes_sent || 0), 0),
    [visible],
  );

  const footerCount =
    `${visible.length} client${visible.length !== 1 ? 's' : ''}` +
    (visible.length ? ` · ${formatBytes(visibleTraffic)} total` : '');

  function handleFilterChange(value: string | number) {
    setFilter(value as FilterKey);
    // Switching filter resets any user-chosen sort back to the default.
    setUserHasSorted(false);
    setSortCol('total');
    setSortDir(-1);
  }

  function handleSort(col: SortCol) {
    if (col === sortCol) {
      setSortDir((d) => (d === 1 ? -1 : 1));
    } else {
      setSortCol(col);
      setSortDir(-1);
    }
    setUserHasSorted(true);
  }

  function sortOrderFor(col: SortCol): 'ascend' | 'descend' | null {
    return userHasSorted && sortCol === col ? (sortDir === 1 ? 'ascend' : 'descend') : null;
  }

  const columns: TableProps<Client>['columns'] = [
    {
      title: 'Client',
      key: 'name',
      sorter: true,
      sortOrder: sortOrderFor('name'),
      render: (_, c) => (
        <span className="clients-cell-name">
          <span
            className={`clients-status-dot ${c.online ? 'is-online' : 'is-offline'}`}
          />
          <span className="clients-name-text">{c.common_name}</span>
        </span>
      ),
    },
    {
      title: 'Status',
      key: 'status',
      sorter: true,
      sortOrder: sortOrderFor('status'),
      render: (_, c) => (
        <span className="clients-status-cell">
          <Badge
            status={c.online ? 'success' : 'default'}
            text={c.online ? 'Online' : 'Offline'}
          />
          {c.online && c.online_openvpn ? <span className="dc-tag dc-tag-ovpn">OVPN</span> : null}
          {c.online && c.online_wireguard ? (
            <span className="dc-tag dc-tag-wg">WG</span>
          ) : null}
        </span>
      ),
    },
    {
      title: 'Total',
      key: 'total',
      sorter: true,
      sortOrder: sortOrderFor('total'),
      render: (_, c) => (
        <span className="clients-total-text">
          {c.total_traffic_readable || formatBytes(c.total_traffic)}
        </span>
      ),
    },
    {
      title: 'Last Connected',
      key: 'time',
      sorter: true,
      sortOrder: sortOrderFor('time'),
      render: (_, c) => {
        const rel = relativeTime(relevantEpoch(c));
        const exact = c.online ? c.connected_since : c.last_seen || c.connected_since;
        const text = <span className="clients-rel-time">{rel}</span>;
        return exact ? <Tooltip title={exact}>{text}</Tooltip> : text;
      },
    },
    {
      title: '',
      key: 'expand',
      className: 'clients-col-expand',
      width: 44,
      render: () => <RightOutlined className="clients-chevron" />,
    },
  ];

  const showSkeleton = isPending && !loaded;

  return (
    <PageShell title="Clients" className="clients-page">
      <div className="clients-stats-grid">
        <StatCard title="Clients" value={loaded ? stats.total : '—'}>
          <div className="clients-stat-rows">
            <div className="clients-stat-row">
              <span className="clients-stat-row-label">
                <span className="clients-dot" style={{ background: 'var(--color-success)' }} />
                Online
              </span>
              <span className="clients-stat-row-value">
                {loaded ? stats.online : '—'}
                {loaded ? <span className="clients-pct">({stats.pctOn}%)</span> : null}
              </span>
            </div>
            <div className="clients-stat-row">
              <span className="clients-stat-row-label">
                <span className="clients-dot" style={{ background: 'var(--text-tertiary)' }} />
                Offline
              </span>
              <span className="clients-stat-row-value">
                {loaded ? stats.offline : '—'}
                {loaded ? <span className="clients-pct">({stats.pctOff}%)</span> : null}
              </span>
            </div>
          </div>
          <div className="clients-ratio-bar">
            <div
              className="clients-ratio-bar-fill"
              style={{ width: `${loaded ? stats.pctOn : 0}%` }}
            />
          </div>
          <div className="clients-ratio-bar-labels">
            <span>Online {loaded ? stats.pctOn : 0}%</span>
            <span>Offline {loaded ? stats.pctOff : 100}%</span>
          </div>
        </StatCard>

        <StatCard title="Traffic" value={loaded ? formatBytes(stats.traffic) : '—'}>
          <div className="clients-stat-rows">
            <div className="clients-stat-row">
              <span className="clients-stat-row-label">
                <span className="clients-dot" style={{ background: 'var(--recv-color)' }} />
                Download
              </span>
              <span className="clients-stat-row-value">
                {loaded ? formatBytes(stats.recv) : '—'}
              </span>
            </div>
            <div className="clients-stat-row">
              <span className="clients-stat-row-label">
                <span className="clients-dot" style={{ background: 'var(--sent-color)' }} />
                Upload
              </span>
              <span className="clients-stat-row-value">
                {loaded ? formatBytes(stats.sent) : '—'}
              </span>
            </div>
          </div>
        </StatCard>
      </div>

      <div className="clients-controls">
        <Segmented
          value={filter}
          onChange={handleFilterChange}
          options={FILTER_OPTIONS}
          size={isMobile ? 'small' : 'middle'}
        />
        <Input
          className="clients-search"
          allowClear
          prefix={<SearchOutlined className="clients-search-icon" />}
          placeholder="Search client..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <section className="dc-card clients-table-card">
        {showSkeleton ? (
          <div className="clients-skeleton">
            <Skeleton active title={false} paragraph={{ rows: 5 }} />
          </div>
        ) : (
          <div className={`clients-table-fade${isFetching ? ' is-fetching' : ''}`}>
            <Table<Client>
              columns={columns}
              dataSource={visible}
              rowKey="common_name"
              pagination={false}
              size={isMobile ? 'small' : 'middle'}
              onChange={(_pagination, _filters, sorter) => {
                const single = Array.isArray(sorter) ? sorter[0] : sorter;
                const col = single?.columnKey as SortCol | undefined;
                if (col) handleSort(col);
              }}
              onRow={(c) => ({
                className: 'clients-row',
                onClick: () => navigate(`/panel/clients/${encodeURIComponent(c.common_name)}`),
              })}
              locale={{
                emptyText: (
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description={
                      <span className="clients-empty">
                        <span className="clients-empty-title">No clients found</span>
                        <span className="clients-empty-sub">
                          Try adjusting the filter or search term
                        </span>
                      </span>
                    }
                  />
                ),
              }}
            />
          </div>
        )}
      </section>

      <div className="clients-footer">
        <span>VPN Client Monitor</span>
        <span>{loaded ? footerCount : 'Loading...'}</span>
      </div>
    </PageShell>
  );
}

export default ClientsPage;

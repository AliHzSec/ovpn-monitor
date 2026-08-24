// DomainDetailPage — React port of templates/domaindetail.html: the leaf level
// of the Visited Domains view (one root domain for one client, listing every
// recorded hostname). Summary numbers are rolled up client-side from the same
// rows the table shows, exactly like the legacy page, so the two can never
// disagree. All colors come from the shared tokens, so the page flips with
// body.dark / body.light.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router';
import { Breadcrumb, Button, Card, Empty, Input, Skeleton, Table, Tag, Tooltip } from 'antd';
import type { TableProps } from 'antd';
import { ArrowLeftOutlined, GlobalOutlined } from '@ant-design/icons';

import { useDomainDetail } from '@/api/queries/useDomainDetail';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import type { VisitedDomain } from '@/models/types';
import { relativeTime } from '@/utils/format';

import './DomainDetailPage.css';

const PAGE_SIZE = 25;
const REFRESH_MS = 15_000;

// Legacy sort semantics: default last-seen desc; picking a new column starts
// desc for everything except domain, which starts asc; re-clicking flips.
const SORT_DIRECTIONS = {
  domain: ['ascend', 'descend'],
  numeric: ['descend', 'ascend'],
} as const;

export function DomainDetailPage() {
  const { name = '', root = '' } = useParams();
  const { isMobile } = useMediaQuery();
  const { data, isPending, isError, refetch } = useDomainDetail(name, root);

  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);

  const clientHref = `/panel/clients/${encodeURIComponent(name)}`;

  useEffect(() => {
    document.title = `${root} — Domain Detail`;
  }, [root]);

  // Auto-refresh like the legacy setInterval(fetchSubdomains, 15000). React
  // Query keeps the previous data while a refetch is in flight, so the table
  // never drops back to the skeleton after the first load.
  useEffect(() => {
    const id = setInterval(() => {
      void refetch();
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [refetch]);

  const domains = useMemo(() => data ?? [], [data]);
  // True until the first successful fetch (also on initial-load error, where
  // the legacy page simply keeps the '—' placeholders in the summary cards).
  const showPlaceholders = data === undefined;

  // The same rollup the legacy renderSummary() does over allDomains.
  const summary = useMemo(() => {
    let total = 0;
    let first = 0;
    let last = 0;
    let direct = 0;
    let firstExact = '';
    let lastExact = '';
    let top: VisitedDomain | null = null;
    for (const d of domains) {
      const count = Number(d.visit_count) || 0;
      total += count;
      const f = Number(d.first_seen_epoch) || 0;
      const l = Number(d.last_seen_epoch) || 0;
      if (f && (!first || f < first)) {
        first = f;
        firstExact = d.first_seen || '';
      }
      if (l && l > last) {
        last = l;
        lastExact = d.last_seen || '';
      }
      if (d.domain === root) direct = count;
      if (!top || count > (Number(top.visit_count) || 0)) top = d;
    }
    return { total, first, last, direct, firstExact, lastExact, top, distinct: domains.length };
  }, [domains, root]);

  // Domain-substring search only — no hostnames blob, no client-IP case.
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return domains;
    return domains.filter((d) => d.domain.toLowerCase().includes(q));
  }, [domains, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  // Legacy clamp: keep the current page inside range when data/filter shrink.
  useEffect(() => {
    setPage((p) => Math.min(Math.max(p, 1), pageCount));
  }, [pageCount]);

  // Sorting itself is uncontrolled (antd toggles between the two directions,
  // never clearing); this only reproduces the legacy "sort change resets to
  // page 1" behavior.
  const sortSigRef = useRef('last:descend');
  const handleTableChange: TableProps<VisitedDomain>['onChange'] = (
    pagination,
    _filters,
    sorter,
  ) => {
    const s = Array.isArray(sorter) ? sorter[0] : sorter;
    const sig = `${String(s?.columnKey ?? '')}:${String(s?.order ?? '')}`;
    if (sig !== sortSigRef.current) {
      sortSigRef.current = sig;
      setPage(1);
    } else {
      setPage(pagination.current ?? 1);
    }
  };

  const columns: TableProps<VisitedDomain>['columns'] = [
    {
      title: 'Domain',
      dataIndex: 'domain',
      key: 'domain',
      sorter: (a, b) => a.domain.toLowerCase().localeCompare(b.domain.toLowerCase()),
      sortDirections: [...SORT_DIRECTIONS.domain],
      render: (domain: string) => (
        <span>
          <span className="dd-domain-text">{domain}</span>
          {domain === root ? <Tag className="dd-self-tag">Root</Tag> : null}
        </span>
      ),
    },
    {
      title: 'First Seen',
      dataIndex: 'first_seen_epoch',
      key: 'first',
      sorter: (a, b) => (a.first_seen_epoch || 0) - (b.first_seen_epoch || 0),
      sortDirections: [...SORT_DIRECTIONS.numeric],
      render: (_: unknown, r) => (
        <Tooltip title={r.first_seen || undefined}>
          <span className="dd-time-cell">{relativeTime(r.first_seen_epoch)}</span>
        </Tooltip>
      ),
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen_epoch',
      key: 'last',
      defaultSortOrder: 'descend',
      sorter: (a, b) => (a.last_seen_epoch || 0) - (b.last_seen_epoch || 0),
      sortDirections: [...SORT_DIRECTIONS.numeric],
      render: (_: unknown, r) => (
        <Tooltip title={r.last_seen || undefined}>
          <span className="dd-time-cell">{relativeTime(r.last_seen_epoch)}</span>
        </Tooltip>
      ),
    },
    {
      title: 'Visits',
      dataIndex: 'visit_count',
      key: 'count',
      align: 'right',
      sorter: (a, b) => (a.visit_count || 0) - (b.visit_count || 0),
      sortDirections: [...SORT_DIRECTIONS.numeric],
      render: (count: number) => <span className="dd-count-pill">{count || 0}</span>,
    },
  ];

  const trimmedQuery = query.trim();
  const emptyText = isError ? (
    <Empty
      image={Empty.PRESENTED_IMAGE_SIMPLE}
      description={
        <div className="dd-empty">
          <div className="dd-empty-title">Could not load domains</div>
          <div className="dd-empty-sub">Please try again.</div>
        </div>
      }
    />
  ) : (
    <Empty
      image={Empty.PRESENTED_IMAGE_SIMPLE}
      description={
        <div className="dd-empty">
          <div className="dd-empty-title">No subdomains recorded</div>
          <div className="dd-empty-sub">
            {trimmedQuery
              ? 'No domains match your search.'
              : 'This client has no recorded history for this domain.'}
          </div>
        </div>
      }
    />
  );

  return (
    <div className="domain-detail-page">
      <Breadcrumb
        className="dd-breadcrumb"
        items={[
          { title: <Link to="/panel/clients">Clients</Link> },
          { title: <Link to={clientHref}>{name}</Link> },
          { title: <span className="dd-crumb-current">{root}</span> },
        ]}
      />

      <div className="dd-back">
        <Link to={clientHref}>
          <Button ghost icon={<ArrowLeftOutlined />}>
            Back to Client
          </Button>
        </Link>
      </div>

      <Card className="dd-domain-head" variant="borderless">
        <div className="dd-domain-avatar">
          <GlobalOutlined />
        </div>
        <div className="dd-domain-head-main">
          <div className="dd-domain-name">{root}</div>
          <div className="dd-domain-sub">Visited by {name}</div>
        </div>
      </Card>

      <div className="dd-info-grid">
        <Card className="dd-info-card" variant="borderless">
          <div className="dd-info-card-title">
            <span className="dd-info-card-title-dot" />
            Activity
          </div>
          <div className="dd-kv">
            <div className="dd-kv-row">
              <span className="dd-kv-label">First Seen</span>
              <Tooltip title={showPlaceholders ? undefined : summary.firstExact || undefined}>
                <span className="dd-kv-value">
                  {showPlaceholders ? '—' : relativeTime(summary.first)}
                </span>
              </Tooltip>
            </div>
            <div className="dd-kv-row">
              <span className="dd-kv-label">Last Seen</span>
              <Tooltip title={showPlaceholders ? undefined : summary.lastExact || undefined}>
                <span className="dd-kv-value">
                  {showPlaceholders ? '—' : relativeTime(summary.last)}
                </span>
              </Tooltip>
            </div>
          </div>
        </Card>

        <Card className="dd-info-card" variant="borderless">
          <div className="dd-info-card-title">
            <span className="dd-info-card-title-dot" />
            Visits
          </div>
          <div className="dd-kv">
            <div className="dd-kv-row">
              <span className="dd-kv-label">Total</span>
              <span className="dd-kv-value total">
                {showPlaceholders ? '—' : summary.total}
              </span>
            </div>
            <div className="dd-kv-row">
              <span className="dd-kv-label">Root Domain Itself</span>
              <span className="dd-kv-value muted">
                {showPlaceholders ? '—' : summary.direct}
              </span>
            </div>
          </div>
        </Card>

        <Card className="dd-info-card" variant="borderless">
          <div className="dd-info-card-title">
            <span className="dd-info-card-title-dot success" />
            Hostnames
          </div>
          <div className="dd-kv">
            <div className="dd-kv-row">
              <span className="dd-kv-label">Distinct</span>
              <span className="dd-kv-value">
                {showPlaceholders ? '—' : summary.distinct}
              </span>
            </div>
            <div className="dd-kv-row">
              <span className="dd-kv-label">Most Visited</span>
              <span className="dd-kv-value muted hostname">
                {showPlaceholders ? '—' : (summary.top?.domain ?? '—')}
              </span>
            </div>
          </div>
        </Card>
      </div>

      <Card className="dd-domains-card" variant="borderless">
        <div className="dd-domains-head">
          <div className="dd-domains-title">
            <GlobalOutlined />
            Subdomains
          </div>
          <Input
            className="dd-search"
            allowClear
            placeholder="Search domain or IP..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(1);
            }}
          />
        </div>

        {isPending ? (
          <div className="dd-table-skeleton">
            <Skeleton active title={false} paragraph={{ rows: 3 }} />
          </div>
        ) : (
          <Table<VisitedDomain>
            rowKey="domain"
            size={isMobile ? 'small' : 'middle'}
            columns={columns}
            dataSource={filtered}
            onChange={handleTableChange}
            locale={{ emptyText }}
            pagination={{
              current: page,
              pageSize: PAGE_SIZE,
              simple: true,
              showSizeChanger: false,
              showTotal: (total) =>
                isError && showPlaceholders
                  ? ''
                  : `${total} hostname${total === 1 ? '' : 's'}${trimmedQuery ? ' (filtered)' : ''}`,
            }}
          />
        )}
      </Card>
    </div>
  );
}

export default DomainDetailPage;

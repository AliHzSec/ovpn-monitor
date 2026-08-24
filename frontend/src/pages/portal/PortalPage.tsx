import { useState } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Badge, Segmented } from 'antd';

import { get } from '@/api/http';
import type { Client } from '@/models/types';
import CopyText from '@/components/ui/CopyText';
import { formatBytes } from '@/utils/format';

import './PortalPage.css';

// Bootstrap data the Go server injects into portal.html as
// window.OVPN_PORTAL before this bundle runs (it replaces the old template's
// server-rendered {{.CommonName}} etc.). Everything falls back to empty
// strings / false so the page still renders when the global is absent (dev
// server, direct file access).
export interface PortalBootstrap {
  common_name: string;
  vpn_address: string;
  online: boolean;
  connected_since: string;
  last_seen: string;
}

declare global {
  interface Window {
    OVPN_PORTAL?: Partial<PortalBootstrap>;
  }
}

export function readPortalBootstrap(): PortalBootstrap {
  const raw = typeof window !== 'undefined' ? window.OVPN_PORTAL : undefined;
  return {
    common_name: raw?.common_name ?? '',
    vpn_address: raw?.vpn_address ?? '',
    online: raw?.online ?? false,
    connected_since: raw?.connected_since ?? '',
    last_seen: raw?.last_seen ?? '',
  };
}

// GET /api/client-stats?filter=… returns the traffic fields of Client. The
// endpoint is IP-gated (VPN subnet), not session-gated, so no 401 redirect
// applies here; failures just render '—' like the old portal did.
type ClientStats = Pick<
  Client,
  | 'total_traffic'
  | 'total_traffic_readable'
  | 'bytes_received'
  | 'bytes_received_readable'
  | 'bytes_sent'
  | 'bytes_sent_readable'
>;

const FILTERS = [
  { value: 'today', label: 'Today' },
  { value: 'week', label: '7 Days' },
  { value: 'month', label: '30 Days' },
  { value: 'all', label: 'All Time' },
] as const;

type FilterValue = (typeof FILTERS)[number]['value'];

const EMPTY = '—';

function statText(readable: string, raw: number): string {
  return readable || formatBytes(raw || 0);
}

interface StatRowProps {
  dotColor: string;
  label: string;
  value: string;
  valueClass: string;
}

function StatRow({ dotColor, label, value, valueClass }: StatRowProps) {
  return (
    <div className="portal-stat-row">
      <div className="portal-stat-row-label">
        <span className="portal-dot" style={{ background: dotColor }} />
        {label}
      </div>
      <div className={`portal-stat-row-value ${valueClass}`}>{value}</div>
    </div>
  );
}

export function PortalPage() {
  const [portal] = useState<PortalBootstrap>(readPortalBootstrap);
  const [filter, setFilter] = useState<FilterValue>('today');

  // Usage card: re-fetches on filter change and every 30s. keepPreviousData
  // keeps the previous filter's numbers on screen until the new fetch lands,
  // matching the old page's DOM-update-on-response behaviour.
  const usageQuery = useQuery({
    queryKey: ['portal-usage', filter],
    queryFn: () => get<ClientStats>('/api/client-stats', { params: { filter } }),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });

  // All Time card: fetched once on load, deliberately NOT on the refresh
  // interval and keyed separately so selecting the "All Time" filter never
  // piggybacks on (or re-triggers) this card's data.
  const allTimeQuery = useQuery({
    queryKey: ['portal-alltime'],
    queryFn: () => get<ClientStats>('/api/client-stats', { params: { filter: 'all' } }),
    staleTime: Infinity,
  });

  const usage = usageQuery.isError ? null : (usageQuery.data ?? null);
  const allTime = allTimeQuery.isError ? null : (allTimeQuery.data ?? null);

  const filterLabel = FILTERS.find((f) => f.value === filter)?.label ?? 'Today';

  const liveText = usageQuery.dataUpdatedAt
    ? `Updated ${new Date(usageQuery.dataUpdatedAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })}`
    : 'Loading...';

  const initial = portal.common_name ? portal.common_name.charAt(0).toUpperCase() : '?';

  return (
    <div className="portal-page">
      {/* TOPBAR — no sidebar, no logout */}
      <header className="portal-topbar">
        <div className="portal-logo-text">
          <span className="portal-logo-dot" />
          Server Monitor
        </div>
        <div className="portal-topbar-center">
          <div className="portal-live-badge">
            <span className="portal-live-dot" />
            <span>{liveText}</span>
          </div>
        </div>
        <div className="portal-topbar-right" />
      </header>

      <main className="portal-main">
        {/* Hero */}
        <div className="portal-hero">
          <div className="portal-hero-avatar">{initial}</div>
          <div className="portal-hero-name">{portal.common_name || EMPTY}</div>
          <div className="portal-hero-ip">
            {portal.vpn_address ? <CopyText text={portal.vpn_address} /> : EMPTY}
          </div>
          <div className="portal-hero-badge-row">
            {portal.online ? (
              <Badge status="success" text="Online" />
            ) : (
              <Badge status="default" text="Offline" />
            )}
          </div>
          {portal.online ? (
            <div className="portal-hero-time connected">
              Connected since: {portal.connected_since}
            </div>
          ) : portal.last_seen ? (
            <div className="portal-hero-time last-seen">Last seen: {portal.last_seen}</div>
          ) : null}
          <div className="portal-hero-divider" />
        </div>

        {/* Stats row: Usage (filtered) + All Time */}
        <div className="portal-stats-grid">
          <section className="portal-stat-card c-usage">
            <div className="portal-stat-card-title">
              <span className="portal-title-dot" style={{ background: 'var(--color-primary)' }} />
              Usage — {filterLabel}
            </div>
            <div className="portal-stat-rows">
              <StatRow
                dotColor="var(--color-primary)"
                label="Total"
                value={usage ? statText(usage.total_traffic_readable, usage.total_traffic) : EMPTY}
                valueClass="total"
              />
              <StatRow
                dotColor="var(--recv-color)"
                label="Download"
                value={usage ? statText(usage.bytes_received_readable, usage.bytes_received) : EMPTY}
                valueClass="recv"
              />
              <StatRow
                dotColor="var(--sent-color)"
                label="Upload"
                value={usage ? statText(usage.bytes_sent_readable, usage.bytes_sent) : EMPTY}
                valueClass="sent"
              />
            </div>
          </section>

          <section className="portal-stat-card c-alltime">
            <div className="portal-stat-card-title">
              <span className="portal-title-dot" style={{ background: 'var(--color-success)' }} />
              All Time
            </div>
            <div className="portal-stat-rows">
              <StatRow
                dotColor="var(--text-secondary)"
                label="Total"
                value={
                  allTime ? statText(allTime.total_traffic_readable, allTime.total_traffic) : EMPTY
                }
                valueClass="traffic-total"
              />
              <StatRow
                dotColor="var(--recv-color)"
                label="Download"
                value={
                  allTime ? statText(allTime.bytes_received_readable, allTime.bytes_received) : EMPTY
                }
                valueClass="recv"
              />
              <StatRow
                dotColor="var(--sent-color)"
                label="Upload"
                value={allTime ? statText(allTime.bytes_sent_readable, allTime.bytes_sent) : EMPTY}
                valueClass="sent"
              />
            </div>
          </section>
        </div>

        {/* Filter tabs */}
        <div className="portal-filter-group">
          <Segmented<FilterValue>
            options={FILTERS.map((f) => ({ value: f.value, label: f.label }))}
            value={filter}
            onChange={setFilter}
          />
        </div>
      </main>

      {/* FOOTER */}
      <footer className="portal-footer">
        <span>
          Your IP: {portal.vpn_address ? <CopyText text={portal.vpn_address} /> : EMPTY}
        </span>
      </footer>
    </div>
  );
}

// The portal entry (src/entries/portal.tsx) imports the default export.
export default PortalPage;

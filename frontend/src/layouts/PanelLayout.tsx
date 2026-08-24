import { useMemo } from 'react';
import { Outlet } from 'react-router';
import { Layout } from 'antd';

import AppSidebar from '@/layouts/AppSidebar';
import { useWebSocketBridge } from '@/api/websocketBridge';
import { useServerStats } from '@/api/queries/useServerStats';

function formatClock(ms: number): string {
  if (!ms) return '—';
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export default function PanelLayout() {
  useWebSocketBridge();
  // dataUpdatedAt moves on every WS push / poll, so the badge is live.
  const { dataUpdatedAt } = useServerStats();
  const updated = useMemo(() => formatClock(dataUpdatedAt), [dataUpdatedAt]);

  return (
    <Layout className="panel-shell" hasSider>
      <AppSidebar />
      <Layout className="panel-main">
        <div className="panel-topbar">
          <span className="topbar-updated">Updated {updated}</span>
        </div>
        <Layout.Content className="content-area">
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  );
}

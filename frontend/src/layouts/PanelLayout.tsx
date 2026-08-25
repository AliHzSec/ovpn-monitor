import { Outlet } from 'react-router';
import { Layout } from 'antd';

import AppSidebar from '@/layouts/AppSidebar';
import { useWebSocketBridge } from '@/api/websocketBridge';

// Panel frame, structured after 3x-ui's pages (sidebar rail + transparent
// content shell; no topbar — the theme toggle lives in the sidebar brand area,
// exactly as in 3x-ui's AppSidebar).
export default function PanelLayout() {
  useWebSocketBridge();

  return (
    <Layout className="panel-shell" hasSider>
      <AppSidebar />
      <Layout className="content-shell">
        <Layout.Content className="content-area">
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  );
}

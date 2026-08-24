import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { Drawer, Layout, Menu } from 'antd';
import type { MenuProps } from 'antd';
import {
  CloseOutlined,
  DashboardOutlined,
  GlobalOutlined,
  LogoutOutlined,
  MenuOutlined,
  MoonOutlined,
  PushpinFilled,
  PushpinOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  SlidersOutlined,
  SunOutlined,
  TeamOutlined,
} from '@ant-design/icons';

import { useTheme } from '@/hooks/useTheme';
import './AppSidebar.css';

const RAIL_WIDTH = 72;
const SIDER_WIDTH = 220;
const SIDEBAR_PINNED_KEY = 'sidebar-pinned';
const LOGOUT_PATH = '/panel/logout';

let hoveredAcrossRemounts = false;

function readSidebarPinned() {
  try {
    return localStorage.getItem(SIDEBAR_PINNED_KEY) === 'true';
  } catch {
    return false;
  }
}

function saveSidebarPinned(pinned: boolean) {
  try {
    localStorage.setItem(SIDEBAR_PINNED_KEY, String(pinned));
  } catch {}
}

// ovpn-monitor's existing menu, mirrored from templates/static/sidebar.js.
const settingsChildren: NonNullable<MenuProps['items']> = [
  { key: '/settings/general', icon: <SlidersOutlined />, label: 'General' },
  { key: '/settings/openvpn', icon: <SafetyCertificateOutlined />, label: 'OpenVPN' },
  { key: '/settings/wireguard', icon: <GlobalOutlined />, label: 'WireGuard' },
  { key: '/settings/domains', icon: <GlobalOutlined />, label: 'Domain Tracking' },
];

const navItems: MenuProps['items'] = [
  { key: '/panel', icon: <DashboardOutlined />, label: 'Overview', title: '' },
  { key: '/panel/clients', icon: <TeamOutlined />, label: 'Clients', title: '' },
  {
    key: '/settings',
    icon: <SettingOutlined />,
    label: 'Panel Settings',
    children: settingsChildren,
  },
];

const utilItems: MenuProps['items'] = [
  { key: LOGOUT_PATH, icon: <LogoutOutlined />, label: 'Log Out', title: '' },
];

// Light/dark toggle, mirroring 3x-ui's sidebar theme button: sun in dark mode
// (switch to light), moon in light mode (switch to dark).
function ThemeToggleButton({ id, isDark, onToggle }: { id: string; isDark: boolean; onToggle: () => void }) {
  const ariaLabel = isDark ? 'Switch to light theme' : 'Switch to dark theme';
  return (
    <button
      id={id}
      type="button"
      className="sidebar-theme-cycle"
      aria-label={ariaLabel}
      title={ariaLabel}
      onClick={onToggle}
    >
      {isDark ? <SunOutlined /> : <MoonOutlined />}
    </button>
  );
}

export default function AppSidebar() {
  const { isDark, toggleTheme } = useTheme();
  const currentTheme = isDark ? ('dark' as const) : ('light' as const);
  const navigate = useNavigate();
  const { pathname } = useLocation();

  const [hovered, setHovered] = useState(() => hoveredAcrossRemounts);
  const [pinned, setPinned] = useState(readSidebarPinned);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const railCollapsed = !hovered && !pinned;
  const railStyle = useMemo(
    () => ({ '--sider-rail': `${pinned ? SIDER_WIDTH : RAIL_WIDTH}px` }) as CSSProperties,
    [pinned],
  );
  const rootRef = useRef<HTMLDivElement>(null);

  const updateHovered = useCallback((value: boolean) => {
    hoveredAcrossRemounts = value;
    setHovered(value);
  }, []);

  const togglePinned = useCallback(() => {
    const next = !pinned;
    saveSidebarPinned(next);
    setPinned(next);
  }, [pinned]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const el = rootRef.current;
      if (el) updateHovered(el.matches(':hover'));
    }, 150);
    return () => window.clearTimeout(timer);
  }, [updateHovered]);

  // Client detail pages (/panel/clients/<name>[...]) keep Clients lit;
  // settings sections match exactly; everything else falls back to Overview.
  const selectedKey = pathname.startsWith('/panel/clients')
    ? '/panel/clients'
    : pathname.startsWith('/settings')
      ? pathname
      : '/panel';

  const onSettings = pathname.startsWith('/settings');
  const [openKeys, setOpenKeys] = useState<string[]>(() => (onSettings ? ['/settings'] : []));
  if (onSettings && !openKeys.includes('/settings')) {
    setOpenKeys([...openKeys, '/settings']);
  }

  const onMenuClick = useCallback<NonNullable<MenuProps['onClick']>>(
    ({ key }) => {
      if (key === LOGOUT_PATH) {
        window.location.href = LOGOUT_PATH;
        return;
      }
      navigate(key);
    },
    [navigate],
  );

  return (
    <div
      ref={rootRef}
      className={`ant-sidebar${pinned ? ' sidebar-pinned' : ''}`}
      style={railStyle}
      onMouseEnter={() => updateHovered(true)}
      onMouseLeave={() => updateHovered(false)}
    >
      <Layout.Sider
        theme={currentTheme}
        width={SIDER_WIDTH}
        collapsedWidth={RAIL_WIDTH}
        collapsed={railCollapsed}
      >
        <div className="sider-brand">
          <div className="brand-block">
            <span className="brand-text">{railCollapsed ? 'SM' : 'Server Monitor'}</span>
          </div>
          {!railCollapsed && (
            <div className="brand-actions">
              <button
                type="button"
                className="sidebar-pin"
                aria-label="Pin sidebar"
                aria-pressed={pinned}
                title={pinned ? 'Unpin sidebar' : 'Pin sidebar'}
                onClick={togglePinned}
              >
                {pinned ? <PushpinFilled /> : <PushpinOutlined />}
              </button>
              <ThemeToggleButton id="theme-cycle" isDark={isDark} onToggle={toggleTheme} />
            </div>
          )}
        </div>
        <Menu
          theme={currentTheme}
          mode="inline"
          selectedKeys={[selectedKey]}
          openKeys={railCollapsed ? undefined : openKeys}
          onOpenChange={(keys) => setOpenKeys(keys as string[])}
          className="sider-nav"
          items={navItems}
          onClick={onMenuClick}
        />
        <Menu
          theme={currentTheme}
          mode="inline"
          selectedKeys={[selectedKey]}
          className="sider-utility"
          items={utilItems}
          onClick={onMenuClick}
        />
      </Layout.Sider>

      <Drawer
        placement="left"
        closable={false}
        open={drawerOpen}
        rootClassName={currentTheme}
        size="min(82vw, 320px)"
        styles={{
          wrapper: { padding: 0 },
          body: { padding: 0, display: 'flex', flexDirection: 'column', height: '100%' },
          header: { display: 'none' },
        }}
        onClose={() => setDrawerOpen(false)}
      >
        <div className="drawer-header">
          <div className="brand-block">
            <span className="drawer-brand">Server Monitor</span>
          </div>
          <div className="drawer-header-actions">
            <ThemeToggleButton id="theme-cycle-drawer" isDark={isDark} onToggle={toggleTheme} />
            <button
              className="drawer-close"
              type="button"
              aria-label="Close menu"
              onClick={() => setDrawerOpen(false)}
            >
              <CloseOutlined />
            </button>
          </div>
        </div>
        <Menu
          theme={currentTheme}
          mode="inline"
          selectedKeys={[selectedKey]}
          openKeys={openKeys}
          onOpenChange={(keys) => setOpenKeys(keys as string[])}
          className="drawer-menu drawer-nav"
          items={navItems}
          onClick={(info) => {
            onMenuClick(info);
            setDrawerOpen(false);
          }}
        />
        <Menu
          theme={currentTheme}
          mode="inline"
          selectedKeys={[selectedKey]}
          className="drawer-menu drawer-utility"
          items={utilItems}
          onClick={(info) => {
            onMenuClick(info);
            setDrawerOpen(false);
          }}
        />
      </Drawer>

      {!drawerOpen && (
        <button
          className="drawer-handle"
          type="button"
          aria-label="Open menu"
          onClick={() => setDrawerOpen(true)}
        >
          <MenuOutlined />
        </button>
      )}
    </div>
  );
}

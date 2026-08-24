import { Suspense, lazy } from 'react';
import { createBrowserRouter, Navigate } from 'react-router';

import PanelLayout from '@/layouts/PanelLayout';

// Lazy page imports keep each route's chunk out of the first paint. Page
// contents land in Step 3 — these are placeholders wired to the real URLs.
const OverviewPage = lazy(() => import('@/pages/overview/OverviewPage'));
const ClientsPage = lazy(() => import('@/pages/clients/ClientsPage'));
const ClientDetailPage = lazy(() => import('@/pages/clientDetail/ClientDetailPage'));
const DomainDetailPage = lazy(() => import('@/pages/domainDetail/DomainDetailPage'));
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'));

function lazyPage(element: React.ReactNode) {
  return <Suspense fallback={<div className="loading-spacer" />}>{element}</Suspense>;
}

export const router = createBrowserRouter(
  [
    {
      element: <PanelLayout />,
      children: [
        { path: 'panel', element: lazyPage(<OverviewPage />) },
        { path: 'panel/clients', element: lazyPage(<ClientsPage />) },
        { path: 'panel/clients/:name', element: lazyPage(<ClientDetailPage />) },
        {
          path: 'panel/clients/:name/domains/:root',
          element: lazyPage(<DomainDetailPage />),
        },
        { path: 'settings', element: <Navigate to="/settings/general" replace /> },
        { path: 'settings/:section', element: lazyPage(<SettingsPage />) },
        { path: '*', element: <Navigate to="/panel" replace /> },
      ],
    },
  ],
  { basename: '/' },
);

// The theme module must be imported FIRST: it applies the stored dark/light
// class to the document at module load, before React mounts and paints.
import { ThemeProvider, ThemedConfigProvider } from '@/hooks/useTheme';
import { createRoot } from 'react-dom/client';
import { message } from 'antd';
import { QueryClientProvider } from '@tanstack/react-query';
import 'antd/dist/reset.css';
import '@/styles/tokens.css';
import '@/styles/page-shell.css';
import '@/styles/page-cards.css';

import { queryClient } from '@/queryClient';
import PortalPage from '@/pages/portal/PortalPage';

const messageContainer = document.getElementById('message');
if (messageContainer) {
  message.config({ getContainer: () => messageContainer });
}

const root = document.getElementById('app');
if (root) {
  createRoot(root).render(
    <ThemeProvider>
      <ThemedConfigProvider>
        <QueryClientProvider client={queryClient}>
          <PortalPage />
        </QueryClientProvider>
      </ThemedConfigProvider>
    </ThemeProvider>,
  );
}

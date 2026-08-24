import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

const outDir = path.resolve(import.meta.dirname, '../internal/web/dist');
const BACKEND_TARGET = process.env.OVPN_BACKEND || 'http://localhost:8080';

function makeBackendProxy(target) {
  return {
    target,
    changeOrigin: true,
    configure(proxy) {
      let warned = false;
      proxy.on('error', (err, req) => {
        const codes = new Set();
        if (err && err.code) codes.add(err.code);
        if (err && Array.isArray(err.errors)) {
          for (const inner of err.errors) {
            if (inner && inner.code) codes.add(inner.code);
          }
        }
        const offline = codes.has('ECONNREFUSED') || codes.has('ECONNRESET');
        if (offline) {
          if (!warned) {
            warned = true;
            // eslint-disable-next-line no-console
            console.warn(
              `[proxy] backend ${target} is not reachable — start the Go server (e.g. \`go run main.go\`) to forward ${req?.url || 'requests'}.`,
            );
          }
          return;
        }
        // eslint-disable-next-line no-console
        console.error('[proxy]', err);
      });
    },
  };
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, 'src'),
    },
  },
  build: {
    outDir,
    emptyOutDir: true,
    // Everything in outDir is embedded into the Go binary via embed.FS, so
    // production sourcemaps would ship inside every release build. To debug a
    // minified bundle, build once with OVPN_SOURCEMAP=true.
    sourcemap: process.env.OVPN_SOURCEMAP === 'true',
    target: 'es2020',
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      input: {
        index: path.resolve(import.meta.dirname, 'index.html'),
        login: path.resolve(import.meta.dirname, 'login.html'),
        portal: path.resolve(import.meta.dirname, 'portal.html'),
      },
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('/node_modules/antd/')) return 'vendor-antd';
          if (id.includes('/@ant-design/icons/') || id.includes('/@ant-design/icons-svg/')) return 'vendor-icons';
          if (
            id.includes('/node_modules/@rc-component/')
            || id.includes('/node_modules/rc-')
            || id.includes('/@ant-design/cssinjs')
            || id.includes('/@ant-design/colors')
            || id.includes('/@ant-design/fast-color')
            || id.includes('/@ant-design/react-slick')
            || id.includes('/@ctrl/tinycolor')
          ) return 'vendor-antd';
          if (
            id.includes('/node_modules/react/')
            || id.includes('/node_modules/react-dom/')
            || id.includes('/node_modules/scheduler/')
          ) return 'vendor-react';
          if (id.includes('/node_modules/react-router')) return 'vendor-router';
          if (id.includes('/node_modules/@tanstack/')) return 'vendor-tanstack';
          if (id.includes('/node_modules/uplot/')) return 'vendor-uplot';
          if (id.includes('dayjs')) return 'vendor-dayjs';
          return 'vendor';
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '^/(api|settings|panel/login|panel/logout|login|logout)(?:/|$)': makeBackendProxy(BACKEND_TARGET),
      '^/$': makeBackendProxy(BACKEND_TARGET),
      '^/ws$': {
        target: BACKEND_TARGET,
        ws: true,
        changeOrigin: true,
      },
    },
  },
});

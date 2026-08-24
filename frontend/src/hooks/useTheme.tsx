import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ConfigProvider, theme as antdTheme } from 'antd';
import type { ThemeConfig } from 'antd';

// Light/dark theme, ported from 3x-ui's hooks/useTheme.tsx with the ultra-dark
// mode dropped. Two modes only, persisted under the same 'dark-mode' key.
const STORAGE_DARK = 'dark-mode';

function readBool(key: string, fallback: boolean): boolean {
  const raw = localStorage.getItem(key);
  if (raw === null) return fallback;
  return raw === 'true';
}

function applyDom(isDark: boolean) {
  document.body.classList.remove('dark', 'light');
  document.body.classList.add(isDark ? 'dark' : 'light');
  const msg = document.getElementById('message');
  if (msg) {
    msg.classList.remove('dark', 'light');
    msg.classList.add(isDark ? 'dark' : 'light');
  }
}

// module load so the document is in the right theme before React mounts.
const initialDark = readBool(STORAGE_DARK, true);
applyDom(initialDark);

const DARK_TOKENS = {
  colorBgBase: '#1a1b1f',
  colorBgLayout: '#1a1b1f',
  colorBgContainer: '#23252b',
  colorBgElevated: '#2d2f37',
};
const DARK_LAYOUT_TOKENS = {
  bodyBg: '#1a1b1f',
  headerBg: '#15161a',
  headerColor: '#ffffff',
  footerBg: '#1a1b1f',
  siderBg: '#15161a',
  triggerBg: '#23252b',
  triggerColor: '#ffffff',
};
const DARK_MENU_TOKENS = {
  darkItemBg: '#15161a',
  darkSubMenuItemBg: '#1a1b1f',
  darkPopupBg: '#23252b',
};
const DARK_CARD_TOKENS = {
  colorBorderSecondary: 'rgba(255, 255, 255, 0.06)',
};
const STATISTIC_TOKENS = {
  contentFontSize: 17,
  titleFontSize: 11,
};
const LIGHT_CONTRAST_TOKENS = {
  colorTextDescription: 'rgba(0, 0, 0, 0.58)',
  colorTextTertiary: 'rgba(0, 0, 0, 0.58)',
  colorTextPlaceholder: '#767676',
  colorError: '#cf1322',
  colorErrorText: '#cf1322',
  colorSuccessText: '#237804',
};
const LIGHT_BUTTON_TOKENS = {
  colorPrimary: '#0958d9',
  colorPrimaryHover: '#2468e5',
  colorPrimaryActive: '#073ea8',
};

// hashed:false drops the `:where(.css-<hash>)` wrapper antd puts around every
// rule. It costs nothing in specificity — `:where()` contributes zero, so the
// panel's own `.ant-*` overrides still win — and it removes thousands of
// wrappers from what the browser has to parse.
//
// cssVar.key pins the CSS-variable scope. Every entry mounts its own
// ConfigProvider, and without a fixed key each mints a fresh useId-derived
// scope, so the token block would be re-serialised and re-injected under a new
// class instead of reusing the one already in the head.
const SHARED_STYLE_CONFIG = {
  hashed: false,
  cssVar: { key: 'ovpn' },
} as const;

export function buildAntdThemeConfig(isDark: boolean): ThemeConfig {
  if (!isDark) {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.defaultAlgorithm,
      token: LIGHT_CONTRAST_TOKENS,
      components: {
        Statistic: STATISTIC_TOKENS,
        Button: LIGHT_BUTTON_TOKENS,
      },
    };
  }
  return {
    ...SHARED_STYLE_CONFIG,
    algorithm: antdTheme.darkAlgorithm,
    token: DARK_TOKENS,
    components: {
      Layout: DARK_LAYOUT_TOKENS,
      Menu: DARK_MENU_TOKENS,
      Card: DARK_CARD_TOKENS,
      Statistic: STATISTIC_TOKENS,
    },
  };
}

interface ThemeContextValue {
  isDark: boolean;
  toggleTheme: () => void;
  antdThemeConfig: ThemeConfig;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [isDark, setIsDark] = useState<boolean>(initialDark);

  useLayoutEffect(() => {
    applyDom(isDark);
    localStorage.setItem(STORAGE_DARK, String(isDark));
  }, [isDark]);

  const toggleTheme = useCallback(() => setIsDark((v) => !v), []);

  const antdThemeConfig = useMemo(() => buildAntdThemeConfig(isDark), [isDark]);

  const value = useMemo<ThemeContextValue>(
    () => ({ isDark, toggleTheme, antdThemeConfig }),
    [isDark, toggleTheme, antdThemeConfig],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// ConfigProvider bound to the live theme: mount it inside <ThemeProvider> and
// every antd subtree below it follows toggleTheme().
export function ThemedConfigProvider({ children }: { children: ReactNode }) {
  const { antdThemeConfig } = useTheme();
  return <ConfigProvider theme={antdThemeConfig}>{children}</ConfigProvider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}

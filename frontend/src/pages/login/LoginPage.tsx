import { useState } from 'react';
import { Button, Form, Input } from 'antd';
import {
  LockOutlined,
  LoginOutlined,
  MoonOutlined,
  SunOutlined,
  UserOutlined,
} from '@ant-design/icons';

import { HttpError, postForm } from '@/api/http';
import { useTheme } from '@/hooks/useTheme';

import './LoginPage.css';

interface LoginFormValues {
  username: string;
  password: string;
}

// 1:1 React port of templates/login.html. The form POSTs form-urlencoded to
// /panel/login via postForm. The Go server answers valid credentials with a
// 303 to /panel (fetch follows it, resolving with the panel HTML) and invalid
// ones with 401 JSON {"error":"Invalid username or password"} — the clean
// contract consumed below.
export function LoginPage() {
  const { isDark, toggleTheme } = useTheme();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const themeLabel = isDark ? 'Switch to light theme' : 'Switch to dark theme';

  const onFinish = async (values: LoginFormValues) => {
    setError(null);
    setSubmitting(true);
    try {
      await postForm('/panel/login', {
        username: values.username,
        password: values.password,
      });
      // Login succeeded: the session cookie is set, enter the panel.
      window.location.href = '/panel';
    } catch (err) {
      if (err instanceof HttpError && err.status === 401) {
        setError('Invalid username or password');
      } else {
        setError('Login request failed — is the server running?');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <Button
        id="login-theme-cycle"
        className="login-theme-toggle"
        shape="circle"
        size="large"
        aria-label={themeLabel}
        title={themeLabel}
        icon={isDark ? <SunOutlined /> : <MoonOutlined />}
        onClick={toggleTheme}
      />

      <div className="login-card">
        <div className="login-header">
          <div className="login-brand">
            <span className="login-brand-dot" />
            <span className="login-brand-text">Server Monitor</span>
          </div>
          <h1 className="login-title">
            <span className="login-hello-dim">→ </span>Sign in
          </h1>
          <div className="login-subtitle">Enter your credentials to continue</div>
        </div>

        {error ? (
          <div className="login-error-box" role="alert">
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            {error}
          </div>
        ) : null}

        <Form<LoginFormValues> onFinish={onFinish} requiredMark={false}>
          <div className="login-field">
            <label className="login-label" htmlFor="username">
              Username
            </label>
            <Form.Item
              name="username"
              rules={[{ required: true, message: 'Username is required' }]}
            >
              <Input
                id="username"
                prefix={<UserOutlined />}
                placeholder="admin"
                autoFocus
                autoComplete="username"
              />
            </Form.Item>
          </div>

          <div className="login-field">
            <label className="login-label" htmlFor="password">
              Password
            </label>
            <Form.Item
              name="password"
              rules={[{ required: true, message: 'Password is required' }]}
            >
              <Input.Password
                id="password"
                prefix={<LockOutlined />}
                placeholder="••••••••"
                autoComplete="current-password"
                visibilityToggle
              />
            </Form.Item>
          </div>

          <div className="login-submit-wrap">
            <Button
              type="primary"
              htmlType="submit"
              className="login-submit"
              loading={submitting}
              icon={<LoginOutlined />}
              block
            >
              Log In
            </Button>
          </div>
        </Form>

        <div className="login-footer">Monitoring — Restricted Access</div>
      </div>
    </div>
  );
}

// The login entry (src/entries/login.tsx) imports this page as a default
// export; the named export above is the canonical one.
export default LoginPage;

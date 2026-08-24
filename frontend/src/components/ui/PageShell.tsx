import type { ReactNode } from 'react';

interface PageShellProps {
  title: string;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}

// Shared page scaffold: header row (title + optional actions) above the page
// grid. Page classes carry the shell styling from styles/page-shell.css.
export default function PageShell({ title, actions, children, className }: PageShellProps) {
  return (
    <div className={className ?? 'overview-page'}>
      <div className="page-header">
        <h1 className="page-title">{title}</h1>
        {actions}
      </div>
      <div className="page-grid">{children}</div>
    </div>
  );
}

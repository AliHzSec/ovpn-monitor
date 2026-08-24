import type { ReactNode } from 'react';
import { Card } from 'antd';

interface StatCardProps {
  title: ReactNode;
  value: ReactNode;
  extra?: ReactNode;
  children?: ReactNode;
}

// glass-card shell for the stat tiles: a single value with an optional footer
// (sparkline, sub-stats), on the shared card styling.
export default function StatCard({ title, value, extra, children }: StatCardProps) {
  return (
    <Card className="glass-card stat-card" variant="borderless">
      <div className="stat-card-title">{title}</div>
      <div className="stat-card-value">{value}</div>
      {extra ? <div className="stat-card-extra">{extra}</div> : null}
      {children}
    </Card>
  );
}

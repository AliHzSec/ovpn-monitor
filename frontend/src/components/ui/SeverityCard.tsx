import type { ReactNode } from 'react';

import StatCard from '@/components/ui/StatCard';

interface SeverityCardProps {
  percent: number; // 0-100
  title: ReactNode;
  value: ReactNode;
  extra?: ReactNode;
  children?: ReactNode;
}

// StatCard whose outline escalates with usage: amber at >=70%, red at >=90%.
export default function SeverityCard({
  percent,
  title,
  value,
  extra,
  children,
}: SeverityCardProps) {
  const severity = percent >= 90 ? 'critical' : percent >= 70 ? 'warn' : 'ok';
  return (
    <div className={`severity-card severity-${severity}`}>
      <StatCard title={title} value={value} extra={extra}>
        {children}
      </StatCard>
    </div>
  );
}

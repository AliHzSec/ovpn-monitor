import type { ReactNode } from 'react';

interface StatCardProps {
  title: ReactNode;
  value: ReactNode;
  extra?: ReactNode;
  children?: ReactNode;
}

// Stat tile on the shared dc card chrome (see styles/dc.css): uppercase micro
// header, one big mono value, then optional extra/footer content.
export default function StatCard({ title, value, extra, children }: StatCardProps) {
  return (
    <section className="dc-card stat-card">
      <div className="dc-card-head">{title}</div>
      <div className="stat-card-body">
        <div className="stat-card-value">{value}</div>
        {extra ? <div className="stat-card-extra">{extra}</div> : null}
        {children}
      </div>
    </section>
  );
}

// GaugeCard — resource monitor tile from the designer's mock
// (VPN Monitor.dc.html): uppercase kicker head, a 270° arc gauge with the
// percent and a Normal/Warning/Critical status inside, and a mono detail line
// below. Per-metric warn/critical bands are the mock's band() thresholds.

const BANDS = {
  cpu: [70, 90],
  ram: [70, 85],
  swap: [20, 50],
  disk: [80, 90],
} as const;

export type GaugeBandKey = keyof typeof BANDS;

// Length of the mock's 270° arc path (r = 44, viewBox 100×100).
const ARC = 179.07;

function band(key: GaugeBandKey, pct: number): { color: string; status: string } {
  const [warn, crit] = BANDS[key];
  if (pct > crit) return { color: 'var(--color-error)', status: 'Critical' };
  if (pct >= warn) return { color: 'var(--color-warning)', status: 'Warning' };
  return { color: 'var(--color-success)', status: 'Normal' };
}

interface GaugeCardProps {
  bandKey: GaugeBandKey;
  label: string;
  pct: number;
  detail: string;
}

export default function GaugeCard({ bandKey, label, pct, detail }: GaugeCardProps) {
  const { color, status } = band(bandKey, pct);
  const clamped = Math.min(100, Math.max(0, pct));

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">{label}</div>
      <div className="ovp-gauge-body">
        <div className="ovp-gauge">
          <svg viewBox="0 0 100 100" className="ovp-gauge-svg">
            <path
              d="M 18.89 81.11 A 44 44 0 1 1 81.11 81.11"
              fill="none"
              stroke="var(--dc-track)"
              strokeWidth="7"
              strokeLinecap="round"
            />
            <path
              d="M 18.89 81.11 A 44 44 0 1 1 81.11 81.11"
              fill="none"
              stroke={color}
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray={`${((ARC * clamped) / 100).toFixed(1)} ${ARC}`}
              className="ovp-gauge-fill"
            />
          </svg>
          <div className="ovp-gauge-center">
            <div className="ovp-gauge-value">
              <div className="ovp-gauge-num" style={{ color }}>
                {pct.toFixed(1)}
              </div>
              <div className="ovp-gauge-unit">%</div>
            </div>
            <div className="ovp-gauge-status" style={{ color }}>
              {status}
            </div>
          </div>
        </div>
        <div className="ovp-gauge-detail">{detail}</div>
      </div>
    </section>
  );
}

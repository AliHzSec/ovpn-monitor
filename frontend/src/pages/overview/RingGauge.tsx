import { useEffect, useRef, useState, type CSSProperties } from 'react';

// 270° arc of a r=50 circle: 2π·50·0.75 = 235.62; full circumference 314.16.
// Matches the legacy dashboard.html ring geometry exactly.
const ARC_LEN = 235.62;
const CIRCUMFERENCE = 314.16;

// Amber and red are warning states only, so the thresholds sit high enough
// that a normally-loaded server stays on the primary color.
const WARN_AT = 0.7;
const CRITICAL_AT = 0.9;

const ANIMATE_MS = 500;

export function gaugeColor(ratio: number): string {
  if (ratio < WARN_AT) return 'var(--color-primary)';
  if (ratio < CRITICAL_AT) return 'var(--color-warning)';
  return 'var(--color-error)';
}

interface RingGaugeProps {
  label: string;
  ratio: number; // 0..1
  sublabel: string;
  // swap_total === 0: center shows 'N/A', ring stays empty.
  unavailable?: boolean;
}

// One SVG ring gauge: 270° arc whose fill animates via stroke-dasharray
// transition while the center percent tweens with a rAF ease-out counter —
// a dependency-free port of the legacy setRing/animateNumber pair.
export function RingGauge({ label, ratio, sublabel, unavailable = false }: RingGaugeProps) {
  const clamped = Math.min(1, Math.max(0, ratio));
  const target = clamped * 100;
  const [display, setDisplay] = useState(0);
  const displayRef = useRef(0);

  useEffect(() => {
    const from = displayRef.current;
    const diff = target - from;
    if (Math.abs(diff) < 0.01) {
      displayRef.current = target;
      setDisplay(target);
      return;
    }
    let raf = 0;
    let start: number | null = null;
    const step = (ts: number) => {
      if (start === null) start = ts;
      const progress = Math.min((ts - start) / ANIMATE_MS, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease out, as legacy
      const current = from + diff * eased;
      displayRef.current = current;
      setDisplay(current);
      if (progress < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target]);

  const color = gaugeColor(clamped);
  const fill = ARC_LEN * clamped;

  return (
    <div className="gauge-item" style={{ '--gauge-accent': color } as CSSProperties}>
      <div className="gauge-item-label">{label}</div>
      <div className="gauge-ring-wrap">
        <svg viewBox="0 0 120 120">
          <circle
            className="ring-track"
            cx={60}
            cy={60}
            r={50}
            strokeDasharray={`${ARC_LEN} ${CIRCUMFERENCE - ARC_LEN}`}
          />
          <circle
            className="ring-fill"
            cx={60}
            cy={60}
            r={50}
            stroke={color}
            strokeDasharray={`${fill} ${CIRCUMFERENCE}`}
          />
        </svg>
        <div className="gauge-center">
          <span className="gauge-center-value">
            {unavailable ? 'N/A' : `${display.toFixed(1)}%`}
          </span>
        </div>
      </div>
      <div className="gauge-sublabel">{sublabel}</div>
    </div>
  );
}

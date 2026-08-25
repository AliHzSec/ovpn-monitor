import { useMemo } from 'react';

// SpeedCard — the mock's Overall Speed section: upload/download readouts above
// a two-series line chart with a mono y-axis. fmt/niceMax/path are the mock's
// own helpers; series arrive in bytes/sec and are converted to MB like the
// design's data.

const MB = 1048576;

function fmt(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
  return `${mb.toFixed(1)} MB`;
}

function niceMax(v: number): number {
  const steps = [0.25, 0.5, 0.75, 1, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 50];
  return steps.find((s) => s >= v * 1.05) || Math.ceil(v);
}

function path(series: number[], max: number): string {
  const w = 300;
  const h = 104;
  const n = series.length;
  if (n < 2 || max <= 0) return '';
  return series
    .map((v, i) => {
      const x = (i / (n - 1)) * w;
      const y = h - Math.min(1, v / max) * (h - 4) - 2;
      return `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');
}

interface SpeedCardProps {
  up: number[]; // bytes/sec history
  down: number[]; // bytes/sec history
  upSpeed: number; // current bytes/sec
  downSpeed: number; // current bytes/sec
}

export default function SpeedCard({ up, down, upSpeed, downSpeed }: SpeedCardProps) {
  const chart = useMemo(() => {
    const upMB = up.map((v) => v / MB);
    const downMB = down.map((v) => v / MB);
    const axisMax = niceMax(Math.max(0.05, ...upMB, ...downMB));
    return {
      axisMax,
      upPath: path(upMB, axisMax),
      downPath: path(downMB, axisMax),
      yTicks: [1, 0.75, 0.5, 0.25].map((f, i) => ({
        label: fmt(axisMax * f),
        top: `${((i / 4) * 100).toFixed(1)}%`,
      })),
    };
  }, [up, down]);

  return (
    <section className="dc-card">
      <div className="dc-card-head">Overall Speed</div>
      <div className="ovp-speed-vals">
        <div className="ovp-speed-cell">
          <div className="ovp-speed-cell-head">
            <div className="dc-dash" style={{ background: 'var(--dc-blue)' }} />
            <div className="ovp-speed-name">Upload</div>
          </div>
          <div className="ovp-speed-num">{fmt(upSpeed / MB)}/s</div>
        </div>
        <div className="ovp-speed-cell">
          <div className="ovp-speed-cell-head">
            <div className="dc-dash" style={{ background: 'var(--dc-purple)' }} />
            <div className="ovp-speed-name">Download</div>
          </div>
          <div className="ovp-speed-num">{fmt(downSpeed / MB)}/s</div>
        </div>
      </div>
      <div className="ovp-chart">
        <div className="ovp-chart-y">
          {chart.yTicks.map((t) => (
            <div key={t.top} className="ovp-chart-tick" style={{ top: t.top }}>
              {t.label}
            </div>
          ))}
        </div>
        <div className="ovp-chart-plot">
          {chart.yTicks.map((t) => (
            <div key={t.top} className="ovp-chart-grid" style={{ top: t.top }} />
          ))}
          <svg
            viewBox="0 0 300 104"
            preserveAspectRatio="none"
            className="ovp-chart-svg"
          >
            <path
              d={chart.downPath}
              fill="none"
              stroke="var(--dc-purple)"
              strokeWidth="1.4"
              vectorEffect="non-scaling-stroke"
            />
            <path
              d={chart.upPath}
              fill="none"
              stroke="var(--dc-blue)"
              strokeWidth="1.4"
              vectorEffect="non-scaling-stroke"
            />
          </svg>
        </div>
      </div>
    </section>
  );
}

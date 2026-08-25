import { formatBytes } from '@/utils/format';

// TrafficCard — the mock's Traffic section: total VPN bytes transferred as the
// headline, with a sent/received split under a hairline.

function splitBytes(bytes: number): { value: string; unit: string } {
  const s = formatBytes(bytes);
  const i = s.lastIndexOf(' ');
  return i < 0 ? { value: s, unit: '' } : { value: s.slice(0, i), unit: s.slice(i + 1) };
}

interface TrafficCardProps {
  sent: number;
  received: number;
}

export default function TrafficCard({ sent, received }: TrafficCardProps) {
  const total = splitBytes(sent + received);
  const up = splitBytes(sent);
  const down = splitBytes(received);

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">Traffic</div>
      <div className="ovp-traffic-body">
        <div className="ovp-traffic-total">
          <div className="ovp-klabel">Total transferred</div>
          <div className="ovp-traffic-total-row">
            <div className="ovp-traffic-num">{total.value}</div>
            <div className="ovp-traffic-unit">{total.unit}</div>
          </div>
        </div>
        <div className="ovp-traffic-split">
          <div className="ovp-traffic-cell">
            <div className="ovp-traffic-cell-head">
              <div className="ovp-dash" style={{ background: 'var(--dc-blue)' }} />
              <div className="ovp-klabel">Sent</div>
            </div>
            <div className="ovp-traffic-val">
              {up.value} <span className="ovp-traffic-val-unit">{up.unit}</span>
            </div>
          </div>
          <div className="ovp-vsep" />
          <div className="ovp-traffic-cell">
            <div className="ovp-traffic-cell-head">
              <div className="ovp-dash" style={{ background: 'var(--dc-dash-recv)' }} />
              <div className="ovp-klabel">Received</div>
            </div>
            <div className="ovp-traffic-val">
              {down.value} <span className="ovp-traffic-val-unit">{down.unit}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

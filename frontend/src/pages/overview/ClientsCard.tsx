// ClientsCard — the mock's Clients section: a large online count with the
// online share on the right, a green progress bar, and offline/total footer.

interface ClientsCardProps {
  online: number;
  total: number;
}

export default function ClientsCard({ online, total }: ClientsCardProps) {
  const offline = Math.max(0, total - online);
  const pct = total > 0 ? Math.round((online / total) * 100) : 0;

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">Clients</div>
      <div className="ovp-clients-body">
        <div className="ovp-clients-top">
          <div className="ovp-clients-count">
            <div className="ovp-clients-num">{online}</div>
            <div className="ovp-clients-word">online</div>
          </div>
          <div className="ovp-clients-pct">{pct}%</div>
        </div>
        <div className="ovp-clients-bar-wrap">
          <div className="ovp-clients-bar">
            <div className="ovp-clients-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="ovp-clients-foot">
            <div>{offline} offline</div>
            <div>{total} total</div>
          </div>
        </div>
      </div>
    </section>
  );
}

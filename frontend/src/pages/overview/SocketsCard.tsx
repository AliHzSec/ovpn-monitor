// SocketsCard — the mock's Connection Stats section: open-socket headline, a
// TCP/UDP share bar, and a dotted legend with live counts.

interface SocketsCardProps {
  tcp: number;
  udp: number;
}

export default function SocketsCard({ tcp, udp }: SocketsCardProps) {
  const total = tcp + udp;
  const tcpShare = total > 0 ? ((tcp / total) * 100).toFixed(1) : '0.0';
  const udpShare = total > 0 ? ((udp / total) * 100).toFixed(1) : '0.0';

  return (
    <section className="ovp-card">
      <div className="ovp-card-head">Connection Stats</div>
      <div className="ovp-socks-body">
        <div className="ovp-socks-head">
          <div className="ovp-socks-num">{total.toLocaleString()}</div>
          <div className="ovp-socks-word">Open sockets</div>
        </div>
        <div className="ovp-socks-stack">
          <div className="ovp-socks-bar">
            <div
              className="ovp-socks-seg"
              style={{ width: `${tcpShare}%`, background: 'var(--dc-blue)' }}
            />
            <div
              className="ovp-socks-seg"
              style={{ width: `${udpShare}%`, background: 'var(--dc-purple)' }}
            />
          </div>
          <div className="ovp-socks-legend">
            <div className="ovp-socks-item">
              <div className="ovp-socks-dot" style={{ background: 'var(--dc-blue)' }} />
              <div className="ovp-socks-name">TCP</div>
              <div className="ovp-socks-count">{tcp.toLocaleString()}</div>
            </div>
            <div className="ovp-socks-item">
              <div className="ovp-socks-dot" style={{ background: 'var(--dc-purple)' }} />
              <div className="ovp-socks-name">UDP</div>
              <div className="ovp-socks-count">{udp.toLocaleString()}</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

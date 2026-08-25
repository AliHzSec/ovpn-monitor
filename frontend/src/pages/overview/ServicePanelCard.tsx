import { useState } from 'react';
import { Modal, message } from 'antd';

import { post } from '@/api/http';
import { useServerStats } from '@/api/queries/useServerStats';
import { formatUptime } from '@/utils/format';
import type { ServiceActionResult } from '@/models/types';

type ServiceName = 'openvpn' | 'wireguard';
type ServiceAction = 'start' | 'stop' | 'restart';

interface ServicePanelCardProps {
  service: ServiceName;
  title: string;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

// OpenVPN/WireGuard card from the designer's mock: status dot + name + state
// label in the head, uptime below, and bordered Restart/Stop (or Start)
// action buttons. Action plumbing (confirm modal, freeze-while-pending, WS
// reconcile) is the same logic the previous antd-button ServiceCard ran.
export default function ServicePanelCard({ service, title }: ServicePanelCardProps) {
  const { data, dataUpdatedAt } = useServerStats();
  const [pendingAction, setPendingAction] = useState<ServiceAction | null>(null);
  // Freeze pins the displayed status to the query snapshot that was current
  // when the action started; the next WS push (a newer dataUpdatedAt) hands
  // rendering back to the live query data.
  const [freeze, setFreeze] = useState<{ at: number; status: boolean } | null>(null);

  const uptime = service === 'openvpn' ? (data?.ovpn_uptime ?? 0) : (data?.wireguard_uptime ?? 0);
  const liveRunning = uptime > 0;
  const running = freeze !== null && freeze.at === dataUpdatedAt ? freeze.status : liveRunning;

  const runAction = async (action: ServiceAction) => {
    setPendingAction(action);
    setFreeze({ at: dataUpdatedAt, status: running });
    try {
      const result = await post<ServiceActionResult>(`/api/service/${service}/${action}`);
      if (result && typeof result.active === 'boolean') {
        // Reconcile immediately; the next WS push takes over from here.
        setFreeze({ at: dataUpdatedAt, status: result.active });
      }
      if (!result || result.ok === false) {
        message.error(`Could not ${action} ${service}`);
      }
    } catch {
      message.error(`Could not ${action} ${service}`);
    } finally {
      setPendingAction(null);
    }
  };

  const confirmAction = (action: ServiceAction) => {
    Modal.confirm({
      title: `${capitalize(action)} ${title}?`,
      content: 'Active VPN connections will be affected.',
      okText: capitalize(action),
      cancelText: 'Cancel',
      okButtonProps: action === 'stop' ? { danger: true } : undefined,
      onOk: () => runAction(action),
    });
  };

  const pending = pendingAction !== null;

  return (
    <section className="dc-card">
      <div className="ovp-svc-head">
        <div
          className="ovp-svc-dot"
          style={{ background: running ? 'var(--color-success)' : 'var(--color-error)' }}
        />
        <div className="dc-card-head-text">{title}</div>
        <div
          className="ovp-svc-state"
          style={{ color: running ? 'var(--color-success)' : 'var(--color-error)' }}
        >
          {running ? 'Running' : 'Stopped'}
        </div>
      </div>
      <div className="ovp-svc-body">
        <div className="ovp-svc-uptime">
          <div className="dc-klabel">Uptime</div>
          <div className="ovp-svc-uptime-val">{running ? formatUptime(uptime) : '—'}</div>
        </div>
        {running ? (
          <div className="ovp-svc-actions">
            <div
              className={`ovp-svc-btn ovp-svc-btn-restart${pending ? ' ovp-svc-btn-pending' : ''}`}
              onClick={pending ? undefined : () => confirmAction('restart')}
            >
              {pendingAction === 'restart' ? 'Restarting…' : 'Restart'}
            </div>
            <div
              className={`ovp-svc-btn ovp-svc-btn-stop${pending ? ' ovp-svc-btn-pending' : ''}`}
              onClick={pending ? undefined : () => confirmAction('stop')}
            >
              {pendingAction === 'stop' ? 'Stopping…' : 'Stop'}
            </div>
          </div>
        ) : (
          <div
            className={`ovp-svc-btn ovp-svc-btn-start${pending ? ' ovp-svc-btn-pending' : ''}`}
            onClick={pending ? undefined : () => confirmAction('start')}
          >
            {pendingAction === 'start' ? 'Starting…' : 'Start'}
          </div>
        )}
      </div>
    </section>
  );
}

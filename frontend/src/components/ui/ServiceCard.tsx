import { useState } from 'react';
import { Button, Card, Modal, message, theme } from 'antd';
import {
  CaretRightOutlined,
  GlobalOutlined,
  PoweroffOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';

import { post } from '@/api/http';
import { useServerStats } from '@/api/queries/useServerStats';
import type { ServiceActionResult } from '@/models/types';

import './ServiceCard.css';

type ServiceName = 'openvpn' | 'wireguard';
type ServiceAction = 'start' | 'stop' | 'restart';

interface ServiceCardProps {
  service: ServiceName;
  title: string;
}

const serviceIcon: Record<ServiceName, React.ReactNode> = {
  openvpn: <SafetyCertificateOutlined />,
  wireguard: <GlobalOutlined />,
};

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

// OpenVPN/WireGuard service control card. Visual treatment mirrors 3x-ui's
// OverviewActionBar service controls: a state pill with a pulsing dot
// (.ov-state) plus an outlined-primary Restart and a text Stop button.
// Status is frozen while an action is in flight, mirroring the legacy
// servicePending behavior.
export default function ServiceCard({ service, title }: ServiceCardProps) {
  const { token } = theme.useToken();
  const { data, dataUpdatedAt } = useServerStats();
  const [pendingAction, setPendingAction] = useState<ServiceAction | null>(null);
  // Freeze pins the displayed status to the query snapshot that was current
  // when the action started; the next WS push (a newer dataUpdatedAt) hands
  // rendering back to the live query data.
  const [freeze, setFreeze] = useState<{ at: number; status: boolean } | null>(null);

  const liveRunning =
    service === 'openvpn' ? (data?.ovpn_uptime ?? 0) > 0 : (data?.wireguard_uptime ?? 0) > 0;
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
    <Card hoverable className="ov-service" styles={{ body: { padding: 0 } }}>
      <div className="ov-tile-head ov-service-head">
        <span className="ov-tile-icon">{serviceIcon[service]}</span>
        <span className="ov-kicker">{title}</span>
        <span className="ov-state" data-state={running ? 'running' : 'stop'}>
          <span
            className="ov-state-dot"
            style={{ color: running ? token.colorSuccess : token.colorTextTertiary }}
          />
          <span>{running ? 'Running' : 'Stopped'}</span>
        </span>
      </div>
      <div className="ov-service-actions">
        {running ? (
          <>
            <Button
              color="primary"
              variant="outlined"
              icon={<ReloadOutlined />}
              disabled={pending}
              loading={pendingAction === 'restart'}
              onClick={() => confirmAction('restart')}
            >
              Restart
            </Button>
            <Button
              type="text"
              icon={<PoweroffOutlined />}
              disabled={pending}
              loading={pendingAction === 'stop'}
              onClick={() => confirmAction('stop')}
            >
              Stop
            </Button>
          </>
        ) : (
          <Button
            color="primary"
            variant="outlined"
            icon={<CaretRightOutlined />}
            disabled={pending}
            loading={pendingAction === 'start'}
            onClick={() => confirmAction('start')}
          >
            Start
          </Button>
        )}
      </div>
    </Card>
  );
}

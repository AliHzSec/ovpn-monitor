import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { Alert, Button, Card, Empty, Input, Spin } from 'antd';
import {
  GlobalOutlined,
  HddOutlined,
  PhoneOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm } from 'react-hook-form';
import type { Resolver } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

import { postForm } from '@/api/http';
import { useSettings } from '@/api/queries/useSettings';
import { keys } from '@/api/queryKeys';
import PageShell from '@/components/ui/PageShell';

import IPv6Card from './IPv6Card';

import './SettingsPage.css';

// ── Schemas ────────────────────────────────────────────────────────────────
// One zod schema per section, matching the key allow-lists in the Go
// handler (pages.go settingsSections). Every field is an optional string —
// the old server-rendered form had no validation, so neither does this one.
const generalSchema = z.object({
  addr: z.string().optional(),
  admin_user: z.string().optional(),
  admin_pass: z.string().optional(),
  poll_interval: z.string().optional(),
});

const openvpnSchema = z.object({
  openvpn_status_log: z.string().optional(),
  openvpn_cert_dir: z.string().optional(),
  openvpn_ipp_file: z.string().optional(),
  openvpn_server_config: z.string().optional(),
});

const wireguardSchema = z.object({
  wireguard_conf: z.string().optional(),
  wireguard_interface: z.string().optional(),
  wireguard_handshake_timeout: z.string().optional(),
});

const domainsSchema = z.object({
  sniffer_ifaces: z.string().optional(),
  sniffer_wg_conf: z.string().optional(),
  sniffer_snaplen: z.string().optional(),
  sniffer_workers: z.string().optional(),
  sniffer_queue: z.string().optional(),
  sniffer_flush: z.string().optional(),
  sniffer_dedup: z.string().optional(),
});

type SettingsFormValues = z.infer<typeof generalSchema> &
  z.infer<typeof openvpnSchema> &
  z.infer<typeof wireguardSchema> &
  z.infer<typeof domainsSchema>;

type FieldName = keyof SettingsFormValues;

// ── Section / field definitions ────────────────────────────────────────────
// Labels, descriptions, warnings and placeholders are copied verbatim from
// templates/settings.html.
interface SettingsField {
  name: FieldName;
  label: string;
  placeholder?: string;
  /** Tertiary note rendered under the label. */
  description?: string;
  /** Amber note rendered under the label. */
  warning?: string;
  password?: boolean;
  autoComplete?: string;
}

interface SettingsSection {
  key: string;
  title: string;
  note: string;
  icon: React.ReactNode;
  schema:
    | typeof generalSchema
    | typeof openvpnSchema
    | typeof wireguardSchema
    | typeof domainsSchema;
  fields: SettingsField[];
}

const SECTIONS: Record<string, SettingsSection> = {
  general: {
    key: 'general',
    title: 'General',
    note: 'Panel address, administrator credentials and refresh cadence.',
    icon: <HddOutlined />,
    schema: generalSchema,
    fields: [
      {
        name: 'addr',
        label: 'Listening Address',
        placeholder: '0.0.0.0:80',
        warning: 'Changing this restarts the service',
      },
      {
        name: 'admin_user',
        label: 'Admin Username',
        placeholder: 'admin',
        autoComplete: 'username',
      },
      {
        name: 'admin_pass',
        label: 'Admin Password',
        placeholder: 'Leave empty to keep the current password',
        password: true,
        autoComplete: 'new-password',
      },
      {
        name: 'poll_interval',
        label: 'Poll Interval',
        placeholder: '10s',
        description: 'Status refresh cadence for OpenVPN and WireGuard',
      },
    ],
  },
  openvpn: {
    key: 'openvpn',
    title: 'OpenVPN',
    note: 'Where the panel reads OpenVPN status, certificates and client IPs.',
    icon: <PhoneOutlined />,
    schema: openvpnSchema,
    fields: [
      {
        name: 'openvpn_status_log',
        label: 'Status Log Path',
        placeholder: '/var/log/openvpn/status.log',
      },
      {
        name: 'openvpn_cert_dir',
        label: 'Certificate Directory',
        placeholder: '/etc/openvpn/server/easy-rsa/pki/issued',
      },
      {
        name: 'openvpn_ipp_file',
        label: 'IPP File Path',
        placeholder: '/etc/openvpn/server/ipp.txt',
      },
      {
        name: 'openvpn_server_config',
        label: 'Server Config File',
        placeholder: '/etc/openvpn/server/server.conf',
      },
    ],
  },
  wireguard: {
    key: 'wireguard',
    title: 'WireGuard',
    note: 'Peer configuration and the interface the poller reads counters from.',
    icon: <SafetyOutlined />,
    schema: wireguardSchema,
    fields: [
      {
        name: 'wireguard_conf',
        label: 'Config File',
        placeholder: '/etc/wireguard/wg0.conf',
        description: 'Empty disables WireGuard monitoring',
      },
      { name: 'wireguard_interface', label: 'Interface', placeholder: 'wg0' },
      {
        name: 'wireguard_handshake_timeout',
        label: 'Handshake Timeout',
        placeholder: '180s',
        description: 'How long after the last handshake a peer counts as online',
      },
    ],
  },
  domains: {
    key: 'domains',
    title: 'Domain Tracking',
    note: 'Passive capture of TLS SNI and HTTP Host names on the tunnel interfaces.',
    icon: <GlobalOutlined />,
    schema: domainsSchema,
    fields: [
      {
        name: 'sniffer_ifaces',
        label: 'Capture Interfaces',
        placeholder: 'tun0,wg0',
        description: 'Comma-separated',
      },
      {
        name: 'sniffer_wg_conf',
        label: 'WireGuard Config File',
        placeholder: '/etc/wireguard/wg0.conf',
        description: 'Peer to name mapping source',
      },
      { name: 'sniffer_snaplen', label: 'Snap Length (bytes)', placeholder: '1600' },
      { name: 'sniffer_workers', label: 'Parse Workers (0 = auto)', placeholder: '0' },
      {
        name: 'sniffer_queue',
        label: 'Parse Queue Size',
        placeholder: '4096',
        description: 'Packets beyond this are dropped rather than queued',
      },
      { name: 'sniffer_flush', label: 'Flush Interval', placeholder: '2m' },
      { name: 'sniffer_dedup', label: 'Dedup Window', placeholder: '60s' },
    ],
  },
};

interface SaveResponse {
  ok: boolean;
  restarting: boolean;
}

type Flash = { type: 'success' | 'warning' | 'error'; message: string } | null;

// Settings page, one sub-page per section (/settings/:section). Values load
// from GET /api/settings/{section}; saving POSTs the section's fields
// form-urlencoded to /settings/{section} with Accept: application/json, which
// the Go handler answers with {"ok":true,"restarting":...} instead of the
// HTML 303 + flash redirect.
export function SettingsPage() {
  const { section: sectionParam = '' } = useParams();
  const section = SECTIONS[sectionParam];
  const queryClient = useQueryClient();
  const [flash, setFlash] = useState<Flash>(null);

  const settingsQuery = useSettings(section ? section.key : '');

  const { control, handleSubmit, reset } = useForm<SettingsFormValues>({
    resolver: section
      ? (zodResolver(section.schema) as Resolver<SettingsFormValues>)
      : undefined,
    defaultValues: {},
  });

  // (Re)populate the form whenever the section or its loaded values change.
  // admin_pass is write-only: it always loads empty, and the server keeps the
  // current password when it stays empty.
  useEffect(() => {
    setFlash(null);
    if (settingsQuery.data) {
      reset({ ...settingsQuery.data, admin_pass: '' });
    }
  }, [settingsQuery.data, reset, sectionParam]);

  const saveMutation = useMutation({
    mutationFn: (values: SettingsFormValues) => {
      if (!section) return Promise.reject(new Error('unknown section'));
      // Submit exactly the fields this section owns — never a key from
      // another section — with undefined normalized to '' (a present-but-
      // empty field, same as the old HTML form submitting empty inputs).
      const body: Record<string, string> = {};
      section.fields.forEach((field) => {
        body[field.name] = values[field.name] ?? '';
      });
      return postForm<SaveResponse>(`/settings/${section.key}`, body, {
        headers: { Accept: 'application/json' },
      });
    },
    onSuccess: (res) => {
      if (!section) return;
      if (res.restarting) {
        setFlash({
          type: 'warning',
          message:
            'Settings saved. Listening address changed — the service is restarting…',
        });
        return;
      }
      setFlash({ type: 'success', message: `${section.title} settings saved successfully.` });
      // The password was consumed by the save; clear the write-only field.
      reset({ ...settingsQuery.data, admin_pass: '' });
      queryClient.invalidateQueries({ queryKey: keys.settings(section.key) });
    },
    onError: () => {
      setFlash({ type: 'error', message: 'Failed to save settings.' });
    },
  });

  if (!section) {
    return (
      <PageShell title="Panel Settings" className="settings-page">
        <Card className="settings-card">
          <Empty description="Unknown settings section (404)" />
        </Card>
      </PageShell>
    );
  }

  // While the restart banner is up the process is about to exit (systemd
  // restarts it); the form locks, mirroring the old page dying after save.
  const restarting = flash?.type === 'warning';

  return (
    <PageShell title={`Panel Settings — ${section.title}`} className="settings-page">
      {flash ? (
        <Alert
          type={flash.type}
          message={flash.message}
          showIcon
          className="settings-flash"
        />
      ) : null}

      <div className="settings-section-head">
        <div className="settings-section-head-title">
          {section.icon}
          {section.title}
        </div>
        <div className="settings-section-head-note">{section.note}</div>
      </div>

      {settingsQuery.isLoading ? (
        <div className="settings-loading">
          <Spin />
        </div>
      ) : settingsQuery.isError ? (
        <Alert type="error" message="Failed to load settings." showIcon />
      ) : (
        <form onSubmit={handleSubmit((values) => saveMutation.mutate(values))}>
          <Card className="settings-card">
            {section.fields.map((field) => (
              <div className="settings-field-row" key={field.name}>
                <div className="settings-field-label-wrap">
                  <label className="settings-field-label" htmlFor={field.name}>
                    {field.label}
                  </label>
                  {field.warning ? (
                    <div className="settings-field-note">{field.warning}</div>
                  ) : null}
                  {field.description ? (
                    <div className="settings-field-desc">{field.description}</div>
                  ) : null}
                </div>
                <div className="settings-field-input-wrap">
                  <Controller
                    name={field.name}
                    control={control}
                    render={({ field: controllerField }) =>
                      field.password ? (
                        <Input.Password
                          {...controllerField}
                          value={controllerField.value ?? ''}
                          id={field.name}
                          placeholder={field.placeholder}
                          autoComplete={field.autoComplete}
                          visibilityToggle
                          disabled={restarting}
                        />
                      ) : (
                        <Input
                          {...controllerField}
                          value={controllerField.value ?? ''}
                          id={field.name}
                          placeholder={field.placeholder}
                          autoComplete={field.autoComplete}
                          disabled={restarting}
                        />
                      )
                    }
                  />
                </div>
              </div>
            ))}
          </Card>

          <div className="settings-form-footer">
            <Button
              type="primary"
              htmlType="submit"
              loading={saveMutation.isPending}
              disabled={restarting}
            >
              Save Settings
            </Button>
            <span className="settings-form-footer-note">
              These settings apply after a service restart.
            </span>
          </div>
        </form>
      )}

      {(section.key === 'wireguard' || section.key === 'openvpn') && (
        <IPv6Card service={section.key} title={section.title} />
      )}
    </PageShell>
  );
}

export default SettingsPage;

import { Badge } from 'antd';

interface LiveBadgeProps {
  live: boolean;
  liveText?: string;
  offlineText?: string;
}

// Small status pill: green pulse while the live channel is up, grey when the
// UI is on the polling fallback.
export default function LiveBadge({
  live,
  liveText = 'Live',
  offlineText = 'Polling',
}: LiveBadgeProps) {
  return (
    <Badge
      status={live ? 'processing' : 'default'}
      color={live ? '#52c41a' : undefined}
      text={live ? liveText : offlineText}
    />
  );
}

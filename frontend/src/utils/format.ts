// utils/format.ts — shared display formatting. relativeTime is the ONE
// relative-time implementation for the whole app ("Never" / "just now" /
// "N minutes ago" / "N hours N minutes ago" / "N days N hours N minutes ago").

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let value = bytes;
  let unit = 'B';
  for (const u of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = u;
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${unit}`;
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
  return parts.join(' ');
}

export function relativeTime(epochSeconds: number): string {
  if (!Number.isFinite(epochSeconds) || epochSeconds <= 0) return 'Never';
  const diff = Math.floor(Date.now() / 1000) - epochSeconds;
  if (diff < 60) return 'just now';
  const minutes = Math.floor(diff / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  if (hours < 24) {
    const parts = [`${hours} hour${hours === 1 ? '' : 's'}`];
    if (remMinutes > 0) parts.push(`${remMinutes} minute${remMinutes === 1 ? '' : 's'}`);
    return `${parts.join(' ')} ago`;
  }
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  const parts = [`${days} day${days === 1 ? '' : 's'}`];
  if (remHours > 0) parts.push(`${remHours} hour${remHours === 1 ? '' : 's'}`);
  if (remMinutes > 0) parts.push(`${remMinutes} minute${remMinutes === 1 ? '' : 's'}`);
  return `${parts.join(' ')} ago`;
}

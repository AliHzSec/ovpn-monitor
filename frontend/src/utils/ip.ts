// utils/ip.ts — public/private IP classification for the "server addresses"
// display. IPv4 ranges are compared numerically to avoid string-prefix traps
// (e.g. "172.20.x" vs "172.3.x").

function parseIPv4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255 || (part.length > 1 && part.startsWith('0'))) return null;
    value = value * 256 + n;
  }
  return value;
}

function inRange(value: number, base: string, prefixBits: number): boolean {
  const baseValue = parseIPv4(base);
  if (baseValue === null) return false;
  const mask = prefixBits === 0 ? 0 : (~0 << (32 - prefixBits)) >>> 0;
  return (value & mask) === (baseValue & mask);
}

// Excludes 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 0/8
// and 224/4+ (multicast, reserved, broadcast).
const PRIVATE_V4: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['224.0.0.0', 4],
];

export function isPublicIPv4(ip: string): boolean {
  const value = parseIPv4(ip);
  if (value === null) return false;
  return !PRIVATE_V4.some(([base, bits]) => inRange(value, base, bits));
}

// Global unicast = 2000::/3, i.e. the first hextet in 0x2000..0x3fff.
export function isPublicIPv6(ip: string): boolean {
  const first = ip.split(':')[0];
  if (!first || !/^[0-9a-fA-F]{1,4}$/.test(first)) return false;
  const hextet = parseInt(first, 16);
  return hextet >= 0x2000 && hextet <= 0x3fff;
}

export function pickPublicIPv4(ips: string[]): string | null {
  return ips.find(isPublicIPv4) ?? null;
}

export function pickPublicIPv6(ipv6s: string[]): string | null {
  return ipv6s.find(isPublicIPv6) ?? null;
}

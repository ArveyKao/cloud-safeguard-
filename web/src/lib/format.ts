import type { Severity } from '../api/types'

export function cx(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ')
}

/** "900" → "15m", "3600" → "1h", "90" → "1m 30s", "45" → "45s". */
export function formatTTL(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  if (seconds === 0) return 'TTL default'
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`
  if (minutes > 0) return secs > 0 ? `${minutes}m ${secs}s` : `${minutes}m`
  return `${secs}s`
}

/** Uptime-style duration: "3d 4h", "2h 14m", "42s". */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = Math.floor(seconds % 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`
  if (minutes > 0) return `${minutes}m ${secs}s`
  return `${secs}s`
}

/** Countdown clock for lease expiry, e.g. "04:32", "1h 04m". */
export function formatCountdown(msRemaining: number): string {
  if (msRemaining <= 0) return 'expired'
  const totalSeconds = Math.ceil(msRemaining / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
}

export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never'
  const then = Date.parse(iso)
  if (Number.isNaN(then)) return '—'
  const deltaSeconds = Math.round((now - then) / 1000)
  if (deltaSeconds < 5) return 'just now'
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`
  const minutes = Math.floor(deltaSeconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  return formatDate(iso)
}

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

const dateFormatter = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
})

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const value = Date.parse(iso)
  if (Number.isNaN(value)) return '—'
  return dateFormatter.format(value)
}

/** "Nov 8, 05:31:22" in the operator's local timezone. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const value = Date.parse(iso)
  if (Number.isNaN(value)) return '—'
  return dateTimeFormatter.format(value)
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const value = Date.parse(iso)
  if (Number.isNaN(value)) return '—'
  return timeFormatter.format(value)
}

export function truncateMiddle(value: string, max = 22): string {
  if (!value) return ''
  if (value.length <= max) return value
  const head = Math.ceil((max - 1) / 2)
  const tail = Math.floor((max - 1) / 2)
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`
}

export function titleCase(value: string): string {
  if (!value) return ''
  return value
    .split(/[_\s-]+/)
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(' ')
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`)
}

export function severityRank(severity: Severity | string): number {
  switch (severity) {
    case 'critical':
      return 3
    case 'warning':
      return 2
    default:
      return 1
  }
}

/** Policy documents arrive as JSON strings in `policy_template`. */
export function tryParseJson(source: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(source) }
  } catch {
    return { ok: false }
  }
}

export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

/**
 * Parse a human duration ("15m", "1h30m", "900") into seconds.
 * Returns null for invalid input. Matches the CLI's duration flag grammar
 * (docs/CONTRACT.md §9): integer seconds or one `h`/`m`/`s` unit.
 */
export function parseDurationInput(raw: string): number | null {
  const value = raw.trim().toLowerCase()
  if (value === '') return null
  if (/^\d+$/.test(value)) return Number(value)
  const match = /^(\d+)(s|m|h)$/.exec(value)
  if (!match) return null
  const amount = Number(match[1])
  switch (match[2]) {
    case 's':
      return amount
    case 'm':
      return amount * 60
    case 'h':
      return amount * 3600
    default:
      return null
  }
}

/** Format seconds in a form suitable for a duration input ("15m", "1h"). */
export function toDurationInput(seconds: number): string {
  return formatTTL(seconds).replace(' ', '')
}

/** Bytes for bundle-free static assets? Not used; kept for audit metadata safety. */
export function relativeTimeFromMs(ms: number, now: number = Date.now()): string {
  return formatRelative(new Date(now - ms).toISOString(), now)
}

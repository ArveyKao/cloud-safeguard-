/** Inline SVG icon set — no icon fonts, no external assets (offline-safe). */
import type { SVGProps } from 'react'

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, 'children'> {
  size?: number
}

function base(props: IconProps) {
  const { size = 18, ...rest } = props
  return {
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    focusable: false,
    ...rest,
  }
}

export function IconShield(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 3 20 6.2v6.1c0 4.6-3.3 7.8-8 9.2-4.7-1.4-8-4.6-8-9.2V6.2L12 3Z" />
      <path d="m8.7 11.9 2.3 2.3 4.3-4.5" />
    </svg>
  )
}

export function IconOverview(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.6" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.6" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.6" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.6" />
    </svg>
  )
}

export function IconAgents(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="4" y="7.5" width="16" height="11" rx="3" />
      <path d="M12 3.5v4" />
      <circle cx="9" cy="12.5" r="1" fill="currentColor" stroke="none" />
      <circle cx="15" cy="12.5" r="1" fill="currentColor" stroke="none" />
      <path d="M9.5 15.5h5" />
    </svg>
  )
}

export function IconCapabilities(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m12 3.2 8.5 4.3-8.5 4.3-8.5-4.3L12 3.2Z" />
      <path d="m3.5 12.3 8.5 4.3 8.5-4.3" />
      <path d="m3.5 16.9 8.5 4.3 8.5-4.3" />
    </svg>
  )
}

export function IconLeases(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="12" cy="12.5" r="8" />
      <path d="M12 8v4.8l3.2 1.9" />
      <path d="M9 2.5h6" />
    </svg>
  )
}

export function IconProviders(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M7 18.5h9.5a3.75 3.75 0 0 0 .7-7.43A5.5 5.5 0 0 0 6.4 9.2 4.65 4.65 0 0 0 7 18.5Z" />
    </svg>
  )
}

export function IconAudit(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M6 3.5h9.5L19 7v13.5H6a1.5 1.5 0 0 1-1.5-1.5V5A1.5 1.5 0 0 1 6 3.5Z" />
      <path d="M8.5 9h6M8.5 12.5h6M8.5 16h3.5" />
    </svg>
  )
}

export function IconSettings(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M4 7h9m4 0h3M4 17h3m4 0h9" />
      <circle cx="15.5" cy="7" r="2.2" />
      <circle cx="9" cy="17" r="2.2" />
    </svg>
  )
}

export function IconRefresh(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M20 11.2A8 8 0 0 0 5.7 6L4 8" />
      <path d="M4 3.8V8h4.2" />
      <path d="M4 12.8A8 8 0 0 0 18.3 18l1.7-2" />
      <path d="M20 20.2V16h-4.2" />
    </svg>
  )
}

export function IconLogout(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M14 4.5h3.5A1.5 1.5 0 0 1 19 6v12a1.5 1.5 0 0 1-1.5 1.5H14" />
      <path d="M10 8.5 6.5 12l3.5 3.5M6.5 12H15" />
    </svg>
  )
}

export function IconPlus(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  )
}

export function IconX(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m6 6 12 12M18 6 6 18" />
    </svg>
  )
}

export function IconCheck(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m4.5 12.5 5 5 10-11" />
    </svg>
  )
}

export function IconCopy(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 5.5A1.5 1.5 0 0 0 13.5 4h-8A1.5 1.5 0 0 0 4 5.5v8A1.5 1.5 0 0 0 5.5 15" />
    </svg>
  )
}

export function IconChevronDown(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  )
}

export function IconChevronRight(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  )
}

export function IconSearch(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </svg>
  )
}

export function IconAlert(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 3.8 21.2 20H2.8L12 3.8Z" />
      <path d="M12 9.5v4.6M12 17.3v.2" />
    </svg>
  )
}

export function IconInfo(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5.2M12 7.9v.2" />
    </svg>
  )
}

export function IconRotate(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M20 12a8 8 0 1 1-2.34-5.66" />
      <path d="M20 4.5V9h-4.5" />
    </svg>
  )
}

export function IconPlay(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M8 5.5 18.5 12 8 18.5v-13Z" />
    </svg>
  )
}

export function IconBan(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m6 18 12-12" />
    </svg>
  )
}

export function IconPause(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M9 5.5v13M15 5.5v13" />
    </svg>
  )
}

export function IconEdit(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3Z" />
      <path d="m14.5 6.5 3 3" />
    </svg>
  )
}

export function IconExternal(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M13 5h6v6M19 5l-8.5 8.5" />
      <path d="M18 14v4.5A1.5 1.5 0 0 1 16.5 20h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10" />
    </svg>
  )
}

export function IconEye(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M2.8 12S6 5.8 12 5.8 21.2 12 21.2 12 18 18.2 12 18.2 2.8 12 2.8 12Z" />
      <circle cx="12" cy="12" r="2.8" />
    </svg>
  )
}

export function IconEyeOff(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m4 4 16 16" />
      <path d="M9.5 6.3A9.6 9.6 0 0 1 12 6c6 0 9.2 6 9.2 6a16 16 0 0 1-2.8 3.4M6.2 8.2A15.4 15.4 0 0 0 2.8 12S6 18 12 18a9.4 9.4 0 0 0 3.4-.6" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    </svg>
  )
}

export function IconFilter(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M3.5 6h17M6.5 12h11M10 18h4" />
    </svg>
  )
}

export function IconLock(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
      <path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7" />
      <path d="M12 14.5v2" />
    </svg>
  )
}

export function IconKey(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="8" cy="8" r="4.2" />
      <path d="m11 11 8.5 8.5M16.5 16.5l2.5-2.5M19.8 19.8l2.2-2.2" />
    </svg>
  )
}

export function IconActivity(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M3 12.5h4l2.4-6.4 4.2 12 2.4-5.6h5" />
    </svg>
  )
}

export function IconClock(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5v5l3.2 1.9" />
    </svg>
  )
}

export function IconTerminal(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" />
      <path d="m7.5 9.5 3 2.5-3 2.5M12.5 15h4" />
    </svg>
  )
}

export function IconChevronUp(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m6 15 6-6 6 6" />
    </svg>
  )
}

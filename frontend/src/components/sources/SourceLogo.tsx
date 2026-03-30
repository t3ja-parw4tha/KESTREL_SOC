// ─────────────────────────────────────────────────────────────────────────────
// SourceLogo — brand-accurate inline SVG logos for all 29 Kestrel integrations
// Colors and shapes based on official brand guidelines / press kits.
// ─────────────────────────────────────────────────────────────────────────────

import { Database } from 'lucide-react'
import { cn } from '@/utils/cn'

export interface SourceLogoProps {
  sourceId: string
  size?: number
  className?: string
}

// ── Microsoft Sentinel ────────────────────────────────────────────────────────
// Azure blue shield with a white radar-eye symbol — Sentinel's core identity.
function SentinelLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <defs>
        <linearGradient id="sent-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#2e74d5" />
          <stop offset="100%" stopColor="#0052aa" />
        </linearGradient>
      </defs>
      {/* Shield */}
      <path
        d={`M ${cx} ${cy - s*0.42} L ${cx + s*0.37} ${cy - s*0.21} L ${cx + s*0.37} ${cy + s*0.1} C ${cx + s*0.37} ${cy + s*0.32} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.37} ${cy + s*0.32} ${cx - s*0.37} ${cy + s*0.1} L ${cx - s*0.37} ${cy - s*0.21} Z`}
        fill="url(#sent-g)"
      />
      {/* Radar arcs */}
      <circle cx={cx} cy={cy - s*0.01} r={s*0.22} fill="none" stroke="white" strokeWidth={s*0.055} strokeOpacity="0.45" />
      <circle cx={cx} cy={cy - s*0.01} r={s*0.13} fill="none" stroke="white" strokeWidth={s*0.055} strokeOpacity="0.7" />
      {/* Center dot */}
      <circle cx={cx} cy={cy - s*0.01} r={s*0.045} fill="white" />
    </svg>
  )
}

// ── Azure Active Directory / Entra ID ─────────────────────────────────────────
// Blue-purple circle with white person silhouette.
function EntraIdLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <defs>
        <linearGradient id="entra-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#7b83eb" />
          <stop offset="100%" stopColor="#0f6cbd" />
        </linearGradient>
      </defs>
      <circle cx={cx} cy={cy} r={s*0.46} fill="url(#entra-g)" />
      {/* Head */}
      <circle cx={cx} cy={cy - s*0.13} r={s*0.11} fill="white" />
      {/* Shoulders arc */}
      <path
        d={`M ${cx - s*0.22} ${cy + s*0.35} C ${cx - s*0.22} ${cy + s*0.07} ${cx + s*0.22} ${cy + s*0.07} ${cx + s*0.22} ${cy + s*0.35}`}
        fill="white"
      />
    </svg>
  )
}

// ── Microsoft Defender for Cloud ──────────────────────────────────────────────
// Azure blue shield with a white cloud inside.
function DefenderCloudLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx} ${cy - s*0.42} L ${cx + s*0.37} ${cy - s*0.21} L ${cx + s*0.37} ${cy + s*0.1} C ${cx + s*0.37} ${cy + s*0.32} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.37} ${cy + s*0.32} ${cx - s*0.37} ${cy + s*0.1} L ${cx - s*0.37} ${cy - s*0.21} Z`}
        fill="#0078d4"
      />
      {/* Cloud bumps */}
      <circle cx={cx - s*0.1} cy={cy + s*0.02} r={s*0.1} fill="white" />
      <circle cx={cx + s*0.04} cy={cy - s*0.04} r={s*0.13} fill="white" />
      <circle cx={cx + s*0.16} cy={cy + s*0.03} r={s*0.09} fill="white" />
      {/* Cloud base */}
      <rect x={cx - s*0.19} y={cy + s*0.03} width={s*0.35} height={s*0.09} rx={s*0.04} fill="white" />
    </svg>
  )
}

// ── Microsoft 365 Defender ────────────────────────────────────────────────────
// Uses the official Microsoft four-square mark.
function MicrosoftFourSquare({ size: s }: { size: number }) {
  const sq = s * 0.41, gap = s * 0.05
  const ox = s / 2 - sq - gap / 2, oy = s / 2 - sq - gap / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={ox}         y={oy}         width={sq} height={sq} fill="#f25022" />
      <rect x={ox+sq+gap}  y={oy}         width={sq} height={sq} fill="#7fba00" />
      <rect x={ox}         y={oy+sq+gap}  width={sq} height={sq} fill="#00a4ef" />
      <rect x={ox+sq+gap}  y={oy+sq+gap}  width={sq} height={sq} fill="#ffb900" />
    </svg>
  )
}

// ── Windows Event Log ─────────────────────────────────────────────────────────
// Windows 11 four-pane logo in Windows blue.
function WindowsLogo({ size: s }: { size: number }) {
  const sq = s * 0.39, gap = s * 0.055
  const ox = s / 2 - sq - gap / 2, oy = s / 2 - sq - gap / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={ox}        y={oy}        width={sq} height={sq} rx={s*0.03} fill="#0078d4" />
      <rect x={ox+sq+gap} y={oy}        width={sq} height={sq} rx={s*0.03} fill="#0078d4" />
      <rect x={ox}        y={oy+sq+gap} width={sq} height={sq} rx={s*0.03} fill="#0078d4" />
      <rect x={ox+sq+gap} y={oy+sq+gap} width={sq} height={sq} rx={s*0.03} fill="#0078d4" />
    </svg>
  )
}

// ── AWS GuardDuty ─────────────────────────────────────────────────────────────
// AWS orange shield with a white detection eye.
function GuardDutyLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx} ${cy - s*0.42} L ${cx + s*0.36} ${cy - s*0.21} L ${cx + s*0.36} ${cy + s*0.08} C ${cx + s*0.36} ${cy + s*0.31} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.36} ${cy + s*0.31} ${cx - s*0.36} ${cy + s*0.08} L ${cx - s*0.36} ${cy - s*0.21} Z`}
        fill="#ff9900"
      />
      {/* Eye shape */}
      <path
        d={`M ${cx - s*0.19} ${cy - s*0.01} Q ${cx} ${cy - s*0.16} ${cx + s*0.19} ${cy - s*0.01} Q ${cx} ${cy + s*0.15} ${cx - s*0.19} ${cy - s*0.01} Z`}
        fill="white"
      />
      <circle cx={cx} cy={cy - s*0.01} r={s*0.065} fill="#ff9900" />
    </svg>
  )
}

// ── AWS CloudTrail ────────────────────────────────────────────────────────────
// AWS orange badge with "CT" and a small trail path.
function CloudTrailLogo({ size: s }: { size: number }) {
  const pad = s * 0.1
  const rw = s - pad * 2, rh = rw * 0.52
  const ry = (s - rh) / 2 - s * 0.06
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={pad} y={ry} width={rw} height={rh} rx={s * 0.09} fill="#ff9900" />
      <text x={s/2} y={ry + rh/2 + s*0.06} textAnchor="middle" fill="white"
        fontSize={s*0.25} fontWeight="700" fontFamily="Arial, sans-serif">aws</text>
      {/* Dotted trail */}
      <circle cx={s/2 - s*0.11} cy={ry + rh + s*0.13} r={s*0.05} fill="#ff9900" />
      <circle cx={s/2}          cy={ry + rh + s*0.18} r={s*0.04} fill="#ff9900" />
      <circle cx={s/2 + s*0.11} cy={ry + rh + s*0.13} r={s*0.03} fill="#ff9900" />
    </svg>
  )
}

// ── GCP Security Command Center ───────────────────────────────────────────────
// Google G on a white background — GCP uses Google's multicolor brand.
function GcpSccLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  const r = s * 0.36, sw = s * 0.12, barH = s * 0.17, barW = r + s * 0.06
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      {/* G arcs */}
      <path d={`M ${cx+r} ${cy} A ${r} ${r} 0 0 0 ${cx} ${cy-r}`}
        fill="none" stroke="#4285f4" strokeWidth={sw} />
      <path d={`M ${cx} ${cy-r} A ${r} ${r} 0 0 0 ${cx-r} ${cy}`}
        fill="none" stroke="#ea4335" strokeWidth={sw} />
      <path d={`M ${cx-r} ${cy} A ${r} ${r} 0 0 0 ${cx} ${cy+r}`}
        fill="none" stroke="#fbbc05" strokeWidth={sw} />
      <path d={`M ${cx} ${cy+r} A ${r} ${r} 0 0 0 ${cx+r} ${cy}`}
        fill="none" stroke="#34a853" strokeWidth={sw} />
      {/* Horizontal bar */}
      <rect x={cx} y={cy - barH/2} width={barW} height={barH} fill="#4285f4" />
    </svg>
  )
}

// ── Google Workspace ──────────────────────────────────────────────────────────
// Same Google G — distinct product placement.
function GoogleWorkspaceLogo({ size: s }: { size: number }) {
  return <GcpSccLogo size={s} />
}

// ── Splunk ────────────────────────────────────────────────────────────────────
// Dark navy (#0D1F2D) background with Splunk electric-green ">" chevron.
function SplunkLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  const r = s * 0.44
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={r} fill="#0D1F2D" />
      {/* Bold ">" chevron — Splunk's signature mark */}
      <polyline
        points={`${cx - s*0.14},${cy - s*0.22} ${cx + s*0.14},${cy} ${cx - s*0.14},${cy + s*0.22}`}
        fill="none" stroke="#65A637" strokeWidth={s*0.1} strokeLinecap="round" strokeLinejoin="round"
      />
    </svg>
  )
}

// ── IBM QRadar ────────────────────────────────────────────────────────────────
// IBM blue square with bold "Q" and radar arcs inside the bowl.
function QRadarLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2, pad = s * 0.08
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={pad} y={pad} width={s-pad*2} height={s-pad*2} rx={s*0.1} fill="#1F70C1" />
      {/* Q letterform */}
      <circle cx={cx} cy={cy - s*0.03} r={s*0.2} fill="none" stroke="white" strokeWidth={s*0.08} />
      {/* Q tail */}
      <line x1={cx + s*0.1} y1={cy + s*0.1} x2={cx + s*0.22} y2={cy + s*0.22}
        stroke="white" strokeWidth={s*0.08} strokeLinecap="round" />
      {/* Inner radar arcs */}
      <circle cx={cx} cy={cy - s*0.03} r={s*0.08} fill="none" stroke="white"
        strokeWidth={s*0.04} strokeOpacity="0.6" strokeDasharray={`${s*0.06} ${s*0.06}`} />
    </svg>
  )
}

// ── Elastic SIEM ──────────────────────────────────────────────────────────────
// Three stacked concentric arcs in Elastic's three brand colors: yellow, teal, pink.
function ElasticLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  const r1 = s * 0.36, r2 = s * 0.24, r3 = s * 0.12
  const sw = s * 0.1, sw2 = s * 0.09, sw3 = s * 0.08
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      {/* Outer arc — yellow */}
      <path d={`M ${cx - r1} ${cy} A ${r1} ${r1} 0 0 1 ${cx + r1} ${cy}`}
        fill="none" stroke="#FEC514" strokeWidth={sw} strokeLinecap="round" />
      {/* Mid arc — teal */}
      <path d={`M ${cx - r2} ${cy + s*0.04} A ${r2} ${r2} 0 0 1 ${cx + r2} ${cy + s*0.04}`}
        fill="none" stroke="#00BFB3" strokeWidth={sw2} strokeLinecap="round" />
      {/* Inner arc — pink */}
      <path d={`M ${cx - r3} ${cy + s*0.1} A ${r3} ${r3} 0 0 1 ${cx + r3} ${cy + s*0.1}`}
        fill="none" stroke="#F04E98" strokeWidth={sw3} strokeLinecap="round" />
      {/* Bottom flat line to ground the "e" shape */}
      <line x1={cx - r1 + sw/2} y1={cy} x2={cx + r1 - sw/2} y2={cy}
        stroke="#FEC514" strokeWidth={sw*0.6} strokeLinecap="round" />
    </svg>
  )
}

// ── CrowdStrike Falcon ────────────────────────────────────────────────────────
// CrowdStrike red (#FC0000) circle with two curved tapered wing lines — the abstract falcon mark.
function CrowdStrikeLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#FC0000" />
      {/* Upper tapered wing — left-heavy, tapering right-up */}
      <path
        d={`M ${cx - s*0.28} ${cy + s*0.14} C ${cx - s*0.2} ${cy - s*0.04} ${cx + s*0.08} ${cy - s*0.2} ${cx + s*0.3} ${cy - s*0.24}`}
        fill="none" stroke="white" strokeWidth={s*0.09} strokeLinecap="round"
      />
      {/* Lower tapered wing — offset, thinner */}
      <path
        d={`M ${cx - s*0.22} ${cy + s*0.24} C ${cx - s*0.1} ${cy + s*0.08} ${cx + s*0.12} ${cy - s*0.06} ${cx + s*0.3} ${cy - s*0.1}`}
        fill="none" stroke="white" strokeWidth={s*0.055} strokeLinecap="round"
      />
    </svg>
  )
}

// ── SentinelOne ───────────────────────────────────────────────────────────────
// Electric violet (#6B0AEA) — segmented helmet dome (their actual icon geometry).
function SentinelOneLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <defs>
        <linearGradient id="s1-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#8B2FF8" />
          <stop offset="100%" stopColor="#4500B6" />
        </linearGradient>
      </defs>
      <circle cx={cx} cy={cy} r={s*0.46} fill="url(#s1-g)" />
      {/* Dome top arc */}
      <path
        d={`M ${cx - s*0.27} ${cy + s*0.04} A ${s*0.27} ${s*0.27} 0 0 1 ${cx + s*0.27} ${cy + s*0.04}`}
        fill="none" stroke="white" strokeWidth={s*0.085}
      />
      {/* Left visor segment */}
      <path
        d={`M ${cx - s*0.27} ${cy + s*0.04} L ${cx - s*0.24} ${cy + s*0.22} L ${cx - s*0.04} ${cy + s*0.22} L ${cx - s*0.02} ${cy + s*0.04}`}
        fill="none" stroke="white" strokeWidth={s*0.065} strokeLinejoin="round"
      />
      {/* Right visor segment */}
      <path
        d={`M ${cx + s*0.02} ${cy + s*0.04} L ${cx + s*0.04} ${cy + s*0.22} L ${cx + s*0.24} ${cy + s*0.22} L ${cx + s*0.27} ${cy + s*0.04}`}
        fill="none" stroke="white" strokeWidth={s*0.065} strokeLinejoin="round"
      />
    </svg>
  )
}

// ── VMware Carbon Black ───────────────────────────────────────────────────────
// Dark hexagon with white "cb" — VMware Carbon Black Cloud brand.
function CarbonBlackLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2, r = s * 0.43
  const pts = Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i - Math.PI / 6
    return `${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`
  }).join(' ')
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <polygon points={pts} fill="#1a1a1a" />
      <polygon points={pts} fill="none" stroke="#4caf50" strokeWidth={s*0.04} />
      <text x={cx} y={cy + s*0.12} textAnchor="middle" fill="white"
        fontSize={s*0.32} fontWeight="800" fontFamily="Arial, sans-serif">cb</text>
    </svg>
  )
}

// ── Palo Alto Cortex XDR ──────────────────────────────────────────────────────
// PAN red with a continuous orbital ring (Cortex product family identity).
function CortexXDRLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={s*0.08} y={s*0.08} width={s*0.84} height={s*0.84} rx={s*0.15} fill="#1a1a2e" />
      {/* Orbital ring */}
      <circle cx={cx} cy={cy} r={s*0.28} fill="none" stroke="#ED1C24" strokeWidth={s*0.08} />
      {/* Dot on ring */}
      <circle cx={cx} cy={cy - s*0.28} r={s*0.065} fill="#ED1C24" />
      {/* XDR text */}
      <text x={cx} y={cy + s*0.12} textAnchor="middle" fill="white"
        fontSize={s*0.2} fontWeight="800" fontFamily="Arial, sans-serif"
        letterSpacing="0.5">XDR</text>
    </svg>
  )
}

// ── Okta ──────────────────────────────────────────────────────────────────────
// Okta blue "Aura" — 12 vertical bars arranged in a perfect ring.
function OktaLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  const n = 12, ringR = s * 0.29, barH = s * 0.14, barW = s * 0.066
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#007BBF" />
      {Array.from({ length: n }, (_, i) => {
        const angle = (2 * Math.PI * i) / n - Math.PI / 2
        const bx = cx + ringR * Math.cos(angle)
        const by = cy + ringR * Math.sin(angle)
        return (
          <rect
            key={i}
            x={bx - barW / 2}
            y={by - barH / 2}
            width={barW}
            height={barH}
            rx={barW * 0.4}
            fill="white"
            transform={`rotate(${(360 / n) * i}, ${bx}, ${by})`}
          />
        )
      })}
    </svg>
  )
}

// ── Palo Alto NGFW (PAN-OS) ───────────────────────────────────────────────────
// Classic PAN red heraldic shield (flat top, pointed bottom).
function PaloAltoLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx - s*0.36} ${cy - s*0.38} L ${cx + s*0.36} ${cy - s*0.38} L ${cx + s*0.36} ${cy + s*0.08} C ${cx + s*0.36} ${cy + s*0.3} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.36} ${cy + s*0.3} ${cx - s*0.36} ${cy + s*0.08} Z`}
        fill="#ED1C24"
      />
      {/* "PA" mark */}
      <text x={cx} y={cy + s*0.1} textAnchor="middle" fill="white"
        fontSize={s*0.32} fontWeight="900" fontFamily="Arial, sans-serif">PA</text>
    </svg>
  )
}

// ── Fortinet FortiGate ────────────────────────────────────────────────────────
// Fortinet red with 8 squares arranged in an oval ring — their official icon mark.
function FortinetLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  const n = 8, rx = s * 0.31, ry = s * 0.22, sq = s * 0.1
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      {/* White background circle for contrast */}
      <circle cx={cx} cy={cy} r={s*0.46} fill="#EE2E24" />
      {Array.from({ length: n }, (_, i) => {
        const angle = (2 * Math.PI * i) / n - Math.PI / 2
        const px = cx + rx * Math.cos(angle)
        const py = cy + ry * Math.sin(angle)
        return (
          <rect
            key={i}
            x={px - sq / 2}
            y={py - sq / 2}
            width={sq}
            height={sq}
            rx={sq * 0.2}
            fill="white"
          />
        )
      })}
    </svg>
  )
}

// ── VirusTotal ────────────────────────────────────────────────────────────────
// Cobalt blue shield (#394EFF) — VirusTotal's official shield logo.
function VirusTotalLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx} ${cy - s*0.44} L ${cx + s*0.36} ${cy - s*0.22} L ${cx + s*0.36} ${cy + s*0.08} C ${cx + s*0.36} ${cy + s*0.3} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.36} ${cy + s*0.3} ${cx - s*0.36} ${cy + s*0.08} L ${cx - s*0.36} ${cy - s*0.22} Z`}
        fill="#394EFF"
      />
      <text x={cx} y={cy + s*0.1} textAnchor="middle" fill="white"
        fontSize={s*0.28} fontWeight="800" fontFamily="Arial, sans-serif">VT</text>
    </svg>
  )
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────
// Red shield with a white warning / report symbol.
function AbuseIPDBLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx} ${cy - s*0.44} L ${cx + s*0.36} ${cy - s*0.22} L ${cx + s*0.36} ${cy + s*0.08} C ${cx + s*0.36} ${cy + s*0.3} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.36} ${cy + s*0.3} ${cx - s*0.36} ${cy + s*0.08} L ${cx - s*0.36} ${cy - s*0.22} Z`}
        fill="#CC3333"
      />
      {/* Exclamation mark */}
      <rect x={cx - s*0.04} y={cy - s*0.18} width={s*0.08} height={s*0.2} rx={s*0.02} fill="white" />
      <circle cx={cx} cy={cy + s*0.17} r={s*0.05} fill="white" />
    </svg>
  )
}

// ── Shodan ────────────────────────────────────────────────────────────────────
// Near-black circle with bold Shodan red "S" — minimalist brand aesthetic.
function ShodanLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#1A1A1A" />
      <text x={cx} y={cy + s*0.15} textAnchor="middle" fill="#C92E34"
        fontSize={s*0.48} fontWeight="900" fontFamily="Arial, sans-serif">S</text>
    </svg>
  )
}

// ── Tenable.io ────────────────────────────────────────────────────────────────
// Tenable blue (#0079DD) with overlapping hexagonal cluster (their official mark).
function TenableLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  // Three overlapping hexagons in a triangular cluster
  const hexPath = (hx: number, hy: number, r: number) => {
    const pts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i - Math.PI / 6
      return `${hx + r * Math.cos(a)},${hy + r * Math.sin(a)}`
    }).join(' ')
    return `M ${pts} Z`
  }
  const r = s * 0.2
  const off = r * 0.85
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path d={hexPath(cx - off * 0.55, cy + off * 0.32, r)} fill="#0079DD" />
      <path d={hexPath(cx + off * 0.55, cy + off * 0.32, r)} fill="#005BB5" fillOpacity="0.85" />
      <path d={hexPath(cx, cy - off * 0.42, r)} fill="#00AAFF" fillOpacity="0.9" />
    </svg>
  )
}

// ── Qualys VMDR ───────────────────────────────────────────────────────────────
// Qualys red Q inside a heraldic shield — their official logomark.
function QualysLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <path
        d={`M ${cx - s*0.36} ${cy - s*0.38} L ${cx + s*0.36} ${cy - s*0.38} L ${cx + s*0.36} ${cy + s*0.08} C ${cx + s*0.36} ${cy + s*0.3} ${cx} ${cy + s*0.44} ${cx} ${cy + s*0.44} C ${cx} ${cy + s*0.44} ${cx - s*0.36} ${cy + s*0.3} ${cx - s*0.36} ${cy + s*0.08} Z`}
        fill="#ED2E26"
      />
      {/* Q circle */}
      <circle cx={cx} cy={cy - s*0.05} r={s*0.16} fill="none" stroke="white" strokeWidth={s*0.07} />
      {/* Q tail */}
      <line x1={cx + s*0.08} y1={cy + s*0.06} x2={cx + s*0.18} y2={cy + s*0.17}
        stroke="white" strokeWidth={s*0.07} strokeLinecap="round" />
    </svg>
  )
}

// ── Syslog ────────────────────────────────────────────────────────────────────
// Dark terminal window with green ">_" prompt.
function SyslogLogo({ size: s }: { size: number }) {
  const pad = s * 0.09
  const w = s - pad * 2, h = s * 0.72
  const y = (s - h) / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <rect x={pad} y={y} width={w} height={h} rx={s*0.1} fill="#1e1e1e" />
      <rect x={pad} y={y} width={w} height={h*0.22} rx={s*0.1} fill="#333" />
      {/* Traffic lights */}
      <circle cx={pad + s*0.1} cy={y + h*0.11} r={s*0.04} fill="#ff5f57" />
      <circle cx={pad + s*0.2} cy={y + h*0.11} r={s*0.04} fill="#ffbd2e" />
      <circle cx={pad + s*0.3} cy={y + h*0.11} r={s*0.04} fill="#28ca41" />
      {/* Prompt */}
      <text x={pad + s*0.08} y={y + h*0.65} fill="#22c55e"
        fontSize={s*0.26} fontWeight="700" fontFamily="Courier New, monospace">{'>_'}</text>
    </svg>
  )
}

// ── Linux Auditd ──────────────────────────────────────────────────────────────
// Orange circle with simplified Tux penguin (Linux mascot).
function LinuxAuditdLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#f97316" />
      {/* Body */}
      <ellipse cx={cx} cy={cy + s*0.1} rx={s*0.18} ry={s*0.22} fill="white" />
      {/* Head */}
      <circle cx={cx} cy={cy - s*0.16} r={s*0.14} fill="#1a1a1a" />
      {/* Face white patch */}
      <ellipse cx={cx} cy={cy - s*0.14} rx={s*0.08} ry={s*0.07} fill="white" />
      {/* Eyes */}
      <circle cx={cx - s*0.04} cy={cy - s*0.17} r={s*0.025} fill="#1a1a1a" />
      <circle cx={cx + s*0.04} cy={cy - s*0.17} r={s*0.025} fill="#1a1a1a" />
      {/* Beak */}
      <polygon
        points={`${cx},${cy - s*0.08} ${cx - s*0.035},${cy - s*0.04} ${cx + s*0.035},${cy - s*0.04}`}
        fill="#ffb900"
      />
      {/* Belly */}
      <ellipse cx={cx} cy={cy + s*0.1} rx={s*0.11} ry={s*0.15} fill="#ffe9cc" />
    </svg>
  )
}

// ── Suricata IDS ──────────────────────────────────────────────────────────────
// Suricata brown-orange with upright meerkat silhouette (the actual Suricata mascot).
function SuricataLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#8E3B1B" />
      {/* Meerkat body — upright silhouette */}
      {/* Torso */}
      <ellipse cx={cx} cy={cy + s*0.1} rx={s*0.11} ry={s*0.18} fill="#F2A667" />
      {/* Head */}
      <circle cx={cx} cy={cy - s*0.18} r={s*0.1} fill="#F2A667" />
      {/* Snout */}
      <ellipse cx={cx} cy={cy - s*0.1} rx={s*0.055} ry={s*0.045} fill="#c97840" />
      {/* Eyes */}
      <circle cx={cx - s*0.04} cy={cy - s*0.2} r={s*0.02} fill="#1a1a1a" />
      <circle cx={cx + s*0.04} cy={cy - s*0.2} r={s*0.02} fill="#1a1a1a" />
      {/* Ears */}
      <ellipse cx={cx - s*0.08} cy={cy - s*0.27} rx={s*0.04} ry={s*0.055} fill="#F2A667" />
      <ellipse cx={cx + s*0.08} cy={cy - s*0.27} rx={s*0.04} ry={s*0.055} fill="#F2A667" />
      {/* Tail — curved behind */}
      <path
        d={`M ${cx + s*0.1} ${cy + s*0.28} C ${cx + s*0.28} ${cy + s*0.25} ${cx + s*0.3} ${cy} ${cx + s*0.18} ${cy - s*0.12}`}
        fill="none" stroke="#F2A667" strokeWidth={s*0.07} strokeLinecap="round"
      />
    </svg>
  )
}

// ── Snort IDS ─────────────────────────────────────────────────────────────────
// Cisco red with Snort's pig mascot (the actual Snort logo is a pig).
function SnortLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#CC0000" />
      {/* Head */}
      <circle cx={cx} cy={cy} r={s*0.28} fill="#ffb3b3" />
      {/* Snout */}
      <ellipse cx={cx} cy={cy + s*0.1} rx={s*0.18} ry={s*0.14} fill="#ff8585" />
      {/* Nostrils */}
      <circle cx={cx - s*0.07} cy={cy + s*0.1} r={s*0.055} fill="#CC0000" />
      <circle cx={cx + s*0.07} cy={cy + s*0.1} r={s*0.055} fill="#CC0000" />
      {/* Eyes */}
      <circle cx={cx - s*0.11} cy={cy - s*0.08} r={s*0.045} fill="white" />
      <circle cx={cx + s*0.11} cy={cy - s*0.08} r={s*0.045} fill="white" />
      <circle cx={cx - s*0.1} cy={cy - s*0.08} r={s*0.025} fill="#1a1a1a" />
      <circle cx={cx + s*0.1} cy={cy - s*0.08} r={s*0.025} fill="#1a1a1a" />
      {/* Ears */}
      <ellipse cx={cx - s*0.22} cy={cy - s*0.18} rx={s*0.07} ry={s*0.1}
        fill="#ffb3b3" transform={`rotate(-20, ${cx - s*0.22}, ${cy - s*0.18})`} />
      <ellipse cx={cx + s*0.22} cy={cy - s*0.18} rx={s*0.07} ry={s*0.1}
        fill="#ffb3b3" transform={`rotate(20, ${cx + s*0.22}, ${cy - s*0.18})`} />
    </svg>
  )
}

// ── Zeek ──────────────────────────────────────────────────────────────────────
// Zeek blue (#0098CB) with a streamlined fish silhouette — their actual logo.
function ZeekLogo({ size: s }: { size: number }) {
  const cx = s / 2, cy = s / 2
  return (
    <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`} aria-hidden>
      <circle cx={cx} cy={cy} r={s*0.46} fill="#0098CB" />
      {/* Fish body */}
      <ellipse cx={cx - s*0.04} cy={cy} rx={s*0.24} ry={s*0.14} fill="white" />
      {/* Tail fin */}
      <polygon
        points={`${cx + s*0.2},${cy} ${cx + s*0.38},${cy - s*0.14} ${cx + s*0.38},${cy + s*0.14}`}
        fill="white"
      />
      {/* Top fin */}
      <path
        d={`M ${cx - s*0.06} ${cy - s*0.14} C ${cx - s*0.04} ${cy - s*0.28} ${cx + s*0.08} ${cy - s*0.26} ${cx + s*0.1} ${cy - s*0.14}`}
        fill="white"
      />
      {/* Eye */}
      <circle cx={cx - s*0.15} cy={cy - s*0.02} r={s*0.045} fill="#0098CB" />
      <circle cx={cx - s*0.15} cy={cy - s*0.02} r={s*0.02} fill="#1a1a1a" />
    </svg>
  )
}

// ── Fallback ──────────────────────────────────────────────────────────────────

function FallbackLogo({ size, className }: { size: number; className?: string }) {
  return <Database width={size} height={size} className={cn('text-muted-foreground', className)} />
}

// ── Logo dispatch ─────────────────────────────────────────────────────────────

const LOGO_MAP: Record<string, (size: number) => JSX.Element> = {
  // Microsoft family
  sentinel:        (s) => <SentinelLogo size={s} />,
  'azure-ad':      (s) => <EntraIdLogo size={s} />,
  'azure-defender':(s) => <DefenderCloudLogo size={s} />,
  'microsoft-365': (s) => <MicrosoftFourSquare size={s} />,
  windows:         (s) => <WindowsLogo size={s} />,
  'windows_event': (s) => <WindowsLogo size={s} />,

  // AWS family
  guardduty:       (s) => <GuardDutyLogo size={s} />,
  'aws-cloudtrail':(s) => <CloudTrailLogo size={s} />,

  // Google family
  'gcp-scc':          (s) => <GcpSccLogo size={s} />,
  'google-workspace': (s) => <GoogleWorkspaceLogo size={s} />,

  // SIEMs
  splunk:          (s) => <SplunkLogo size={s} />,
  qradar:          (s) => <QRadarLogo size={s} />,
  'elastic-siem':  (s) => <ElasticLogo size={s} />,

  // EDR
  crowdstrike:     (s) => <CrowdStrikeLogo size={s} />,
  sentinelone:     (s) => <SentinelOneLogo size={s} />,
  carbonblack:     (s) => <CarbonBlackLogo size={s} />,
  'cortex-xdr':    (s) => <CortexXDRLogo size={s} />,

  // Identity
  okta:            (s) => <OktaLogo size={s} />,

  // Network / Firewall
  'palo-alto':     (s) => <PaloAltoLogo size={s} />,
  fortinet:        (s) => <FortinetLogo size={s} />,

  // Enrichment
  virustotal:      (s) => <VirusTotalLogo size={s} />,
  abuseipdb:       (s) => <AbuseIPDBLogo size={s} />,
  shodan:          (s) => <ShodanLogo size={s} />,

  // Vulnerability
  tenable:         (s) => <TenableLogo size={s} />,
  qualys:          (s) => <QualysLogo size={s} />,

  // OS / Push
  syslog:          (s) => <SyslogLogo size={s} />,
  'linux-auditd':  (s) => <LinuxAuditdLogo size={s} />,

  // IDS/IPS
  suricata:        (s) => <SuricataLogo size={s} />,
  snort:           (s) => <SnortLogo size={s} />,
  zeek:            (s) => <ZeekLogo size={s} />,
}

// ── Public component ──────────────────────────────────────────────────────────

export function SourceLogo({ sourceId, size = 32, className }: SourceLogoProps) {
  const renderer = LOGO_MAP[sourceId]
  if (!renderer) return <FallbackLogo size={size} className={className} />
  return (
    <span
      className={cn('inline-flex items-center justify-center shrink-0', className)}
      style={{ width: size, height: size }}
      aria-label={sourceId}
    >
      {renderer(size)}
    </span>
  )
}

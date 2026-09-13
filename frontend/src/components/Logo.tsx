/**
 * PacketKage wordmark — single inline SVG logo used by sidebar and favicon.
 * Radar-pulse motif inside a bracketed frame; emerald accent on currentColor text.
 */
export function Logo({ size = 28, withWordmark = true }: { size?: number; withWordmark?: boolean }) {
  return (
    <span className="inline-flex select-none items-center gap-2.5">
      <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden focusable="false">
        {/* bracket frame */}
        <path
          d="M10 4H6a2 2 0 0 0-2 2v4M22 4h4a2 2 0 0 1 2 2v4M10 28H6a2 2 0 0 1-2-2v-4M22 28h4a2 2 0 0 0 2-2v-4"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          className="text-fg-muted"
        />
        {/* radar pulses */}
        <circle cx="16" cy="16" r="2.6" className="fill-accent" />
        <path
          d="M11.5 16a4.5 4.5 0 0 1 9 0"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          className="text-accent"
          opacity="0.9"
        />
        <path
          d="M8.5 16a7.5 7.5 0 0 1 15 0"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          className="text-accent"
          opacity="0.45"
        />
      </svg>
      {withWordmark && (
        <span className="flex flex-col leading-none">
          <span className="text-[15px] font-semibold tracking-tight text-fg">PacketKage</span>
        </span>
      )}
    </span>
  )
}


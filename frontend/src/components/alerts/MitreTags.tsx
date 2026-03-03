import { ExternalLink } from 'lucide-react'
import { getMitreUrl, formatTechniqueId } from '@/utils/mitre'
import { isSafeUrl } from '@/security/sanitize'
import type { MitreTechnique } from '@/types/alert'
import { cn } from '@/utils/cn'

interface MitreTagsProps {
  techniques: MitreTechnique[]
  className?: string
}

export function MitreTags({ techniques, className }: MitreTagsProps) {
  if (!techniques?.length) return null

  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {techniques.map((t) => {
        const id = t.technique_id ?? (t as { id?: string }).id
        const url = getMitreUrl(id ?? '')
        const safe = isSafeUrl(url)
        return safe ? (
          <a
            key={id}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-soc-border/50 text-soc-muted hover:text-soc-text hover:bg-soc-border transition-colors"
          >
            {formatTechniqueId(id ?? '')}
            <ExternalLink className="w-3 h-3" />
          </a>
        ) : (
          <span
            key={id}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-soc-border/50 text-soc-muted"
          >
            {formatTechniqueId(id ?? '')}
          </span>
        )
      })}
    </div>
  )
}

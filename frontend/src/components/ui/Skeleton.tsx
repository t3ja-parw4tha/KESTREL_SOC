import type React from 'react'
import { cn } from '@/utils/cn'

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-muted/50', className)}
      style={style}
    />
  )
}

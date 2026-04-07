import { useEffect, useRef, useCallback, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { getToken } from '@/api/client'

const WS_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000').replace(
  /^http/,
  'ws'
)

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error'

interface WebSocketMessage {
  type: 'new_alert' | 'alert_update' | 'stats_update' | 'incident_update'
  payload: Record<string, unknown>
}

const MAX_RECONNECT = 5
const BASE_DELAY = 2000

export function useRealtimeAlerts({ enabled = true, showToasts = true } = {}) {
  const queryClient = useQueryClient()
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()
  const reconnectAttempts = useRef(0)
  const [status, setStatus] = useState<ConnectionStatus>('disconnected')

  const invalidateDashboard = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
  }, [queryClient])

  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const msg: WebSocketMessage = JSON.parse(event.data as string)
        switch (msg.type) {
          case 'new_alert':
            invalidateDashboard()
            if (showToasts) {
              toast((msg.payload.title as string) ?? 'New Alert', {
                description: `Severity: ${((msg.payload.severity as string) ?? 'info').toUpperCase()}`,
                duration: 5000,
              })
            }
            break
          case 'alert_update':
            queryClient.invalidateQueries({ queryKey: ['alerts'] })
            queryClient.invalidateQueries({ queryKey: ['dashboard', 'recent'] })
            break
          case 'stats_update':
            queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
            break
          case 'incident_update':
            queryClient.invalidateQueries({ queryKey: ['incidents'] })
            queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
            break
          default:
            break
        }
      } catch {
        // ignore malformed messages
      }
    },
    [invalidateDashboard, queryClient, showToasts]
  )

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    setStatus('connecting')
    const token = getToken()
    const url = `${WS_BASE_URL}/api/v1/ws/alerts${token ? `?token=${token}` : ''}`

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setStatus('connected')
        reconnectAttempts.current = 0
      }

      ws.onmessage = handleMessage

      ws.onclose = () => {
        setStatus('disconnected')
        wsRef.current = null
        if (enabled && reconnectAttempts.current < MAX_RECONNECT) {
          const delay = BASE_DELAY * Math.pow(2, reconnectAttempts.current)
          reconnectAttempts.current++
          reconnectTimer.current = setTimeout(connect, delay)
        }
      }

      ws.onerror = () => {
        setStatus('error')
        ws.close()
      }
    } catch {
      setStatus('error')
    }
  }, [enabled, handleMessage])

  const disconnect = useCallback(() => {
    clearTimeout(reconnectTimer.current)
    reconnectAttempts.current = MAX_RECONNECT
    wsRef.current?.close()
    wsRef.current = null
    setStatus('disconnected')
  }, [])

  useEffect(() => {
    if (enabled) connect()
    return () => disconnect()
  }, [enabled, connect, disconnect])

  return { status, reconnect: connect, disconnect }
}

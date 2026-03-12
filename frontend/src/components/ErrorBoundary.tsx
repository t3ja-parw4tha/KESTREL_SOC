import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-soc-bg flex items-center justify-center p-6">
          <div className="max-w-md w-full rounded-xl border border-soc-border bg-soc-surface p-8 text-center">
            <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500" />
            </div>
            <h1 className="text-xl font-semibold text-soc-text mb-2">Something went wrong</h1>
            <p className="text-sm text-soc-muted mb-6">
              An unexpected error occurred. Try refreshing the page or go back to the dashboard.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              <button
                type="button"
                onClick={this.handleRetry}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-700"
              >
                <RefreshCw className="w-4 h-4" />
                Try again
              </button>
              <a
                href="/app"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm font-medium hover:bg-soc-border/50"
              >
                Go to Dashboard
              </a>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

import { Link } from 'react-router-dom'

export function NotFound() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
      <h1 className="text-6xl font-bold text-soc-muted">404</h1>
      <p className="text-soc-text mt-2">Page not found</p>
      <Link to="/" className="mt-6 text-low hover:underline">
        Back to Dashboard
      </Link>
    </div>
  )
}

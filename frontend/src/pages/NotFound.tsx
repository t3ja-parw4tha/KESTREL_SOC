import { Link } from 'react-router-dom'

export function NotFound() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4 animate-fade-in">
      <div className="relative mb-6">
        <div className="absolute inset-0 rounded-full bg-primary/10 blur-3xl animate-glow-pulse" />
        <h1 className="relative text-8xl font-bold text-gradient-brand">404</h1>
      </div>
      <p className="text-foreground text-lg font-medium mt-2">Page not found</p>
      <p className="text-muted-foreground text-sm mt-1">The page you're looking for doesn't exist.</p>
      <Link
        to="/app"
        className="mt-8 inline-flex items-center gap-2 px-5 py-2.5 rounded-xl gradient-primary text-white text-sm font-medium hover:opacity-90 transition-opacity"
      >
        Back to Dashboard
      </Link>
    </div>
  )
}

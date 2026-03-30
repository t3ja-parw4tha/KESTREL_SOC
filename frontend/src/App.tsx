import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { Toaster, toast, useSonner } from 'sonner'
import { X } from 'lucide-react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/security/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { setUnauthorizedHandler } from '@/api/client'
import { ProtectedRoute, SourcesRoute, AdminRoute } from '@/security/ProtectedRoute'
import { SessionTimeoutModal } from '@/components/security/SessionTimeoutModal'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { Alerts } from '@/pages/Alerts'
import { AlertDetail } from '@/pages/AlertDetail'
import { Incidents } from '@/pages/Incidents'
import { IncidentDetail } from '@/pages/IncidentDetail'
import { Assets } from '@/pages/Assets'
import MitreCoverage from '@/pages/MitreCoverage'
import { Sources } from '@/pages/Sources'
import { ThreatHunting } from '@/pages/ThreatHunting'
import { Reports } from '@/pages/Reports'
import { Playbooks } from '@/pages/Playbooks'
import { Help } from '@/pages/Help'
import { UserManagement } from '@/pages/UserManagement'
import { Settings } from '@/pages/Settings'
import { DetectionRules } from '@/pages/DetectionRules'
import { Resilience } from '@/pages/Resilience'
import { SetupWizard } from '@/pages/SetupWizard'
import { Login } from '@/pages/Login'
import { Landing } from '@/pages/Landing'
import { NotFound } from '@/pages/NotFound'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60 * 1000,
      retry: 1,
    },
  },
})

function AuthInterceptorSetup() {
  const { logout } = useAuth()
  useEffect(() => {
    setUnauthorizedHandler(logout)
    return () => setUnauthorizedHandler(() => { })
  }, [logout])
  return null
}

function SetupCheck() {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    if (isAuthenticated) return
    fetch('/api/v1/auth/setup-status')
      .then((r) => r.json())
      .then((d) => {
        if (!d.setup_complete) {
          navigate('/setup')
        }
      })
      .catch(() => { })
  }, [isAuthenticated, navigate])

  return null
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/setup" element={<SetupWizard />} />
      <Route path="/login" element={<Login />} />
      <Route
        path="/app"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:id" element={<AlertDetail />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="assets" element={<Assets />} />
        <Route path="mitre" element={<MitreCoverage />} />
        <Route path="hunting" element={<ThreatHunting />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="detection-rules" element={<DetectionRules />} />
        <Route path="resilience" element={<Resilience />} />
        <Route path="reports" element={<Reports />} />
        <Route path="help" element={<Help />} />
        <Route
          path="sources"
          element={
            <SourcesRoute>
              <Sources />
            </SourcesRoute>
          }
        />
        <Route
          path="settings"
          element={
            <AdminRoute>
              <Settings />
            </AdminRoute>
          }
        />
        <Route
          path="users"
          element={
            <AdminRoute>
              <UserManagement />
            </AdminRoute>
          }
        />
        <Route path="404" element={<NotFound />} />
        <Route path="*" element={<Navigate to="/app/404" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function AppToaster() {
  const { theme } = useTheme()
  const { toasts } = useSonner()
  const hasActiveToasts = toasts.some((t) => !t.delete)

  return (
    <>
      {hasActiveToasts && (
        <div className="fixed top-[68px] right-4 z-[120] pointer-events-none">
          <button
            type="button"
            onClick={() => toast.dismiss()}
            className="pointer-events-auto inline-flex items-center gap-1 rounded-md border border-border bg-card/95 px-2 py-1 text-[11px] font-medium text-muted-foreground shadow-md hover:text-foreground hover:bg-accent transition-colors"
            title="Clear all popups"
            aria-label="Clear all popups"
          >
            <X className="h-3 w-3" />
            Clear all
          </button>
        </div>
      )}
      <Toaster richColors position="top-right" theme={theme} closeButton offset={104} />
    </>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <ErrorBoundary>
            <AuthInterceptorSetup />
            <SetupCheck />
            <SessionTimeoutModal />
            <AppRoutes />
            <AppToaster />
          </ErrorBoundary>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  )
}

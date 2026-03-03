import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/security/AuthContext'
import { setUnauthorizedHandler } from '@/api/client'
import { ProtectedRoute, SourcesRoute, AdminRoute } from '@/security/ProtectedRoute'
import { SessionTimeoutModal } from '@/components/security/SessionTimeoutModal'
import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { Alerts } from '@/pages/Alerts'
import { AlertDetail } from '@/pages/AlertDetail'
import { Incidents } from '@/pages/Incidents'
import { IncidentDetail } from '@/pages/IncidentDetail'
import { MitreCoverage } from '@/pages/MitreCoverage'
import { Sources } from '@/pages/Sources'
import { UserManagement } from '@/pages/UserManagement'
import { Settings } from '@/pages/Settings'
import { SetupWizard } from '@/pages/SetupWizard'
import { Login } from '@/pages/Login'
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
    return () => setUnauthorizedHandler(() => {})
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
      .catch(() => {})
  }, [isAuthenticated, navigate])

  return null
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/setup" element={<SetupWizard />} />
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
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
        <Route path="mitre" element={<MitreCoverage />} />
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
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <AuthInterceptorSetup />
          <SetupCheck />
          <SessionTimeoutModal />
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  )
}

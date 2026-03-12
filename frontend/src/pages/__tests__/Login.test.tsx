import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Login } from '@/pages/Login'

// Mock useAuth
const mockLogin = vi.fn()
vi.mock('@/security/AuthContext', () => ({
  useAuth: () => ({ login: mockLogin }),
}))

// Mock useNavigate and useLocation
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({ state: null, pathname: '/login' }),
  }
})

// A minimal valid-looking JWT with role=analyst
const MOCK_JWT = [
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',
  btoa(JSON.stringify({ sub: '1', username: 'admin', role: 'analyst', exp: Math.floor(Date.now() / 1000) + 3600 })),
  'signature',
].join('.')

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>
  )
}

// Helper: get the first "Sign in" button (the main form, not SSO)
function getSignInButton() {
  // The main login submit button has exact text "Sign in"
  const buttons = screen.getAllByRole('button')
  return buttons.find((b) => b.textContent?.trim() === 'Sign in')!
}

describe('Login page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('fetch', vi.fn())
  })

  it('renders username and password inputs', () => {
    renderLogin()
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('renders the main sign-in button', () => {
    renderLogin()
    expect(getSignInButton()).toBeInTheDocument()
  })

  it('renders the SSO email input', () => {
    renderLogin()
    expect(screen.getByPlaceholderText(/name@company.com/i)).toBeInTheDocument()
  })

  it('shows error message on failed login', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      json: async () => ({ detail: 'Invalid username or password' }),
    } as Response)

    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'bad' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong' } })
    fireEvent.click(getSignInButton())

    await waitFor(() => {
      expect(screen.getByText('Invalid username or password')).toBeInTheDocument()
    })
  })

  it('calls login and navigates on successful credentials', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: MOCK_JWT }),
    } as Response)

    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'P@ssword1!' } })
    fireEvent.click(getSignInButton())

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(MOCK_JWT, expect.objectContaining({ role: 'analyst' }))
      expect(mockNavigate).toHaveBeenCalledWith('/app', { replace: true })
    })
  })

  it('disables submit button while loading', async () => {
    // Never resolves — keeps loading state
    vi.mocked(fetch).mockReturnValueOnce(new Promise(() => {}))

    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'P@ssword1!' } })
    fireEvent.click(getSignInButton())

    await waitFor(() => {
      expect(screen.getByText('Signing in...')).toBeInTheDocument()
      expect(screen.getByText('Signing in...').closest('button')).toBeDisabled()
    })
  })

  it('shows error on network failure', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'))

    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'P@ssword1!' } })
    fireEvent.click(getSignInButton())

    await waitFor(() => {
      expect(screen.getByText(/could not connect/i)).toBeInTheDocument()
    })
  })
})

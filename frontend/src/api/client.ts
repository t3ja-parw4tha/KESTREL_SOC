/**
 * API client: baseURL /api (proxied to FastAPI). Typed get/post/patch.
 */

import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios'

const REQUEST_TIMEOUT_MS = 30_000
const isDev = import.meta.env.DEV

let accessToken: string | null = null
let csrfToken: string | null = null

type LogoutCallback = () => void
let _onUnauthorized: LogoutCallback | null = null

export function setUnauthorizedHandler(cb: LogoutCallback): void {
  _onUnauthorized = cb
}

export function setToken(token: string): void {
  accessToken = token
}

export function clearToken(): void {
  accessToken = null
  csrfToken = null
}

export function getToken(): string | null {
  return accessToken
}

export function setCsrfToken(token: string): void {
  csrfToken = token
}

export function getCsrfToken(): string | null {
  return csrfToken
}

export function requestConfig(signal?: AbortSignal): AxiosRequestConfig {
  return { timeout: REQUEST_TIMEOUT_MS, signal }
}

export const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: REQUEST_TIMEOUT_MS,
  headers: {
    'Content-Type': 'application/json',
  },
})

apiClient.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  const method = (config.method ?? '').toUpperCase()
  if (['POST', 'PATCH', 'DELETE', 'PUT'].includes(method) && csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (isDev) {
      console.error('[API Error]', error?.response?.data ?? error?.message ?? error)
    }
    const status = error?.response?.status
    if (status === 401) {
      clearToken()
      if (_onUnauthorized) {
        _onUnauthorized()
      } else {
        window.location.href = '/login'
      }
    }
    const sanitized = new Error(
      isDev && error?.response?.data?.detail
        ? String(error.response.data.detail)
        : status === 401
        ? 'Session expired. Please sign in again.'
        : 'Something went wrong'
    )
    return Promise.reject(sanitized)
  }
)

export async function get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await apiClient.get(url, config)
  return res.data
}

export async function post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await apiClient.post(url, data, config)
  return res.data
}

export async function patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await apiClient.patch(url, data, config)
  return res.data
}

export async function put<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await apiClient.put(url, data, config)
  return res.data
}

export async function del<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await apiClient.delete(url, config)
  return res.data
}

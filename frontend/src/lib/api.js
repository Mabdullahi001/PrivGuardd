import { getToken } from './auth.js'

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000"

async function request(path, { method = "GET", body } = {}) {
  const token = getToken()
  const headers = { "Content-Type": "application/json" }
  if (token) headers["Authorization"] = `Bearer ${token}`

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  })

  // redirect on unauthorized
  if (res.status === 401) {
    throw new Error("Unauthorized")
  }
  const contentType = res.headers.get("content-type") || ""
  if (contentType.includes("application/json")) return await res.json()
  return await res.text()
}

export const api = {
  signup: (email, password) => request("/api/auth/signup", { method: "POST", body: { email, password } }),
  login: (email, password) => request("/api/auth/login", { method: "POST", body: { email, password } }),
  gmailStatus: () => request("/api/gmail/status"),
  gmailOauthStart: () => request("/api/gmail/oauth/start"),
  gmailDisconnect: () => request("/api/gmail/disconnect", { method: "POST" }),
  scanNow: (max_results = 25, query = null) => request("/api/scan", { method: "POST", body: { max_results, query } }),
  latest: (limit = 50) => request(`/api/reports/latest?limit=${limit}`)
,
  messageDetail: (message_id) => request(`/api/messages/${message_id}`)
}

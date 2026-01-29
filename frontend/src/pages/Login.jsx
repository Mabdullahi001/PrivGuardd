import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api.js'
import { setToken } from '../lib/auth.js'

export default function Login() {
  const nav = useNavigate()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [err, setErr] = useState("")

  async function submit(e) {
    e.preventDefault()
    setErr("")
    try {
      const res = await api.login(email, password)
      setToken(res.access_token)
      nav("/dashboard")
    } catch (e) {
      setErr("Login failed. Check your email/password.")
    }
  }

  return (
    <div className="min-h-screen grid place-items-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow">
        <div className="text-2xl font-semibold">PrivGuard</div>
        <div className="text-sm text-slate-400 mt-1">Sign in to scan and protect your Gmail.</div>
        <form onSubmit={submit} className="mt-6 space-y-3">
          <input className="w-full rounded-lg bg-slate-900 border border-slate-800 px-3 py-2"
            placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} />
          <input className="w-full rounded-lg bg-slate-900 border border-slate-800 px-3 py-2"
            placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
          {err && <div className="text-sm text-red-400">{err}</div>}
          <button className="w-full rounded-lg bg-slate-100 text-slate-950 font-medium py-2 hover:opacity-90">Login</button>
        </form>
        <div className="text-sm text-slate-400 mt-4">
          No account? <Link className="text-slate-200 hover:underline" to="/signup">Create one</Link>
        </div>
      </div>
    </div>
  )
}

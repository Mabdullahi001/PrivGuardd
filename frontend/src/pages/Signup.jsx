import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api.js'
import { setToken } from '../lib/auth.js'

export default function Signup() {
  const nav = useNavigate()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [err, setErr] = useState("")

  async function submit(e) {
    e.preventDefault()
    setErr("")
    try {
      const res = await api.signup(email, password)
      setToken(res.access_token)
      nav("/dashboard")
    } catch (e) {
      setErr("Signup failed. Email may already exist.")
    }
  }

  return (
    <div className="min-h-screen grid place-items-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow">
        <div className="text-2xl font-semibold">Create account</div>
        <div className="text-sm text-slate-400 mt-1">Start protecting your inbox.</div>
        <form onSubmit={submit} className="mt-6 space-y-3">
          <input className="w-full rounded-lg bg-slate-900 border border-slate-800 px-3 py-2"
            placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} />
          <input className="w-full rounded-lg bg-slate-900 border border-slate-800 px-3 py-2"
            placeholder="Password (min 8 chars)" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
          {err && <div className="text-sm text-red-400">{err}</div>}
          <button className="w-full rounded-lg bg-slate-100 text-slate-950 font-medium py-2 hover:opacity-90">Sign up</button>
        </form>
        <div className="text-sm text-slate-400 mt-4">
          Have an account? <Link className="text-slate-200 hover:underline" to="/login">Login</Link>
        </div>
      </div>
    </div>
  )
}

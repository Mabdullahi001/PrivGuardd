import React from 'react'
import { Link } from 'react-router-dom'
import { clearToken } from '../lib/auth.js'

export default function Shell({ title, children }) {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-950/70 backdrop-blur">
        <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-slate-800 flex items-center justify-center font-bold">PG</div>
            <div>
              <div className="text-lg font-semibold">{title}</div>
              <div className="text-xs text-slate-400">Email Security & Privacy</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link className="text-sm text-slate-300 hover:text-white" to="/dashboard">Dashboard</Link>
            <button
              className="text-sm rounded-lg border border-slate-700 px-3 py-1.5 hover:bg-slate-900"
              onClick={() => { clearToken(); window.location.href="/login" }}
            >
              Log out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-6">{children}</main>
    </div>
  )
}

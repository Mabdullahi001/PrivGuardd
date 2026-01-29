import React, { useEffect, useState } from 'react'
import Shell from '../components/Shell.jsx'
import { api } from '../lib/api.js'

function Badge({ level }) {
  const base = "px-2 py-0.5 rounded-full text-xs border"
  if (level === "Malicious") return <span className={`${base} border-red-700 text-red-300`}>Malicious</span>
  if (level === "Suspicious") return <span className={`${base} border-amber-700 text-amber-300`}>Suspicious</span>
  return <span className={`${base} border-emerald-700 text-emerald-300`}>Safe</span>
}

export default function Dashboard() {
  const [gmail, setGmail] = useState({ connected: false })
  const [latest, setLatest] = useState([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState("")
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailBusy, setDetailBusy] = useState(false)

  async function refresh() {
    setErr("")
    try {
      const st = await api.gmailStatus()
      setGmail(st)
      const list = await api.latest(50)
      setLatest(list)
    } catch (e) {
      setErr("Failed to load dashboard.")
    }
  }

  useEffect(() => { refresh() }, [])

  async function connectGmail() {
    setErr("")
    try {
      const { auth_url } = await api.gmailOauthStart()
      window.location.href = auth_url
    } catch (e) {
      setErr("Unable to start Gmail connection.")
    }
  }

  async function disconnect() {
    setBusy(true)
    try {
      await api.gmailDisconnect()
      await refresh()
    } catch (e) {
      setErr("Disconnect failed.")
    } finally {
      setBusy(false)
    }
  }

  async function scanNow() {
    setBusy(true)
    setErr("")
    try {
      const res = await api.scanNow(25, null)
      setLatest(res.items.concat(latest).slice(0, 50))
      await refresh()
    } catch (e) {
      setErr("Scan failed. Ensure Gmail is connected.")
    } finally {
      setBusy(false)
    }
  }


  async function openDetail(messageId) {
    setSelected(messageId)
    setDetail(null)
    setDetailBusy(true)
    try {
      const res = await api.messageDetail(messageId)
      setDetail(res)
    } catch (e) {
      setErr("Failed to load message details.")
    } finally {
      setDetailBusy(false)
    }
  }

  function closeDetail() {
    setSelected(null)
    setDetail(null)
  }

  const kpi = latest.reduce((acc, it) => {
    if (it.threat_level === "Malicious") acc.mal += 1
    else if (it.threat_level === "Suspicious") acc.susp += 1
    else acc.safe += 1
    return acc
  }, { mal: 0, susp: 0, safe: 0 })

  return (
    <Shell title="Security Dashboard">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-2xl font-semibold">PrivGuard Overview</div>
          <div className="text-sm text-slate-400 mt-1">
            Connect Gmail occasionally, scan on-demand, and review threat reports.
          </div>
        </div>
        <div className="flex gap-2">
          {!gmail.connected ? (
            <button className="rounded-lg bg-slate-100 text-slate-950 px-3 py-2 text-sm font-medium hover:opacity-90"
              onClick={connectGmail} disabled={busy}>
              Connect Gmail
            </button>
          ) : (
            <>
              <button className="rounded-lg border border-slate-700 px-3 py-2 text-sm hover:bg-slate-900"
                onClick={disconnect} disabled={busy}>
                Disconnect
              </button>
              <button className="rounded-lg bg-slate-100 text-slate-950 px-3 py-2 text-sm font-medium hover:opacity-90"
                onClick={scanNow} disabled={busy}>
                Scan Now
              </button>
            </>
          )}
        </div>
      </div>

      {err && <div className="mt-4 text-sm text-red-400">{err}</div>}

      <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="text-xs text-slate-400">Gmail Status</div>
          <div className="mt-2 text-sm">
            {gmail.connected ? (
              <div className="text-slate-200">Connected: <span className="font-medium">{gmail.connected_email}</span></div>
            ) : (
              <div className="text-slate-400">Not connected</div>
            )}
          </div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="text-xs text-slate-400">Malicious</div>
          <div className="mt-2 text-2xl font-semibold">{kpi.mal}</div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="text-xs text-slate-400">Suspicious</div>
          <div className="mt-2 text-2xl font-semibold">{kpi.susp}</div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="text-xs text-slate-400">Safe</div>
          <div className="mt-2 text-2xl font-semibold">{kpi.safe}</div>
        </div>
      </div>

      <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="font-medium">Latest Findings</div>
          <div className="text-xs text-slate-400">{latest.length} items</div>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-400">
              <tr className="text-left">
                <th className="px-4 py-3">Threat</th>
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {latest.map((it) => (
                <tr key={it.gmail_message_id} className="border-t border-slate-900 hover:bg-slate-900/40">
                  <td className="px-4 py-3"><Badge level={it.threat_level} /></td>
                  <td className="px-4 py-3 text-slate-200">{it.sender || "-"}</td>
                  <td className="px-4 py-3 text-slate-200">{it.subject || "-"}</td>
                  <td className="px-4 py-3 text-slate-200">{it.risk_score.toFixed(2)}</td>
                  <td className="px-4 py-3">
                    <button className="text-xs rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-900" onClick={() => openDetail(it.gmail_message_id)}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
              {latest.length === 0 && (
                <tr>
                  <td className="px-4 py-6 text-slate-400" colSpan="5">
                    No scan results yet. Connect Gmail and click “Scan Now”.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-3xl rounded-2xl border border-slate-800 bg-slate-950 p-4 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-lg font-semibold">Email Details</div>
                <div className="text-xs text-slate-400">Message ID: {selected}</div>
              </div>
              <button className="rounded-lg border border-slate-700 px-3 py-1 text-sm hover:bg-slate-900" onClick={closeDetail}>
                Close
              </button>
            </div>

            {detailBusy && <div className="mt-4 text-sm text-slate-400">Loading...</div>}

            {detail && (
              <div className="mt-4 space-y-4">
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                  <div className="text-xs text-slate-400">From</div>
                  <div className="text-sm text-slate-200 mt-1">{detail.message.sender || "-"}</div>
                  <div className="text-xs text-slate-400 mt-3">Subject</div>
                  <div className="text-sm text-slate-200 mt-1">{detail.message.subject || "-"}</div>
                  <div className="text-xs text-slate-400 mt-3">Date</div>
                  <div className="text-sm text-slate-200 mt-1">{detail.message.date || "-"}</div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">Threat Analysis</div>
                    <Badge level={detail.analysis.threat_level} />
                  </div>
                  <div className="mt-2 text-sm text-slate-200">Risk score: {Number(detail.analysis.risk_score || 0).toFixed(2)}</div>
                  <div className="mt-3">
                    <div className="text-xs text-slate-400">Reasons</div>
                    <ul className="mt-2 list-disc ml-5 text-sm text-slate-200 space-y-1">
                      {(detail.analysis.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                  <div className="mt-3">
                    <div className="text-xs text-slate-400">Recommendations</div>
                    <ul className="mt-2 list-disc ml-5 text-sm text-slate-200 space-y-1">
                      {(detail.analysis.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                  <div className="text-sm font-medium">Body (safe view)</div>
                  <pre className="mt-2 whitespace-pre-wrap text-sm text-slate-200 max-h-64 overflow-auto">{detail.message.body || detail.message.snippet || ""}</pre>
                </div>

                {detail.message.attachments?.length > 0 && (
                  <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                    <div className="text-sm font-medium">Attachments</div>
                    <ul className="mt-2 text-sm text-slate-200 space-y-1">
                      {detail.message.attachments.map((a, i) => (
                        <li key={i} className="flex justify-between gap-3">
                          <span>{a.filename}</span>
                          <span className="text-slate-400">{a.mime_type || "-"} • {a.size || 0} bytes</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

    </Shell>
  )
}

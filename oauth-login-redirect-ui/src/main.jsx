import React from 'react'
import { createRoot } from 'react-dom/client'
function App() {
  React.useEffect(() => {
    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    let target = (import.meta.env.VITE_REDIRECT_URI || 'http://localhost:5174/oidc/callback')
    try {
      if (state) { const st = new URLSearchParams(state); if (st.get('target')) target = st.get('target') }
    } catch {}
    const to = new URL(target)
    if (code) to.searchParams.set('code', code)
    if (state) to.searchParams.set('state', state)
    window.location.replace(to.toString())
  }, [])
  return <div style={{fontFamily:'sans-serif',padding:24}}>
    <h2>Redirecting…</h2>
    <p>If not redirected, <a href={import.meta.env.VITE_REDIRECT_URI || "http://localhost:5174/oidc/callback"}>click here</a>.</p>
  </div>
}
createRoot(document.getElementById('root')).render(<App/>)

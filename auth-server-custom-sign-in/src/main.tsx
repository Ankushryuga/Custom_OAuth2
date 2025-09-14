import React from 'react'
import { createRoot } from 'react-dom/client'
import { motion } from 'framer-motion'
import './index.css'

type Csrf = { headerName: string, parameterName: string, token: string }

function useCsrf() {
  const [csrf, setCsrf] = React.useState<Csrf | null>(null)
  React.useEffect(() => {
    fetch('/csrf', { credentials: 'include' })
      .then(r => r.json()).then(setCsrf).catch(() => setCsrf(null))
  }, [])
  return csrf
}

function App() {
  const csrf = useCsrf()
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    const url = new URL(window.location.href)
    if (url.searchParams.get('error')) setError('Invalid username or password')
  }, [])

  return (
    <div className="relative min-h-screen bg-slate-950 bg-grid overflow-hidden">
      <div className="pointer-events-none absolute -top-40 -left-40 h-96 w-96 rounded-full bg-primary-700 blur-[120px] opacity-30 animate-float"></div>
      <div className="pointer-events-none absolute -bottom-40 -right-40 h-[28rem] w-[28rem] rounded-full bg-indigo-500 blur-[140px] opacity-20 animate-float"></div>

      <div className="relative z-10 flex min-h-screen items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="glass max-w-md w-full rounded-3xl p-8 shadow-glow"
        >
          <div className="mb-6 text-center">
            <motion.div
              initial={{ rotate: -6, scale: 0.9 }}
              animate={{ rotate: 0, scale: 1 }}
              transition={{ type: 'spring', stiffness: 120, damping: 10 }}
              className="mx-auto mb-3 h-14 w-14 rounded-2xl bg-gradient-to-br from-primary-400 to-primary-700 grid place-items-center text-white text-2xl font-black shadow-lg"
            >
              🔐
            </motion.div>
            <h1 className="text-2xl font-bold text-white">Welcome back</h1>
            <p className="text-white/60">Sign in to continue</p>
          </div>

          {error && <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-red-200">{error}</div>}

          <form method="post" action="/login" className="space-y-4" onSubmit={() => setLoading(true)}>
            <div>
              <label className="mb-2 block text-sm text-white/80">Email or Username</label>
              <input name="username" type="text" placeholder="you@example.com" className="input" required />
            </div>
            <div>
              <label className="mb-2 block text-sm text-white/80">Password</label>
              <input name="password" type="password" placeholder="••••••••" className="input" required />
            </div>
            {csrf && <input type="hidden" name={csrf.parameterName} value={csrf.token} />}
            <button className="btn" disabled={!csrf || loading}>{loading ? 'Signing in…' : 'Sign in'}</button>
          </form>

          <p className="mt-6 text-center text-xs text-white/50">By continuing you agree to our Terms and Privacy Policy.</p>
        </motion.div>
      </div>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)

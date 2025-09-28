// // // // import React from 'react'
// // // // import { createRoot } from 'react-dom/client'
// // // // import './index.css'
// // // //
// // // // type Csrf = { headerName: string; parameterName: string; token: string }
// // // //
// // // // /** Fetch Spring's CSRF token so the login POST succeeds */
// // // // function useCsrf(): Csrf | null {
// // // //   const [csrf, setCsrf] = React.useState<Csrf | null>(null)
// // // //   React.useEffect(() => {
// // // //     fetch('/csrf', { credentials: 'include' })
// // // //       .then(r => r.ok ? r.json() : Promise.reject(new Error('CSRF fetch failed')))
// // // //       .then((json: Csrf) => setCsrf(json))
// // // //       .catch(() => setCsrf(null))
// // // //   }, [])
// // // //   return csrf
// // // // }
// // // //
// // // // function App() {
// // // //   const csrf = useCsrf()
// // // //   const [loading, setLoading] = React.useState(false)
// // // //   const [error, setError] = React.useState<string | null>(null)
// // // //
// // // //   // SAS appends ?continue=... to /login — keep it on POST so it can resume /oauth2/authorize
// // // //   const [cont] = React.useState(() => new URL(window.location.href).searchParams.get('continue') || '')
// // // // console.log("cont", cont);
// // // //   React.useEffect(() => {
// // // //     const u = new URL(window.location.href)
// // // //     if (u.searchParams.get('error')) setError('Invalid username or password')
// // // //   }, [])
// // // //
// // // //   return (
// // // //     <div className="min-h-screen bg-slate-950 text-white grid place-items-center p-6">
// // // //       <div className="w-full max-w-md rounded-2xl p-8 bg-white/5 backdrop-blur border border-white/10 shadow-xl">
// // // //         <h1 className="text-2xl font-bold mb-6">Sign in</h1>
// // // //
// // // //         {error && (
// // // //           <div className="mb-4 rounded-md bg-red-500/20 border border-red-500/40 px-4 py-3 text-red-200">
// // // //             {error}
// // // //           </div>
// // // //         )}
// // // //
// // // //         <form
// // // //           method="post"
// // // //           action="/login"
// // // //           className="space-y-4"
// // // //           onSubmit={() => setLoading(true)}
// // // //         >
// // // //           <div>
// // // //             <label className="block mb-1 text-sm text-white/80">Username</label>
// // // //             <input
// // // //               name="username"
// // // //               className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none"
// // // //               required
// // // //             />
// // // //           </div>
// // // //
// // // //           <div>
// // // //             <label className="block mb-1 text-sm text-white/80">Password</label>
// // // //             <input
// // // //               name="password"
// // // //               type="password"
// // // //               className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none"
// // // //               required
// // // //             />
// // // //           </div>
// // // //
// // // //           {/* ✅ Echo back SAS 'continue' value so it can resume authorize */}
// // // //           {cont ? <input type="hidden" name="continue" value={cont} /> : null}
// // // //
// // // //           {/* ✅ CSRF token from /csrf */}
// // // //           {csrf ? (
// // // //             <input type="hidden" name={csrf.parameterName} value={csrf.token} />
// // // //           ) : null}
// // // //
// // // //           <button
// // // //             className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 transition px-3 py-2"
// // // //             disabled={!csrf || loading}
// // // //           >
// // // //             {loading ? 'Signing in…' : 'Sign in'}
// // // //           </button>
// // // //         </form>
// // // //
// // // //       </div>
// // // //     </div>
// // // //   )
// // // // }
// // // //
// // // // createRoot(document.getElementById('root')!).render(<App />)
// // //
// // //
// // //
// // //
// // // import React from 'react'
// // // import { createRoot } from 'react-dom/client'
// // // import './index.css'
// // //
// // // type Csrf = { headerName: string; parameterName: string; token: string }
// // //
// // // function useCsrf(): Csrf | null {
// // //   const [csrf, setCsrf] = React.useState<Csrf | null>(null)
// // //   React.useEffect(() => {
// // //     fetch('/csrf', { credentials: 'include' })
// // //       .then(r => r.ok ? r.json() : Promise.reject(new Error('CSRF fetch failed')))
// // //       .then((json: Csrf) => setCsrf(json))
// // //       .catch(() => setCsrf(null))
// // //   }, [])
// // //   return csrf
// // // }
// // //
// // // function App() {
// // //   const csrf = useCsrf()
// // //   const [loading, setLoading] = React.useState(false)
// // //   const [msg, setMsg] = React.useState<string | null>(null)
// // //
// // //   React.useEffect(() => {
// // //     const u = new URL(window.location.href)
// // //     if (u.searchParams.get('error')) setMsg('Invalid username or password')
// // //   }, [])
// // //
// // //   return (
// // //     <div className="min-h-screen bg-slate-950 text-white grid place-items-center p-6">
// // //       <div className="w-full max-w-md rounded-2xl p-8 bg-white/5 backdrop-blur border border-white/10 shadow-xl">
// // //         <h1 className="text-2xl font-bold mb-6">Sign in</h1>
// // //
// // //         {msg && (
// // //           <div className="mb-4 rounded-md bg-amber-500/20 border border-amber-500/40 px-4 py-3 text-amber-200">
// // //             {msg}
// // //           </div>
// // //         )}
// // //
// // //         <form method="post" action="/login" className="space-y-4" onSubmit={() => setLoading(true)}>
// // //           <div>
// // //             <label className="block mb-1 text-sm text-white/80">Username</label>
// // //             <input name="username" autoComplete="username"
// // //                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
// // //           </div>
// // //           <div>
// // //             <label className="block mb-1 text-sm text-white/80">Password</label>
// // //             <input name="password" type="password" autoComplete="current-password"
// // //                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
// // //           </div>
// // //           {csrf ? (<input type="hidden" name={csrf.parameterName} value={csrf.token} />) : null}
// // //           <button className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 transition px-3 py-2"
// // //                   disabled={!csrf || loading}>
// // //             {loading ? 'Signing in…' : 'Sign in'}
// // //           </button>
// // //         </form>
// // //       </div>
// // //     </div>
// // //   )
// // // }
// // //
// // // createRoot(document.getElementById('root')!).render(<App />)
// //
// // // login-ui/src/main.tsx
// // import React from 'react'
// // import { createRoot } from 'react-dom/client'
// // import './index.css'
// //
// // type Csrf = { headerName: string; parameterName: string; token: string }
// //
// // function useCsrf(): Csrf | null {
// //   const [csrf, setCsrf] = React.useState<Csrf | null>(null)
// //   React.useEffect(() => {
// //     fetch('/csrf', { credentials: 'include' })
// //       .then(r => r.ok ? r.json() : Promise.reject(new Error('CSRF fetch failed')))
// //       .then((json: Csrf) => setCsrf(json))
// //       .catch(() => setCsrf(null))
// //   }, [])
// //   return csrf
// // }
// //
// // function App() {
// //   const csrf = useCsrf()
// //   const [loading, setLoading] = React.useState(false)
// //   const [msg, setMsg] = React.useState<string | null>(null)
// //
// //   React.useEffect(() => {
// //     const u = new URL(window.location.href)
// //     if (u.searchParams.get('error')) setMsg('Invalid username or password')
// //   }, [])
// //
// //   return (
// //     <div className="min-h-screen bg-slate-950 text-white grid place-items-center p-6">
// //       <div className="w-full max-w-md rounded-2xl p-8 bg-white/5 backdrop-blur border border-white/10 shadow-xl">
// //         <h1 className="text-2xl font-bold mb-6">Sign in</h1>
// //
// //         {msg && (
// //           <div className="mb-4 rounded-md bg-amber-500/20 border border-amber-500/40 px-4 py-3 text-amber-200">
// //             {msg}
// //           </div>
// //         )}
// //
// //         <form method="post" action="/login" className="space-y-4" onSubmit={() => setLoading(true)}>
// //           <div>
// //             <label className="block mb-1 text-sm text-white/80">Username</label>
// //             <input name="username" autoComplete="username"
// //                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
// //           </div>
// //           <div>
// //             <label className="block mb-1 text-sm text-white/80">Password</label>
// //             <input name="password" type="password" autoComplete="current-password"
// //                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
// //           </div>
// //           {csrf ? (<input type="hidden" name={csrf.parameterName} value={csrf.token} />) : null}
// //           <button className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 transition px-3 py-2"
// //                   disabled={!csrf || loading}>
// //             {loading ? 'Signing in…' : 'Sign in'}
// //           </button>
// //         </form>
// //       </div>
// //     </div>
// //   )
// // }
// //
// // createRoot(document.getElementById('root')!).render(<App />)
//
// // auth-server/login-ui/src/main.tsx
// import React from 'react'
// import { createRoot } from 'react-dom/client'
// import './index.css'
//
// type Csrf = { headerName: string; parameterName: string; token: string }
//
// function useCsrf(): Csrf | null {
//   const [csrf, setCsrf] = React.useState<Csrf | null>(null)
//   React.useEffect(() => {
//     fetch('/csrf', { credentials: 'include' })
//       .then(r => r.ok ? r.json() : Promise.reject(new Error('CSRF fetch failed')))
//       .then((json: Csrf) => setCsrf(json))
//       .catch(() => setCsrf(null))
//   }, [])
//   return csrf
// }
//
// function App() {
//   const csrf = useCsrf()
//   const [loading, setLoading] = React.useState(false)
//   const [msg, setMsg] = React.useState<string | null>(null)
//   const [cont, setCont] = React.useState<string>('')
//
//   // Fetch the resume URL (SavedRequest or cookie) to include in the POST
//   React.useEffect(() => {
//     fetch('/login/context', { credentials: 'include' })
//       .then(r => r.ok ? r.json() : { continue: '' })
//       .then((j) => setCont(j?.continue || ''))
//       .catch(() => setCont(''))
//
//     const u = new URL(window.location.href)
//     if (u.searchParams.get('error')) setMsg('Invalid username or password')
//   }, [])
//
//   return (
//     <div className="min-h-screen bg-slate-950 text-white grid place-items-center p-6">
//       <div className="w-full max-w-md rounded-2xl p-8 bg-white/5 backdrop-blur border border-white/10 shadow-xl">
//         <h1 className="text-2xl font-bold mb-6">Sign in</h1>
//
//         {msg && (
//           <div className="mb-4 rounded-md bg-amber-500/20 border border-amber-500/40 px-4 py-3 text-amber-200">
//             {msg}
//           </div>
//         )}
//
//         <form method="post" action="/login" className="space-y-4" onSubmit={() => setLoading(true)}>
//           <div>
//             <label className="block mb-1 text-sm text-white/80">Username</label>
//             <input name="username" autoComplete="username"
//                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
//           </div>
//           <div>
//             <label className="block mb-1 text-sm text-white/80">Password</label>
//             <input name="password" type="password" autoComplete="current-password"
//                    className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
//           </div>
//
//           {/* Hidden field ensures the original authorize URL is posted back even if SavedRequest/cookie are flaky */}
//           {cont ? <input type="hidden" name="continue" value={cont} /> : null}
//
//           {csrf ? (<input type="hidden" name={csrf.parameterName} value={csrf.token} />) : null}
//
//           <button className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 transition px-3 py-2"
//                   disabled={!csrf || loading}>
//             {loading ? 'Signing in…' : 'Sign in'}
//           </button>
//         </form>
//
//         {/* small debug footer (optional) */}
//         <div className="mt-3 text-xs text-white/50 break-all">{cont ? <>continue=&nbsp;{cont}</> : null}</div>
//       </div>
//     </div>
//   )
// }
//
// createRoot(document.getElementById('root')!).render(<App />)

import React from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'

type Csrf = { headerName: string; parameterName: string; token: string }

function useCsrf(): Csrf | null {
  const [csrf, setCsrf] = React.useState<Csrf | null>(null)
  React.useEffect(() => {
    fetch('/csrf', { credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('CSRF fetch failed')))
      .then((json: Csrf) => setCsrf(json))
      .catch(() => setCsrf(null))
  }, [])
  return csrf
}

function App() {
  const csrf = useCsrf()
  const [loading, setLoading] = React.useState(false)
  const [msg, setMsg] = React.useState<string | null>(null)
  const [cont, setCont] = React.useState<string>('')

  React.useEffect(() => {
    fetch('/login/context', { credentials: 'include' })
      .then(r => r.ok ? r.json() : { continue: '' })
      .then((j) => setCont(j?.continue || ''))
      .catch(() => setCont(''))

    const u = new URL(window.location.href)
    if (u.searchParams.get('error')) setMsg('Invalid username or password')
  }, [])

  return (
    <div className="min-h-screen bg-slate-950 text-white grid place-items-center p-6">
      <div className="w-full max-w-md rounded-2xl p-8 bg-white/5 backdrop-blur border border-white/10 shadow-xl">
        <h1 className="text-2xl font-bold mb-6">Sign in</h1>

        {msg && (
          <div className="mb-4 rounded-md bg-amber-500/20 border border-amber-500/40 px-4 py-3 text-amber-200">
            {msg}
          </div>
        )}

        <form method="post" action="/login" className="space-y-4" onSubmit={() => setLoading(true)}>
          <div>
            <label className="block mb-1 text-sm text-white/80">Username</label>
            <input name="username" autoComplete="username"
                   className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
          </div>
          <div>
            <label className="block mb-1 text-sm text-white/80">Password</label>
            <input name="password" type="password" autoComplete="current-password"
                   className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 outline-none" required />
          </div>

          {/* Hidden field ensures the original authorize URL is posted back */}
          {cont ? <input type="hidden" name="continue" value={cont} /> : null}

          {csrf ? (<input type="hidden" name={csrf.parameterName} value={csrf.token} />) : null}

          <button className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 transition px-3 py-2"
                    disabled={loading}      // ⬅️ was: disabled={!csrf || loading}
                  >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        {/* debug footer */}
        <div className="mt-3 text-xs text-white/50 break-all">{cont ? <>continue=&nbsp;{cont}</> : null}</div>
      </div>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)

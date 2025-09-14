// // import React from 'react'
// // import { createRoot } from 'react-dom/client'
// // import {
// //   BrowserRouter,
// //   Routes,
// //   Route,
// //   Navigate,
// //   useNavigate,
// //   useLocation
// // } from 'react-router-dom'
// //
// // /** ===== Env ===== */
// // const env = {
// //   issuer: import.meta.env.VITE_ISSUER,
// //   clientId: import.meta.env.VITE_CLIENT_ID,
// //   scope: import.meta.env.VITE_SCOPE || 'openid profile email api.read',
// //   redirectUri: import.meta.env.VITE_REDIRECT_URI,   // e.g., http://localhost:5174/oidc/callback
// //   rsBase: import.meta.env.VITE_RS_BASE
// // }
// //
// // /** ===== PKCE helpers ===== */
// // function b64url(ab) {
// //   return btoa(String.fromCharCode(...new Uint8Array(ab)))
// //     .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
// // }
// // async function sha256(s) {
// //   const ab = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
// //   return b64url(ab)
// // }
// // function gen(n = 32) {
// //   const a = new Uint8Array(n)
// //   crypto.getRandomValues(a)
// //   return b64url(a.buffer)
// // }
// // const save = (k, v) => sessionStorage.setItem(k, JSON.stringify(v))
// // const load = (k) => { const v = sessionStorage.getItem(k); return v ? JSON.parse(v) : null }
// // const del  = (k) => sessionStorage.removeItem(k)
// //
// // // Prevent open-redirects: only allow same-origin, root-relative paths
// // const safePath = (p) => (typeof p === 'string' && p.startsWith('/')) ? p : '/'
// //
// // /** ===== Auth Context (tokens in sessionStorage) ===== */
// // const AuthCtx = React.createContext(null)
// //
// // function AuthProvider({ children }) {
// //   const [tokens, setTokens] = React.useState(() => load('tokens'))
// //
// //   const setTokensPersist = (t) => {
// //     setTokens(t)
// //     if (t) save('tokens', t)
// //     else del('tokens')
// //   }
// //
// //   const logout = () => {
// //     setTokensPersist(null)
// //     sessionStorage.clear()
// //   }
// //
// //   return (
// //     <AuthCtx.Provider value={{ tokens, setTokens: setTokensPersist, logout }}>
// //       {children}
// //     </AuthCtx.Provider>
// //   )
// // }
// // const useAuth = () => React.useContext(AuthCtx)
// //
// // /** ===== ProtectedRoute: require tokens, else go to /login ===== */
// // function ProtectedRoute({ children }) {
// //   const { tokens } = useAuth()
// //   const loc = useLocation()
// //   if (!tokens) {
// //     // Remember where user wanted to go; login() also saves returnTo, but
// //     // this ensures /login shows after direct deep-link to protected route.
// //     save('pkce_return_hint', (loc.pathname + loc.search + loc.hash) || '/')
// //     return <Navigate to="/login" replace />
// //   }
// //   return children
// // }
// //
// // /** ===== LoginPage (starts PKCE) ===== */
// // function LoginPage() {
// //   const startLogin = async () => {
// //     try {
// //       const verifier = gen(48)
// //       const challenge = await sha256(verifier)
// //       const state = gen(24)
// //       const nonce = gen(24)
// //
// //       // Prefer the last protected route user tried; else current route; else /
// //       const hinted = load('pkce_return_hint')
// //       const current = (location.pathname + location.search + location.hash) || '/'
// //       const returnTo = hinted || (current === '/login' ? '/' : current)
// //
// //       save('pkce', { verifier, state, nonce, returnTo })
// //
// //       const u = new URL(env.issuer + '/oauth2/authorize')
// //       u.searchParams.set('response_type', 'code')
// //       u.searchParams.set('client_id', env.clientId)
// //       u.searchParams.set('redirect_uri', env.redirectUri)
// //       u.searchParams.set('scope', env.scope)
// //       u.searchParams.set('code_challenge', challenge)
// //       u.searchParams.set('code_challenge_method', 'S256')
// //       u.searchParams.set('state', state)
// //       u.searchParams.set('nonce', nonce)
// //       console.log('AUTH URL →', u.toString())
// //       window.location.href = u.toString()
// //     } catch (error) {
// //       console.error(error)
// //       alert('Failed to start login: ' + String(error))
// //     }
// //   }
// //
// //   return (
// //     <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
// //       <h2>Login</h2>
// //       <p>This page is public. Click to authenticate.</p>
// //       <button onClick={startLogin}>Login with OIDC</button>
// //     </div>
// //   )
// // }
// //
// // /** ===== CallbackPage: handle code -> token exchange, then go home/returnTo ===== */
// // function CallbackPage() {
// //   const { setTokens } = useAuth()
// //   const navigate = useNavigate()
// //
// //   React.useEffect(() => {
// //     (async () => {
// //       const url = new URL(window.location.href)
// //       const code = url.searchParams.get('code')
// //       const state = url.searchParams.get('state') || ''
// //
// //       if (!code) { navigate('/', { replace: true }); return }
// //
// //       const saved = load('pkce')
// //       if (!saved || saved.state !== state) {
// //         alert('State mismatch; please try logging in again.')
// //         navigate('/login', { replace: true })
// //         return
// //       }
// //
// //       // Exchange code
// //       const body = new URLSearchParams({
// //         grant_type: 'authorization_code',
// //         code,
// //         redirect_uri: env.redirectUri,
// //         client_id: env.clientId,
// //         code_verifier: saved.verifier
// //       })
// //
// //       const res = await fetch(env.issuer + '/oauth2/token', {
// //         method: 'POST',
// //         headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
// //         body,
// //         credentials: 'include'
// //       })
// //       const json = await res.json()
// //       if (!res.ok) {
// //         console.error('Token exchange failed:', json)
// //         alert('Token exchange failed: ' + (json.error_description || json.error || 'unknown'))
// //         navigate('/login', { replace: true })
// //         return
// //       }
// //
// //       // Persist tokens & navigate back
// //       setTokens(json)
// //       const returnTo = safePath(saved.returnTo || load('pkce_return_hint'))
// //       // Clean URL + go to destination
// //       navigate(returnTo || '/', { replace: true })
// //       del('pkce')
// //       del('pkce_return_hint')
// //     })()
// //   }, [navigate, setTokens])
// //
// //   return (
// //     <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
// //       <h2>Finishing sign-in…</h2>
// //       <p>Please wait.</p>
// //     </div>
// //   )
// // }
// //
// // /** ===== HelloPage (protected, default) ===== */
// // function HelloPage() {
// //   const { tokens, logout } = useAuth()
// //
// //   const callApi = async () => {
// //     const res = await fetch(env.rsBase + '/data', {
// //       headers: { Authorization: `Bearer ${tokens?.access_token || ''}` }
// //     })
// //     alert('API response:\n' + await res.text())
// //   }
// //
// //   return (
// //     <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
// //       <h2>Hello (Protected)</h2>
// //       <p>You are signed in. 🎉</p>
// //       <button onClick={callApi}>GET /data</button>{' '}
// //       <button onClick={logout}>Logout (local)</button>
// //       <h3>Tokens</h3>
// //       <pre>{JSON.stringify(tokens, null, 2)}</pre>
// //     </div>
// //   )
// // }
// //
// // /** ===== App (routes) ===== */
// // function AppRoutes() {
// //   return (
// //     <Routes>
// //       {/* Default protected home */}
// //       <Route path="/" element={
// //         <ProtectedRoute><HelloPage /></ProtectedRoute>
// //       } />
// //
// //       {/* Public login page */}
// //       <Route path="/login" element={<LoginPage />} />
// //
// //       {/* OIDC callback */}
// //       <Route path={new URL(env.redirectUri).pathname} element={<CallbackPage />} />
// //
// //       {/* Fallback */}
// //       <Route path="*" element={<Navigate to="/" replace />} />
// //     </Routes>
// //   )
// // }
// //
// // function App() {
// //   return (
// //     <AuthProvider>
// //       <BrowserRouter>
// //         <AppRoutes />
// //       </BrowserRouter>
// //     </AuthProvider>
// //   )
// // }
// //
// // createRoot(document.getElementById('root')).render(<App />)
//
// import React from 'react'
// import { createRoot } from 'react-dom/client'
// import { BrowserRouter, Routes, Route, useNavigate, Link } from 'react-router-dom'
//
// const env = {
//   issuer: import.meta.env.VITE_ISSUER,
//   clientId: import.meta.env.VITE_CLIENT_ID,
//   scope: import.meta.env.VITE_SCOPE || 'openid profile email api.read',
//   redirectUri: import.meta.env.VITE_REDIRECT_URI, // e.g. http://localhost:5174/oidc/callback
//   rsBase: import.meta.env.VITE_RS_BASE
// }
//
// function b64url(ab) {
//   return btoa(String.fromCharCode(...new Uint8Array(ab)))
//     .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
// }
// async function sha256(str) {
//   const ab = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
//   return b64url(ab)
// }
// function gen(n = 32) {
//   const a = new Uint8Array(n)
//   crypto.getRandomValues(a)
//   return b64url(a.buffer)
// }
// const save = (k, v) => sessionStorage.setItem(k, JSON.stringify(v))
// const load = (k) => { const v = sessionStorage.getItem(k); return v ? JSON.parse(v) : null }
//
// function Home() {
//   const [tokens, setTokens] = React.useState(load('tokens'))
//   const doLogin = async () => {
//     const verifier = gen(48)
//     const challenge = await sha256(verifier)
//     const state = gen(24)
//     const nonce = gen(24)
//     save('pkce', { verifier, state, nonce })
//     const u = new URL(env.issuer + '/oauth2/authorize')
//     u.searchParams.set('response_type', 'code')
//     u.searchParams.set('client_id', env.clientId)
//     u.searchParams.set('redirect_uri', env.redirectUri)
//     u.searchParams.set('scope', env.scope)
//     u.searchParams.set('code_challenge', challenge)
//     u.searchParams.set('code_challenge_method', 'S256')
//     u.searchParams.set('state', state)
//     u.searchParams.set('nonce', nonce)
//     window.location.href = u.toString()
//   }
//   const logout = () => { sessionStorage.clear(); setTokens(null) }
//   const callApi = async () => {
//     const res = await fetch(env.rsBase + '/data', {
//       headers: { Authorization: `Bearer ${tokens?.access_token || ''}` }
//     })
//     alert('API:\n' + await res.text())
//   }
//   return (
//     <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
//       <h2>Client UI (PKCE)</h2>
//       {!tokens ? (
//         <button onClick={doLogin}>Login with OIDC</button>
//       ) : (
//         <>
//           <button onClick={logout}>Logout (local)</button>
//           <h3>Tokens</h3>
//           <pre>{JSON.stringify(tokens, null, 2)}</pre>
//           <button onClick={callApi}>GET /data</button>
//         </>
//       )}
//       <p style={{ marginTop: 16 }}><Link to="/oidc/callback">Callback route</Link></p>
//     </div>
//   )
// }
//
// function Callback() {
//   const nav = useNavigate()
//   React.useEffect(() => {
//     (async () => {
//       try {
//         const url = new URL(window.location.href)
//         const code = url.searchParams.get('code')
//         const state = url.searchParams.get('state') || ''
//         if (!code) return
//         const saved = load('pkce')
//         if (!saved || saved.state !== state) throw new Error('state mismatch')
//         const body = new URLSearchParams({
//           grant_type: 'authorization_code',
//           code,
//           redirect_uri: env.redirectUri,
//           client_id: env.clientId,
//           code_verifier: saved.verifier
//         })
//         const res = await fetch(env.issuer + '/oauth2/token', {
//           method: 'POST',
//           headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
//           body,
//           credentials: 'include'
//         })
//         const json = await res.json()
//         if (!res.ok) throw new Error(JSON.stringify(json))
//         save('tokens', json)
//         sessionStorage.removeItem('pkce')
//         nav('/', { replace: true })
//       } catch (e) {
//         alert('Callback failed: ' + e)
//       }
//     })()
//   }, [nav])
//   return <div style={{ padding: 20, fontFamily: 'system-ui, sans-serif' }}>
//     <h3>Exchanging code…</h3>
//   </div>
// }
//
// function App() {
//   return (
//     <BrowserRouter>
//       <Routes>
//         <Route path="/" element={<Home/>}/>
//         <Route path="/oidc/callback" element={<Callback/>}/>
//       </Routes>
//     </BrowserRouter>
//   )
// }
//
// createRoot(document.getElementById('root')).render(<App/>)

import React from 'react'
import { createRoot } from 'react-dom/client'

const env = {
  issuer: import.meta.env.VITE_ISSUER,
  clientId: import.meta.env.VITE_CLIENT_ID,
  scope: import.meta.env.VITE_SCOPE || 'openid profile email api.read',
  redirectUri: import.meta.env.VITE_REDIRECT_URI,   // e.g., http://localhost:5174/oidc/callback
  rsBase: import.meta.env.VITE_RS_BASE
}

function b64url(ab) {
  return btoa(String.fromCharCode(...new Uint8Array(ab)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
}
async function sha256(s) {
  const ab = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return b64url(ab)
}
function gen(n = 32) {
  const a = new Uint8Array(n)
  crypto.getRandomValues(a)
  return b64url(a.buffer)
}
const save = (k, v) => sessionStorage.setItem(k, JSON.stringify(v))
const load = (k) => { const v = sessionStorage.getItem(k); return v ? JSON.parse(v) : null }

// Prevent open-redirects: only allow same-origin, root-relative paths
const safePath = (p) => (typeof p === 'string' && p.startsWith('/')) ? p : '/'

function App() {
  const [tokens, setTokens] = React.useState(null)
  const [error, setError] = React.useState(null)

  React.useEffect(() => {
    const url = new URL(window.location.href)
    const callbackPath = new URL(env.redirectUri).pathname

    if (url.pathname.startsWith(callbackPath) && url.searchParams.get('code')) {
      (async () => {
        try {
          const st = url.searchParams.get('state') || ''
          const saved = load('pkce')
          if (!saved || saved.state !== st) { setError({ error: 'state_mismatch' }); return }

          const code = url.searchParams.get('code')
          const body = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: env.redirectUri,
            client_id: env.clientId,
            code_verifier: saved.verifier
          })

//           const res = await fetch(env.issuer + '/oauth2/token', {
//             method: 'POST',
//             headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
//             body,
//             credentials: 'include'
//           })

          const res= await fetch(env.issuer+'/oauth2/token', {
              method:'POST',
              headers:{
                  'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
                  'Accept':'application/json'
                  },
              body,
              credentials:'omit'
              })
          const text = await res.text()
          let json = null
          if (text) {
            try { json = JSON.parse(text) } catch (e) {
              throw new Error(`Token HTTP ${res.status} ${res.statusText}. Body: ${text.slice(0,400)}`)
            }
          }
          if (!res.ok) {
            throw new Error(json ? JSON.stringify(json) : `Token HTTP ${res.status}`)
          }

          setTokens(json)

          // 👇 Navigate back to origin path (or "/")
          const returnTo = safePath(saved.returnTo)
          window.history.replaceState({}, '', returnTo)

        } catch (e) {
            console.log(e);
          setError({ error: 'exchange_failed', detail: String(e) })
        } finally {
          sessionStorage.removeItem('pkce')
        }
      })()
    }
  }, [])

  const login = async () => {
    const verifier = gen(48)
    const challenge = await sha256(verifier)
    const state = gen(24)
    const nonce = gen(24)

    // remember the current SPA route (with query+hash)
    const returnTo = (location.pathname + location.search + location.hash) || '/'
    save('pkce', { verifier, state, nonce, returnTo })

    const u = new URL(env.issuer + '/oauth2/authorize')
    u.searchParams.set('response_type', 'code')
    u.searchParams.set('client_id', env.clientId)
    u.searchParams.set('redirect_uri', env.redirectUri)
    u.searchParams.set('scope', env.scope)
    u.searchParams.set('code_challenge', challenge)
    u.searchParams.set('code_challenge_method', 'S256')
    u.searchParams.set('state', state)
    u.searchParams.set('nonce', nonce)
    window.location.href = u.toString()
  }

  const api = async () => {
    const res = await fetch(env.rsBase + '/data', {
      headers: { Authorization: `Bearer ${tokens?.access_token || ''}` }
    })
    alert('API response:\n' + await res.text())
  }

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
      <h2>Client UI (PKCE)</h2>

      {!tokens ? (
        <button onClick={login}>Login</button>
      ) : (
        <>
          <button onClick={() => { setTokens(null); sessionStorage.clear() }}>Logout (local)</button>

          <h3>Tokens</h3>
          <pre>{JSON.stringify(tokens, null, 2)}</pre>

          <h3>ID Token Claims</h3>
          <pre>—</pre>

          <h3>Call Resource Server</h3>
          <button onClick={api}>GET /data</button>

          <p>Issuer: {env.issuer} | Client: {env.clientId}</p>
        </>
      )}

      {error && (
        <>
          <h3>Error</h3>
          <pre>{JSON.stringify(error, null, 2)}</pre>
        </>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')).render(<App />)

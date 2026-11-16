import { useState, lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login.jsx'
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'))

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '')

  if (!token) {
    return <Login onLogin={(t) => {
      localStorage.setItem('token', t)
      setToken(t)
    }} />
  }

  return (
    <Suspense fallback={<div className="bc-empty" role="status">Loading your workspace…</div>}><BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard token={token} onLogout={() => {
          localStorage.removeItem('token')
          setToken('')
        }} />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter></Suspense>
  )
}


export default App

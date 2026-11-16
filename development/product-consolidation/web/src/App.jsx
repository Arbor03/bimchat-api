import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '')

  if (!token) {
    return <Login onLogin={(t) => {
      localStorage.setItem('token', t)
      setToken(t)
    }} />
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard token={token} onLogout={() => {
          localStorage.removeItem('token')
          setToken('')
        }} />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  )
}


export default App
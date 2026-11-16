import { useState } from 'react'
import axios from 'axios'

import { API } from '../api'

export default function Login({ onLogin }) {
  // mode: 'login' | 'forgot' | 'reset'
  const [mode, setMode] = useState('login')

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  // reset flow
  const [code, setCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)

  const clearMsg = () => { setError(''); setInfo('') }

  const goTo = (m) => {
    clearMsg()
    setMode(m)
  }

  const handleLogin = async () => {
    clearMsg()
    setLoading(true)
    try {
      const res = await axios.post(`${API}/auth/login`, { email, password })
      onLogin(res.data.token)
    } catch (err) {
      setError('Invalid email or password!')
    }
    setLoading(false)
  }

  const handleForgot = async () => {
    clearMsg()
    if (!email) { setError('Please enter your email.'); return }
    setLoading(true)
    try {
      await axios.post(`${API}/auth/forgot-password`, { email })
      setInfo('If the email exists, a 6-digit reset code was sent. Check your inbox.')
      setMode('reset')
    } catch (err) {
      setError(err.response?.data?.error || 'Could not send the reset code.')
    }
    setLoading(false)
  }

  const handleReset = async () => {
    clearMsg()
    if (!code.trim()) { setError('Enter the 6-digit code from your email.'); return }
    if (newPassword.length < 6) { setError('Password must be at least 6 characters.'); return }
    if (newPassword !== confirmPassword) { setError('Passwords do not match.'); return }

    setLoading(true)
    try {
      // backend accepts the 6-digit code in the `token` field
      await axios.post(`${API}/auth/reset-password`, {
        token: code.trim(),
        new_password: newPassword,
      })
      setPassword('')
      setCode(''); setNewPassword(''); setConfirmPassword('')
      setMode('login')
      setInfo('Password reset successfully. You can now log in.')
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid or expired reset code.')
    }
    setLoading(false)
  }

  const inputClass =
    'w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500'

  return (
    <div className="bc-login">
      <div className="bc-login-card">
        <div className="bc-brand"><span className="bc-brand-mark">B</span><span>BIMChat</span></div><h1>{mode === 'login' ? 'Welcome back' : 'Account recovery'}</h1>
        <p className="bc-login-sub">
          {mode === 'login' && 'Sign in to your project workspace.'}
          {mode === 'forgot' && 'Reset your password'}
          {mode === 'reset' && 'Enter code & new password'}
        </p>

        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded-lg mb-4 text-sm">
            {error}
          </div>
        )}
        {info && (
          <div className="bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm">
            {info}
          </div>
        )}

        {/* ---------- LOGIN ---------- */}
        {mode === 'login' && (
          <>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()}
                className={inputClass}
                placeholder="your@email.com"
              />
            </div>
            <div className="mb-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()}
                className={inputClass}
                placeholder="••••••••"
              />
            </div>
            <div className="mb-6 text-right">
              <button
                onClick={() => goTo('forgot')}
                className="text-sm text-blue-700 hover:underline"
              >
                Forgot password?
              </button>
            </div>
            <button
              onClick={handleLogin}
              disabled={loading}
              className="w-full bg-blue-700 text-white py-2 rounded-lg font-semibold hover:bg-blue-800 transition disabled:opacity-50"
            >
              {loading ? 'Logging in...' : 'Login'}
            </button>
          </>
        )}

        {/* ---------- FORGOT (request code) ---------- */}
        {mode === 'forgot' && (
          <>
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleForgot()}
                className={inputClass}
                placeholder="your@email.com"
              />
              <p className="text-xs text-gray-500 mt-2">
                We'll email you a 6-digit code to reset your password.
              </p>
            </div>
            <button
              onClick={handleForgot}
              disabled={loading}
              className="w-full bg-blue-700 text-white py-2 rounded-lg font-semibold hover:bg-blue-800 transition disabled:opacity-50"
            >
              {loading ? 'Sending...' : 'Send code'}
            </button>
            <div className="mt-4 text-center">
              <button
                onClick={() => goTo('login')}
                className="text-sm text-gray-500 hover:underline"
              >
                ← Back to login
              </button>
            </div>
          </>
        )}

        {/* ---------- RESET (code + new password) ---------- */}
        {mode === 'reset' && (
          <>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Reset code</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                className={`${inputClass} tracking-[0.4em] text-center text-lg font-semibold`}
                placeholder="000000"
              />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">New password</label>
              <input
                type="password"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                className={inputClass}
                placeholder="••••••••"
              />
            </div>
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Confirm new password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleReset()}
                className={inputClass}
                placeholder="••••••••"
              />
            </div>
            <button
              onClick={handleReset}
              disabled={loading}
              className="w-full bg-blue-700 text-white py-2 rounded-lg font-semibold hover:bg-blue-800 transition disabled:opacity-50"
            >
              {loading ? 'Resetting...' : 'Reset password'}
            </button>
            <div className="mt-4 flex justify-between">
              <button
                onClick={() => goTo('forgot')}
                className="text-sm text-gray-500 hover:underline"
              >
                Resend code
              </button>
              <button
                onClick={() => goTo('login')}
                className="text-sm text-gray-500 hover:underline"
              >
                ← Back to login
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

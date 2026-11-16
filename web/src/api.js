// Build-time configuration only. Authentication is sent to this trusted API, never to download URLs.
export const API = (import.meta.env.VITE_API_URL || 'https://bimchat-api-production.up.railway.app').replace(/\/$/, '')

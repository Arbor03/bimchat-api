// Use the configured API and attachment ID, never a server-supplied file_url.
export async function fetchAttachment(api, id, token, signal, request = fetch) {
  if (!token || typeof id !== 'string' || !id) throw new Error('Please sign in to download this file.')
  const response = await request(`${api.replace(/\/$/, '')}/attachments/${encodeURIComponent(id)}/content`, {
    headers: { Authorization: `Bearer ${token}` }, signal, redirect: 'error', cache: 'no-store',
  })
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error('This file is no longer accessible. Check your sign-in and project access.')
    throw new Error('The file could not be downloaded. Please try again.')
  }
  return response.blob()
}

export function imageMime(type) {
  return ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(type) ? type : null
}

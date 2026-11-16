import { useEffect, useState } from 'react'
import { fetchAttachment, imageMime } from './attachmentContent'

export default function ProtectedAttachment({ attachment, api, token }) {
  const [attempt, setAttempt] = useState(0)
  const [result, setResult] = useState(null)
  const id = attachment.id
  const type = imageMime(attachment.file_type)
  // A changed session/id must never render bytes from the previous request.
  const current = result?.api === api && result?.id === id && result?.token === token && result?.attempt === attempt && result?.type === type ? result : null

  useEffect(() => {
    if (!type && attempt === 0) return
    const controller = new AbortController()
    let objectUrl
    fetchAttachment(api, id, token, controller.signal).then(blob => {
      if (controller.signal.aborted) return
      objectUrl = URL.createObjectURL(new Blob([blob], { type: type || 'application/octet-stream' }))
      setResult({ api, id, token, attempt, type, url: objectUrl })
    }).catch(error => {
      if (!controller.signal.aborted) setResult({ api, id, token, attempt, type, error: error.message })
    })
    return () => { controller.abort(); if (objectUrl) URL.revokeObjectURL(objectUrl) }
  }, [api, id, token, type, attempt])

  return <div className="mt-2 rounded border border-gray-200 bg-white p-2 text-xs">
    <span className="block truncate text-gray-700">{attachment.file_name}</span>
    {current?.url && type && <img src={current.url} alt={attachment.file_name} className="mt-1 max-w-full max-h-56 rounded" />}
    {current?.url ? <a href={current.url} download={attachment.file_name} className="mt-1 inline-block text-blue-700 underline">Download</a>
      : current?.error ? <div role="alert"><span>{current.error}</span><button type="button" onClick={() => setAttempt(n => n + 1)} className="ml-2 text-blue-700 underline">Retry</button></div>
        : type || attempt > 0 ? <span role="status">Loading file…</span>
          : <button type="button" onClick={() => setAttempt(n => n + 1)} className="mt-1 text-blue-700 underline">Load file</button>}
  </div>
}

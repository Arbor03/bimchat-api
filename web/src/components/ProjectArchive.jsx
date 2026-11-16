import { useEffect, useState } from 'react'
import axios from 'axios'
import Icon from './Icon'

import { API } from '../api'
const normalizedPath = file => (file.relative_path || file.file_name || '').replaceAll('\\', '/').replace(/^\/+|\/+$/g, '')
const parentPath = value => value.includes('/') ? value.slice(0, value.lastIndexOf('/')) : ''
const sizeLabel = size => !Number.isFinite(Number(size)) ? '—' : Number(size) < 1024 ? `${size} B` : Number(size) < 1024 ** 2 ? `${(size / 1024).toFixed(1)} KB` : `${(size / 1024 ** 2).toFixed(1)} MB`
const dateLabel = value => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toLocaleDateString('en-GB') : '—'

export default function ProjectArchive({ projectId, token, onModels }) {
  const [listing, setListing] = useState(null)
  const [folder, setFolder] = useState('')
  const [expanded, setExpanded] = useState({ '': true })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [history, setHistory] = useState(null)
  const [detailError, setDetailError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [downloading, setDownloading] = useState(false)
  const currentListing = listing?.projectId === projectId && listing?.token === token && listing?.refresh === refresh ? listing : null
  const files = currentListing?.files || []
  const loading = !currentListing
  const error = currentListing?.error || ''
  const currentHistory = selected && history?.fileId === selected.id && history?.token === token ? history : null
  const versions = currentHistory?.items ?? null
  const selectFile = file => { setSelected(file); setDetailError('') }
  const reload = () => { setSelected(null); setFolder(''); setSearch(''); setRefresh(value => value + 1) }
  useEffect(() => {
    const controller = new AbortController()
    axios.get(`${API}/drive/files/${projectId}`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal })
      .then(response => { if (!controller.signal.aborted) setListing({ projectId, token, refresh, files: response.data }) })
      .catch(err => { if (!controller.signal.aborted) setListing({ projectId, token, refresh, files: [], error: err.response?.status === 403 ? 'You do not have access to these project files.' : 'Project files could not be loaded. Please try again.' }) })
    return () => controller.abort()
  }, [projectId, token, refresh])
  useEffect(() => {
    if (!selected) return
    const controller = new AbortController()
    axios.get(`${API}/drive/files/${selected.id}/versions`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal })
      .then(response => { if (!controller.signal.aborted) setHistory({ fileId: selected.id, token, items: response.data }) })
      .catch(() => { if (!controller.signal.aborted) setHistory({ fileId: selected.id, token, items: [], error: 'Version history could not be loaded.' }) })
    return () => controller.abort()
  }, [selected, token])
  const directories = new Set([''])
  files.forEach(file => { let current = parentPath(normalizedPath(file)); while (current) { directories.add(current); current = parentPath(current) } })
  const children = current => [...directories].filter(item => item && parentPath(item) === current).sort((a, b) => a.localeCompare(b))
  const visibleFiles = files.filter(file => search ? normalizedPath(file).toLowerCase().includes(search.toLowerCase()) : parentPath(normalizedPath(file)) === folder)
  const navigate = value => { setFolder(value); setSearch(''); setSelected(null); setExpanded(old => ({ ...old, [value]: true })) }
  const tree = (value = '', depth = 0) => <div key={value || 'root'}>
    <div className={`bc-tree-row ${folder === value && !search ? 'is-selected' : ''}`} style={{ paddingLeft: 8 + depth * 16 }}>
      {children(value).length ? <button className="bc-tree-toggle" aria-label={`${expanded[value] ? 'Collapse' : 'Expand'} ${value || 'Project files'}`} aria-expanded={!!expanded[value]} onClick={() => setExpanded(old => ({ ...old, [value]: !old[value] }))}><Icon name={expanded[value] ? 'minus' : 'plus'} size={14} /></button> : <span className="bc-tree-spacer" />}
      <button className="bc-tree-folder" onClick={() => navigate(value)}><Icon name={expanded[value] || folder === value ? 'folderOpen' : 'folder'} /><span>{value.split('/').pop() || 'Project files'}</span></button>
    </div>{expanded[value] && children(value).map(child => tree(child, depth + 1))}
  </div>
  const download = async () => {
    // The authenticated endpoint enforces ownership restrictions; do not use the list's cached download_url.
    const tab = window.open('', '_blank')
    if (!tab) { setDetailError('Allow a new tab to download this file.'); return }
    tab.opener = null
    setDownloading(true); setDetailError('')
    try {
      const { data } = await axios.get(`${API}/drive/files/${selected.id}/download-url`, { headers: { Authorization: `Bearer ${token}` } })
      const url = new URL(data.downloadUrl)
      if (url.protocol !== 'https:') throw new Error('Invalid download address')
      tab.location.href = url.href
    } catch (err) { tab.close(); setDetailError([409, 423].includes(err.response?.status) ? 'This file is currently in use. Try again after synchronization finishes.' : 'The file could not be downloaded. Check your access and try again.') }
    finally { setDownloading(false) }
  }
  return <section aria-label="Project archive">
    <div className="bc-toolbar"><span className="bc-muted">{loading ? 'Loading project files…' : `${files.length} files · ${directories.size - 1} folders`}</span><div className="bc-actions"><button className="bc-button" onClick={onModels}><Icon name="model" size={17} />Linked models & folders</button><button className="bc-button" onClick={reload} disabled={loading}><Icon name="refresh" size={17} />Refresh</button></div></div>
    {error && <div className="bc-error" role="alert">{error}<button className="bc-button" onClick={reload}>Try again</button></div>}
    {!error && <div className="bc-archive-layout"><aside className="bc-folder-tree" aria-label="Project folders">{tree()}</aside><div className="bc-archive-content">
      <div className="bc-breadcrumb"><button onClick={() => navigate('')}>Project files</button>{folder.split('/').filter(Boolean).map((name, index, all) => <span key={index}> / <button onClick={() => navigate(all.slice(0, index + 1).join('/'))}>{name}</button></span>)}</div>
      <label className="bc-search"><span className="sr-only">Search project files</span><div><Icon name="search" /><input type="search" placeholder="Search all project files" value={search} onChange={e => setSearch(e.target.value)} /></div></label>
      <div className="bc-surface bc-table-wrap"><table className="bc-file-table"><thead><tr><th>Name</th><th>Version</th><th>Size</th><th>Updated</th></tr></thead><tbody>
        {!search && children(folder).map(child => <tr key={child}><td colSpan={4}><button className="bc-file-link" onClick={() => navigate(child)}><Icon name="folder" />{child.split('/').pop()}</button></td></tr>)}
        {visibleFiles.map(file => <tr key={file.id} className={selected?.id === file.id ? 'is-selected' : ''}><td><button className="bc-file-link" onClick={() => selectFile(file)}><Icon name="document" /><span>{file.file_name}<small>{search ? parentPath(normalizedPath(file)) : file.locked_by_name ? `In use by ${file.locked_by_name}` : ''}</small></span></button></td><td>v{file.current_version ?? 1}</td><td>{sizeLabel(file.file_size)}</td><td>{dateLabel(file.updated_at || file.uploaded_at)}</td></tr>)}
      </tbody></table>{loading ? <p className="bc-empty">Loading files…</p> : !visibleFiles.length && (search || !children(folder).length) && <div className="bc-empty"><Icon name="folderOpen" size={32} /><h3>{search ? 'No matching files' : 'This folder is empty'}</h3><p>{search ? 'Try a different file name.' : 'Files synchronized through BIMChat Drive will appear here.'}</p></div>}</div>
      {selected && <section className="bc-surface bc-file-details" aria-label="File details"><div className="bc-toolbar"><div><h3>{selected.file_name}</h3><p className="bc-muted">{normalizedPath(selected)}</p></div><button className="bc-icon-button" aria-label="Close file details" onClick={() => setSelected(null)}><Icon name="close" /></button></div><button className="bc-button is-primary" onClick={download} disabled={downloading}><Icon name="download" size={17} />{downloading ? 'Preparing download…' : 'Download latest'}</button><h4><Icon name="history" size={17} />Version history</h4>{(detailError || currentHistory?.error) && <p role="alert" className="bc-error">{detailError || currentHistory?.error}</p>}{versions === null ? <p className="bc-muted">Loading history…</p> : versions.length ? <ul className="bc-version-list">{versions.map(version => <li key={version.id || version.version}><strong>Version {version.version}</strong><span>{dateLabel(version.created_at || version.uploaded_at)}</span><span>{sizeLabel(version.file_size)}</span></li>)}</ul> : <p className="bc-muted">No previous versions recorded.</p>}</section>}
    </div></div>}
  </section>
}

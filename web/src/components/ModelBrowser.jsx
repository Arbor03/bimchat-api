import { useState } from 'react'
import Icon from './Icon'

export default function ModelBrowser({ files, folders, selected, onToggle, onSelect, onClear, onOpen, onOpenOne, onManage, scene = false }) {
  const [search, setSearch] = useState('')
  const [folder, setFolder] = useState('all')
  const [collapsed, setCollapsed] = useState({})
  const ready = file => file.frag_status === 'ready'
  const nameOf = id => folders.find(item => item.id === id)?.name || 'Unassigned models'
  const filtered = files.filter(file => (!search || file.file_name.toLowerCase().includes(search.toLowerCase()) || nameOf(file.folder_id).toLowerCase().includes(search.toLowerCase())) && (folder === 'all' || String(file.folder_id ?? '') === folder))
  const groups = [...new Set(filtered.map(file => file.folder_id ?? null))]
  const hidden = [...selected].filter(id => !filtered.some(file => file.id === id)).length
  return <section className={`bc-model-browser ${scene ? 'is-scene' : ''}`} aria-label={scene ? 'Models in this view' : 'Model selection'}>
    <div className="bc-filters">
      <label className="bc-search"><span>Search models</span><div><Icon name="search" /><input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search name or folder" /></div></label>
      <label><span>Folder</span><select value={folder} onChange={e => setFolder(e.target.value)}><option value="all">All folders</option>{folders.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}<option value="">Unassigned models</option></select></label>
    </div>
    <div className="bc-toolbar"><span className="bc-muted">{filtered.length} of {files.length} models</span><div className="bc-actions">
      {!scene && <button className="bc-button" disabled={!filtered.some(ready)} onClick={() => onSelect(new Set([...selected, ...filtered.filter(ready).map(file => file.id)]))}>Select filtered</button>}
      {onManage && <button className="bc-button" onClick={onManage}><Icon name="folder" size={17} />Manage folders</button>}
    </div></div>
    <div className="bc-model-list">
      {groups.map(id => <section key={id ?? 'unassigned'} className="bc-model-group">
        <button className="bc-group-heading" aria-expanded={!collapsed[id ?? 'unassigned']} onClick={() => setCollapsed(old => ({ ...old, [id ?? 'unassigned']: !old[id ?? 'unassigned'] }))}>
          <Icon name={collapsed[id ?? 'unassigned'] ? 'right' : 'down'} size={16} /><span>{nameOf(id)}</span><span className="bc-count">{filtered.filter(file => (file.folder_id ?? null) === id).length}</span>
        </button>
        {!collapsed[id ?? 'unassigned'] && filtered.filter(file => (file.folder_id ?? null) === id).map(file => <div key={file.id} className={`bc-model-row ${selected.has(file.id) ? 'is-selected' : ''}`}>
          <input type="checkbox" aria-label={`${scene ? 'Show' : 'Select'} ${file.file_name}`} checked={selected.has(file.id)} disabled={!ready(file)} onChange={() => onToggle(file.id)} />
          <span className="bc-file-icon"><Icon name="model" /></span><div className="bc-model-name"><strong>{file.file_name}</strong><span>{file.linked_by || 'Linked project model'}</span></div>
          <span className={`bc-badge ${ready(file) ? 'is-ready' : ''}`}>{ready(file) ? 'Ready to view' : file.frag_status === 'error' ? 'Conversion failed' : file.frag_status === 'pending' ? 'Preparing' : 'Not published to 3D'}</span>
          {!scene && <button className="bc-button" disabled={!ready(file)} onClick={() => onOpenOne(file)} aria-label={`Open ${file.file_name}`}>Open 3D</button>}
        </div>)}
      </section>)}
      {!filtered.length && <div className="bc-empty"><Icon name="model" size={34} /><h3>{files.length ? 'No models match your search' : 'No models linked yet'}</h3><p>{files.length ? 'Try another name or folder.' : 'Link a model from Revit, then publish it to the web to open it here.'}</p></div>}
    </div>
    {!scene && <div className="bc-selection-bar"><span><strong>{selected.size}</strong> models selected{hidden > 0 && <small className="bc-muted"> · {hidden} hidden by filters</small>}</span><div className="bc-actions"><button className="bc-button" onClick={onClear} disabled={!selected.size}>Clear selection</button><button className="bc-button is-primary" disabled={!selected.size} onClick={onOpen}>Open selected{selected.size > 0 ? ` (${selected.size})` : ''}</button></div></div>}
  </section>
}

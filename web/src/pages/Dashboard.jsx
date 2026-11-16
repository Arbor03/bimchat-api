import { useState, useEffect, useRef, lazy, Suspense } from 'react'
import axios from 'axios'
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { API } from '../api'
import Icon from '../components/Icon'
import ModelBrowser from '../components/ModelBrowser'
import ProjectArchive from '../components/ProjectArchive'

const Viewer = lazy(() => import('./Viewer'))
const COLORS = ['#E74C3C', '#F39C12', '#27AE60']
const ROLES = ['BIM Manager', 'BIM Coordinator', 'BIM Specialist', 'Architect', 'Structural', 'MEP', 'Client']

// Visual + ordering config for conversation levels (project > folder > model)
const LEVEL_META = {
  project: { order: 0, icon: '🌐', header: 'Project',               border: 'border-l-indigo-500', badge: 'bg-indigo-100 text-indigo-700' },
  folder:  { order: 1, icon: '📁', header: 'Folders / Disciplines', border: 'border-l-amber-500',  badge: 'bg-amber-100 text-amber-700' },
  model:   { order: 2, icon: '🧊', header: 'Models',                border: 'border-l-teal-500',   badge: 'bg-teal-100 text-teal-700' },
}

function emailFromToken(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return (payload.email || '').toLowerCase()
  } catch { return '' }
}

// Inline input for creating a new folder
function NewFolderInput({ onCreate, onCancel }) {
  const [name, setName] = useState('')
  return (
    <div className="flex items-center gap-2 my-2 ml-2">
      <span className="text-base">📁</span>
      <input autoFocus value={name} onChange={e => setName(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') onCreate(name); if (e.key === 'Escape') onCancel() }}
        placeholder="Folder name..."
        className="border border-gray-300 rounded px-2 py-1 text-sm flex-1 max-w-xs focus:outline-none focus:ring-2 focus:ring-blue-500" />
      <button onClick={() => onCreate(name)}
        className="bg-blue-700 hover:bg-blue-800 text-white px-2 py-1 rounded text-xs">Add</button>
      <button onClick={onCancel}
        className="text-gray-500 hover:bg-gray-100 px-2 py-1 rounded text-xs">Cancel</button>
    </div>
  )
}

const SidebarItem = ({ icon, label, active, onClick }) => (
  <button onClick={onClick} className={active ? 'is-active' : ''} title={label} aria-label={label} aria-current={active ? 'page' : undefined}>
    <Icon name={icon} /><span className="bc-nav-label">{label}</span>
  </button>
)

export default function Dashboard({ token, onLogout }) {
  const [projects, setProjects] = useState([])
  const [openedProject, setOpenedProject] = useState(null)
  const [loading, setLoading] = useState(true)
  // The 3D scene is a single live list of models (array of { id, name } | null).
  // Single 3D open = [one model]; "Open 3D" = the selected models; while open you
  // add/remove models from the sidebar checkboxes.
  const [viewerFiles, setViewerFiles] = useState(null)

  // Pre-launch selection (checkboxes in the Revit Files panel).
  const [federatedSel, setFederatedSel] = useState(() => new Set())

  const [activeTab, setActiveTab] = useState('overview')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('bimchat.sidebar') === 'collapsed')
  const [mobileNav, setMobileNav] = useState(false)
  useEffect(() => { localStorage.setItem('bimchat.sidebar', sidebarCollapsed ? 'collapsed' : 'expanded') }, [sidebarCollapsed])
  const [selectedFile, setSelectedFile] = useState(null)
  const [folders, setFolders] = useState([])
  const [newFolderParent, setNewFolderParent] = useState(undefined)
  const [expandedFolders, setExpandedFolders] = useState({})
  const [tasks, setTasks] = useState([])
  const [users, setUsers] = useState([])
  const [attachmentsMap, setAttachmentsMap] = useState({})
  const [uploading, setUploading] = useState(false)

  // ---------- chat (conversations) ----------
  const [conversations, setConversations] = useState([])
  const [selectedConv, setSelectedConv] = useState(null)
  const [convMessages, setConvMessages] = useState([])
  const [newConvMessage, setNewConvMessage] = useState('')
  const [showScrollBtn, setShowScrollBtn] = useState(false)
  const [showNewConvModal, setShowNewConvModal] = useState(false)
  const [ncType, setNcType] = useState('dm')
  const [ncName, setNcName] = useState('')
  const [ncMembers, setNcMembers] = useState([])
  const [ncLevel, setNcLevel] = useState('project')
  const [ncFolderId, setNcFolderId] = useState('')
  const [ncFileId, setNcFileId] = useState('')

  const [showNewProjectModal, setShowNewProjectModal] = useState(false)
  const [showAddMemberModal, setShowAddMemberModal] = useState(false)
  const [newProjectName, setNewProjectName] = useState('')
  const [newProjectDesc, setNewProjectDesc] = useState('')
  const [newProjectDeadline, setNewProjectDeadline] = useState('')
  const [newMemberEmail, setNewMemberEmail] = useState('')
  const [newMemberRole, setNewMemberRole] = useState('BIM Specialist')

  const convFileRef = useRef(null)
  const convEndRef = useRef(null)

  const headers = { Authorization: `Bearer ${token}` }
  const projectName = openedProject?.name
  const userEmail = emailFromToken(token)

  useEffect(() => { loadProjects() }, [])

  const loadProjects = async () => {
    setLoading(true)
    try {
      const res = await axios.get(`${API}/projects`, { headers })
      setProjects(res.data)
    } catch (err) { console.error(err) }
    setLoading(false)
  }

  const openProject = async (projectId) => {
    try {
      const res = await axios.get(`${API}/projects/${projectId}`, { headers })
      setOpenedProject(res.data)
      setActiveTab('overview')
      setSelectedFile(null); setFolders([]); setNewFolderParent(undefined); setExpandedFolders({}); setMobileNav(false)
      setTasks([]); setUsers([]); setAttachmentsMap({})
      setConversations([]); setSelectedConv(null); setConvMessages([])
      setFederatedSel(new Set())   // reset model selection when switching project
      setViewerFiles(null)
    } catch (err) {
      alert('Failed to open project: ' + (err.response?.data?.error || err.message))
    }
  }

  const closeProject = () => {
    setOpenedProject(null)
    setActiveTab('overview')
    setFederatedSel(new Set())
    setViewerFiles(null)
  }

  useEffect(() => {
    if (!openedProject) return
    loadWorkspaceData()
  }, [openedProject])

  const loadWorkspaceData = async () => {
    if (!projectName) return
    try {
      const [tasksRes, usersRes] = await Promise.all([
        axios.get(`${API}/tasks/${encodeURIComponent(projectName)}`, { headers }),
        axios.get(`${API}/users/${encodeURIComponent(projectName)}`, { headers })
      ])
      setTasks(tasksRes.data)
      setUsers(usersRes.data)
    } catch (err) { console.error(err) }
  }

  // ---------- conversations ----------
  const loadConversations = async () => {
    if (!openedProject) return
    try {
      const res = await axios.get(`${API}/conversations?project_id=${openedProject.id}`, { headers })
      setConversations(res.data)
    } catch (err) { console.error(err) }
  }

  useEffect(() => { if (openedProject) loadConversations() }, [openedProject])

  const openConversation = async (conv) => {
    setSelectedConv(conv)
    try {
      const res = await axios.get(`${API}/conversations/${conv.id}/messages`, { headers })
      setConvMessages(res.data)
      loadAttachments(res.data)
      setTimeout(() => convEndRef.current?.scrollIntoView({ behavior: 'auto' }), 100)
    } catch (err) { console.error(err) }
  }

  useEffect(() => {
    if (!openedProject || activeTab !== 'chat' || !selectedConv) return
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${API}/conversations/${selectedConv.id}/messages`, { headers })
        setConvMessages(res.data)
        loadAttachments(res.data)
      } catch { }
    }, 3000)
    return () => clearInterval(interval)
  }, [activeTab, openedProject, selectedConv, token])

  useEffect(() => {
    if (!openedProject || activeTab !== 'chat') return
    const interval = setInterval(loadConversations, 8000)
    return () => clearInterval(interval)
  }, [activeTab, openedProject, token])

  const sendConvMessage = async () => {
    if (!newConvMessage.trim() || !selectedConv) return
    try {
      await axios.post(`${API}/conversations/${selectedConv.id}/messages`,
        { message: newConvMessage }, { headers })
      setNewConvMessage('')
      const res = await axios.get(`${API}/conversations/${selectedConv.id}/messages`, { headers })
      setConvMessages(res.data)
      loadAttachments(res.data)
    } catch (err) { console.error(err) }
  }

  const createConversation = async () => {
    if (ncType === 'group' && !ncName.trim()) { alert('Group name is required'); return }
    if (ncMembers.length === 0) { alert('Select at least one member'); return }
    if (ncType === 'dm' && ncMembers.length !== 1) { alert('A DM needs exactly one other person'); return }
    if (ncLevel === 'folder' && !ncFolderId) { alert('Select a folder'); return }
    if (ncLevel === 'model' && !ncFileId) { alert('Select a model'); return }

    const body = { project_id: openedProject.id, type: ncType, level: ncLevel, members: ncMembers }
    if (ncType === 'group') body.name = ncName.trim()
    if (ncLevel === 'folder') body.folder_id = parseInt(ncFolderId)
    if (ncLevel === 'model') body.file_id = parseInt(ncFileId)

    try {
      const res = await axios.post(`${API}/conversations`, body, { headers })
      closeNewConvModal()
      await loadConversations()
      const newId = res.data.conversation_id
      const conv = (await axios.get(`${API}/conversations?project_id=${openedProject.id}`, { headers }))
        .data.find(c => c.id === newId)
      if (conv) openConversation(conv)
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const closeNewConvModal = () => {
    setShowNewConvModal(false)
    setNcType('dm'); setNcName(''); setNcMembers([]); setNcLevel('project'); setNcFolderId(''); setNcFileId('')
  }

  const leaveConversation = async (conv) => {
    if (!confirm('Leave this conversation?')) return
    try {
      await axios.delete(`${API}/conversations/${conv.id}/members/${encodeURIComponent(userEmail)}`, { headers })
      setSelectedConv(null); setConvMessages([])
      await loadConversations()
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  const convertMessageToTask = async (m) => {
    if (!confirm('Create a task from this message?')) return
    try {
      await axios.post(`${API}/tasks/from-message`, { message_id: m.id }, { headers })
      const res = await axios.get(`${API}/tasks/${encodeURIComponent(projectName)}`, { headers })
      setTasks(res.data)
      alert('Task created.')
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  const loadAttachments = async (messages) => {
    const newMap = {}
    await Promise.all(messages.map(async m => {
      try {
        const res = await axios.get(`${API}/attachments/message/${m.id}`, { headers })
        if (res.data.length > 0) newMap[m.id] = res.data
      } catch { }
    }))
    setAttachmentsMap(prev => ({ ...prev, ...newMap }))
  }

  useEffect(() => {
    const el = convEndRef.current?.parentElement
    if (!el) return
    const handler = () => {
      const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100
      setShowScrollBtn(!nearBottom)
    }
    el.addEventListener('scroll', handler)
    return () => el.removeEventListener('scroll', handler)
  }, [selectedConv])

  useEffect(() => {
    const el = convEndRef.current?.parentElement
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 150) {
      convEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [convMessages])

  const handlePaste = async (e) => {
    const items = e.clipboardData?.items
    if (!items) return
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault()
        const blob = item.getAsFile()
        if (!blob) continue
        const ext = item.type.split('/')[1] || 'png'
        const file = new File([blob], `screenshot_${Date.now()}.${ext}`, { type: item.type })
        await handleConvFileSelect({ target: { files: [file], value: '' } })
        return
      }
    }
  }

  const uploadFile = async (file, messageId) => {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('message_id', messageId)
    await axios.post(`${API}/attachments/upload`, formData, {
      headers: { ...headers, 'Content-Type': 'multipart/form-data' }
    })
  }

  const handleConvFileSelect = async (e) => {
    const file = e.target.files[0]
    if (!file || !selectedConv) return
    if (file.size > 10 * 1024 * 1024) { alert('File too large (max 10MB)'); return }
    setUploading(true)
    try {
      const msgRes = await axios.post(`${API}/conversations/${selectedConv.id}/messages`,
        { message: `📎 ${file.name}` }, { headers })
      const messageId = msgRes.data.id
      await uploadFile(file, messageId)
      const res = await axios.get(`${API}/conversations/${selectedConv.id}/messages`, { headers })
      setConvMessages(res.data)
      loadAttachments(res.data)
    } catch (err) {
      alert('Upload failed: ' + (err.response?.data?.error || err.message))
    }
    setUploading(false)
    e.target.value = ''
  }

  const createProject = async () => {
    if (!newProjectName.trim()) { alert('Project name is required'); return }
    try {
      await axios.post(`${API}/projects`, {
        name: newProjectName,
        description: newProjectDesc || null,
        deadline: newProjectDeadline || null
      }, { headers })
      setNewProjectName(''); setNewProjectDesc(''); setNewProjectDeadline('')
      setShowNewProjectModal(false)
      await loadProjects()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const deleteProject = async (projectId) => {
    if (!confirm('Delete this project? This cannot be undone.')) return
    try {
      await axios.delete(`${API}/projects/${projectId}`, { headers })
      if (openedProject?.id === projectId) closeProject()
      await loadProjects()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const addMember = async () => {
    if (!newMemberEmail.trim()) { alert('Email required'); return }
    try {
      await axios.post(`${API}/projects/${openedProject.id}/members`, {
        user_email: newMemberEmail,
        role: newMemberRole
      }, { headers })
      setNewMemberEmail(''); setNewMemberRole('BIM Specialist')
      setShowAddMemberModal(false)
      await refreshOpenedProject()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const removeMember = async (email) => {
    if (!confirm(`Remove ${email}?`)) return
    try {
      await axios.delete(`${API}/projects/${openedProject.id}/members/${encodeURIComponent(email)}`, { headers })
      await refreshOpenedProject()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const unlinkFile = async (fileId, fileName) => {
    if (!confirm(`Hiq lidhjen e "${fileName}"?`)) return
    try {
      await axios.delete(`${API}/revit-files/${fileId}`, { headers })
      await refreshOpenedProject()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const updateMemberRole = async (email, role) => {
    try {
      await axios.put(`${API}/projects/${openedProject.id}/members/${encodeURIComponent(email)}`, { role }, { headers })
      await refreshOpenedProject()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const refreshOpenedProject = async () => {
    if (!openedProject) return
    const res = await axios.get(`${API}/projects/${openedProject.id}`, { headers })
    setOpenedProject(res.data)
  }

  // ---------- folders ----------
  const isManager = openedProject?.members?.find(m => m.user_email === userEmail)?.role === 'BIM Manager'

  const loadFolders = async () => {
    if (!openedProject) return
    try {
      const res = await axios.get(`${API}/projects/${openedProject.id}/folders`, { headers })
      setFolders(res.data)
    } catch (err) { console.error(err) }
  }

  useEffect(() => { if (openedProject) loadFolders() }, [openedProject])

  const createFolder = async (parentId, name) => {
    if (!name || !name.trim()) return
    try {
      await axios.post(`${API}/projects/${openedProject.id}/folders`,
        { name: name.trim(), parent_id: parentId }, { headers })
      setNewFolderParent(undefined)
      await loadFolders()
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  const renameFolder = async (folderId, currentName) => {
    const name = prompt('New folder name:', currentName)
    if (!name || !name.trim()) return
    try {
      await axios.put(`${API}/folders/${folderId}`, { name: name.trim() }, { headers })
      await loadFolders()
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  const deleteFolder = async (folderId, name) => {
    if (!confirm(`Delete folder "${name}"? Files inside will become unassigned.`)) return
    try {
      await axios.delete(`${API}/folders/${folderId}`, { headers })
      await loadFolders()
      await refreshOpenedProject()
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  // ---------- federated model selection ----------
  // A model can be opened in the web 3D viewer only if its IFC has been converted
  // to Fragments (frag_status === 'ready'). Others show a "not on web" badge.
  const isOnWeb = (f) => f?.frag_status === 'ready'

  const toggleFederated = (fileId) => {
    setFederatedSel(prev => {
      const next = new Set(prev)
      if (next.has(fileId)) next.delete(fileId)
      else next.add(fileId)
      return next
    })
  }

  const clearFederated = () => setFederatedSel(new Set())

  // Open the selected models in the live 3D scene.
  const openFederated = () => {
    const ids = [...federatedSel]
    if (ids.length === 0) return
    const chosen = (openedProject.files || [])
      .filter(f => ids.includes(f.id) && isOnWeb(f))
      .map(f => ({ id: f.id, name: f.file_name }))
    if (chosen.length) setViewerFiles(chosen)
  }

  // open a single model directly in 3D
  const open3D = (f) => { if (isOnWeb(f)) setViewerFiles([{ id: f.id, name: f.file_name }]) }

  // is a model currently in the open 3D scene?

  // add/remove a model from the live scene (only meaningful while 3D is open)
  const toggleSceneModel = (f) => {
    if (!isOnWeb(f)) return
    setViewerFiles(prev => {
      if (!prev) return prev
      return prev.some(x => x.id === f.id)
        ? (prev.length === 1 ? null : prev.filter(x => x.id !== f.id))
        : [...prev, { id: f.id, name: f.file_name }]
    })
  }

  // ---------- conversation display helpers ----------
  const memberName = (email) => {
    const m = openedProject?.members?.find(x => x.user_email === email)
    if (m?.full_name) return m.full_name
    const u = users.find(x => x.email === email)
    return u?.full_name || email
  }

  const convTitle = (conv) => {
    if (conv.type === 'group') return conv.name || 'Group'
    const others = (conv.members || []).filter(e => e !== userEmail)
    return others.map(memberName).join(', ') || 'Direct message'
  }

  // Normalize a conversation level to one of the known keys (default = project)
  const normLevel = (conv) => (LEVEL_META[conv.level] ? conv.level : 'project')

  // Bare name of the level target (no emoji) — used inside colored badges
  const convLevelName = (conv) => {
    if (conv.level === 'folder') {
      const f = folders.find(x => x.id === conv.folder_id)
      return f ? f.name : 'Folder'
    }
    if (conv.level === 'model') {
      const file = openedProject?.files?.find(x => x.id === conv.file_id)
      return file ? file.file_name : 'Model'
    }
    return 'Project'
  }

  // Full label with emoji — used in the conversation header pane
  const convLevelLabel = (conv) => {
    if (conv.level === 'folder') {
      const f = folders.find(x => x.id === conv.folder_id)
      return f ? `📁 ${f.name}` : '📁 Folder'
    }
    if (conv.level === 'model') {
      const file = openedProject?.files?.find(x => x.id === conv.file_id)
      return file ? `🧊 ${file.file_name}` : '🧊 Model'
    }
    return '🌐 Project'
  }

  const projectMembersExceptMe = (openedProject?.members || []).filter(m => m.user_email !== userEmail)

  const stats = {
    open: tasks.filter(t => t.status === 'Open').length,
    inProgress: tasks.filter(t => t.status === 'InProgress').length,
    closed: tasks.filter(t => t.status === 'Closed').length,
  }
  const chartData = [
    { name: 'Open', value: stats.open },
    { name: 'In Progress', value: stats.inProgress },
    { name: 'Closed', value: stats.closed },
  ]

  const navigate = tab => { setActiveTab(tab); setViewerFiles(null); setMobileNav(false) }
  const pages = {
    overview: ['Overview', 'Your project at a glance.'],
    archive: ['Project files', 'Models, drawings, reports and supporting documents in one place.'],
    models: ['3D Models', 'Select one or more published models to open together.'],
    documentation: ['Documentation', 'Track the documents and drawings your project needs to deliver.'],
    tasks: ['Tasks', 'Follow assignments, progress and outstanding work.'],
    chat: ['Conversations', 'Discuss the project, folders and models with your team.'],
    members: ['Team', 'The people collaborating on this project.'],
    files: ['Linked models & folders', 'Organize the models linked from Revit.'],
    settings: ['Settings', 'Project preferences.'],
  }
  return (
    <div className={['bc-app', sidebarCollapsed ? 'is-collapsed' : '', mobileNav ? 'is-mobile-nav-open' : ''].join(' ')}>
      <header className="bc-header">
        {openedProject && <button className="bc-icon-button bc-mobile-menu" aria-label="Open project menu" aria-expanded={mobileNav} onClick={() => setMobileNav(!mobileNav)}><Icon name="menu" /></button>}
        <button className="bc-brand" onClick={closeProject} aria-label="BIMChat projects"><span className="bc-brand-mark">B</span><span className="bc-brand-word">BIMChat</span></button>
        <div className="bc-project-title">{openedProject?.name || 'Your workspace'}</div>
        <div className="bc-user"><span className="bc-avatar">{userEmail[0]?.toUpperCase() || 'B'}</span><span className="bc-user-email">{userEmail}</span><button onClick={onLogout} className="bc-button" aria-label="Sign out"><Icon name="logout" size={16} /><span>Sign out</span></button></div>
      </header>

      {!openedProject && (
        <div className="bc-projects-home">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold text-gray-700">Projects</h2>
            <button onClick={() => setShowNewProjectModal(true)}
              className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm font-medium">
              + New Project
            </button>
          </div>

          {loading ? (
            <div className="text-center text-gray-500 py-20">Loading...</div>
          ) : projects.length === 0 ? (
            <div className="bg-white rounded-xl shadow p-10 text-center text-gray-500">
              <p className="text-4xl mb-2">📁</p>
              <p>No projects yet. Create your first project!</p>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-4">
              {projects.map(p => (
                <div key={p.id} onClick={() => openProject(p.id)}
                  className="bg-white rounded-xl shadow p-5 cursor-pointer hover:shadow-lg transition border-l-4 border-blue-600">
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="font-bold text-gray-800 text-lg">{p.name}</h3>
                    <span className={`text-xs px-2 py-1 rounded-full ${
                      p.status === 'Active' ? 'bg-green-100 text-green-700' :
                      p.status === 'Completed' ? 'bg-blue-100 text-blue-700' :
                      'bg-gray-100 text-gray-700'
                    }`}>
                      {p.status || 'Active'}
                    </span>
                  </div>
                  {p.description && (
                    <p className="text-sm text-gray-600 mb-3 line-clamp-2">{p.description}</p>
                  )}
                  <div className="flex gap-4 text-xs text-gray-500 border-t pt-2">
                    <span>👥 {p.member_count ?? 0} members</span>
                    <span>📋 {p.task_count ?? 0} tasks</span>
                  </div>
                  <div className="mt-2 text-xs text-gray-400">
                    Your role: <span className="font-medium text-blue-700">{p.my_role || 'Member'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {openedProject && (
        <div className="bc-project-layout">
          {mobileNav && <button className="bc-drawer-shade" aria-label="Close project menu" onClick={() => setMobileNav(false)} />}
          <aside className="bc-sidebar">
            <button className="bc-mobile-nav-close" onClick={() => setMobileNav(false)}><Icon name="close" /><span>Close menu</span></button>
            <button className="bc-collapse" onClick={() => setSidebarCollapsed(value => !value)} aria-label={sidebarCollapsed ? 'Expand menu' : 'Collapse menu'} title={sidebarCollapsed ? 'Expand menu' : 'Collapse menu'} aria-expanded={!sidebarCollapsed}><Icon name={sidebarCollapsed ? 'right' : 'left'} /><span className="bc-nav-label">Collapse menu</span></button>
            <nav aria-label="Project navigation">
              <SidebarItem icon="overview" label="Overview" active={activeTab === 'overview' && !viewerFiles} onClick={() => navigate('overview')} />
              <SidebarItem icon="folder" label="Project files" active={['archive','files'].includes(activeTab) && !viewerFiles} onClick={() => navigate('archive')} />
              <SidebarItem icon="model" label="3D Models" active={activeTab === 'models' || !!viewerFiles} onClick={() => navigate('models')} />
              <SidebarItem icon="document" label="Documentation" active={activeTab === 'documentation' && !viewerFiles} onClick={() => navigate('documentation')} />
              <SidebarItem icon="tasks" label="Tasks" active={activeTab === 'tasks' && !viewerFiles} onClick={() => navigate('tasks')} />
              <SidebarItem icon="chat" label="Conversations" active={activeTab === 'chat' && !viewerFiles} onClick={() => navigate('chat')} />
              <SidebarItem icon="team" label="Team" active={activeTab === 'members' && !viewerFiles} onClick={() => navigate('members')} />
              <SidebarItem icon="settings" label="Settings" active={activeTab === 'settings' && !viewerFiles} onClick={() => navigate('settings')} />
            </nav>
            <button className="bc-back-projects" onClick={closeProject} title="All projects"><Icon name="left" /><span className="bc-nav-label">All projects</span></button>
          </aside>
          <main className="bc-main" inert={viewerFiles || mobileNav ? true : undefined}>
            <div className="bc-page-heading"><div><h1>{pages[activeTab]?.[0]}</h1><p>{pages[activeTab]?.[1]}</p></div></div>
            {activeTab === 'archive' && <ProjectArchive key={openedProject.id} projectId={openedProject.id} token={token} onModels={() => { setSelectedFile(null); navigate('files') }} />}
            {activeTab === 'models' && <ModelBrowser key={openedProject.id} files={openedProject.files || []} folders={folders} selected={federatedSel} onToggle={toggleFederated} onSelect={setFederatedSel} onClear={clearFederated} onOpen={openFederated} onOpenOne={open3D} onManage={() => { setSelectedFile(null); navigate('files') }} />}
            {activeTab === 'documentation' && <div className="bc-surface bc-empty"><Icon name="document" size={38} /><h3>Your deliverable register</h3><p>Deliverables have not been set up for this project. Browse the existing drawings, reports and supporting documents in Project files.</p><button className="bc-button is-primary" onClick={() => navigate('archive')}>Browse project files</button></div>}
            {activeTab === 'overview' && (
              <div>
                <div className="grid grid-cols-3 gap-4 mb-6">
                  <div className="bg-white rounded-xl shadow p-5 border-l-4 border-red-500">
                    <p className="text-gray-500 text-sm">Open</p>
                    <p className="text-3xl font-bold text-red-500">{stats.open}</p>
                  </div>
                  <div className="bg-white rounded-xl shadow p-5 border-l-4 border-yellow-500">
                    <p className="text-gray-500 text-sm">In Progress</p>
                    <p className="text-3xl font-bold text-yellow-500">{stats.inProgress}</p>
                  </div>
                  <div className="bg-white rounded-xl shadow p-5 border-l-4 border-green-500">
                    <p className="text-gray-500 text-sm">Closed</p>
                    <p className="text-3xl font-bold text-green-500">{stats.closed}</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-white rounded-xl shadow p-6">
                    <h2 className="text-lg font-semibold text-gray-700 mb-4">Task Status</h2>
                    {tasks.length === 0 ? (
                      <p className="text-gray-400 text-center py-10">No tasks yet</p>
                    ) : (
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie data={chartData} cx="50%" cy="50%" outerRadius={80} dataKey="value"
                            label={({ name, value }) => `${name}: ${value}`}>
                            {chartData.map((_, index) => (<Cell key={index} fill={COLORS[index]} />))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </div>

                  <div className="bg-white rounded-xl shadow p-6">
                    <h2 className="text-lg font-semibold text-gray-700 mb-4">Project Info</h2>
                    <div className="space-y-3 text-sm">
                      <div className="flex justify-between"><span className="text-gray-500">Status:</span><span className="font-medium">{openedProject.status || 'Active'}</span></div>
                      <div className="flex justify-between"><span className="text-gray-500">Members:</span><span className="font-medium">{openedProject.members?.length || 0}</span></div>
                      <div className="flex justify-between"><span className="text-gray-500">Linked Files:</span><span className="font-medium">{openedProject.files?.length || 0}</span></div>
                      <div className="flex justify-between"><span className="text-gray-500">Deadline:</span><span className="font-medium">{openedProject.deadline ? new Date(openedProject.deadline).toLocaleDateString() : '—'}</span></div>
                      <div className="flex justify-between"><span className="text-gray-500">Created:</span><span className="font-medium">{new Date(openedProject.created_at).toLocaleDateString()}</span></div>
                      {openedProject.description && (
                        <div className="pt-2 border-t">
                          <p className="text-gray-500 text-xs mb-1">Description:</p>
                          <p className="text-gray-700">{openedProject.description}</p>
                        </div>
                      )}
                    </div>
                    <div className="mt-4 pt-4 border-t">
                      <button onClick={() => deleteProject(openedProject.id)}
                        className="text-red-600 hover:bg-red-50 px-3 py-1 rounded text-sm">
                        🗑 Delete Project
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'tasks' && (
              <div className="bc-task-table bg-white rounded-xl shadow">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 border-b">
                    <tr>
                      <th className="text-left px-4 py-3 text-gray-600">Description</th>
                      <th className="text-left px-4 py-3 text-gray-600">Assignee</th>
                      <th className="text-left px-4 py-3 text-gray-600">Created By</th>
                      <th className="text-left px-4 py-3 text-gray-600">Status</th>
                      <th className="text-left px-4 py-3 text-gray-600">Created At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map(task => (
                      <tr key={task.id} className="border-b hover:bg-gray-50">
                        <td className="px-4 py-3 font-medium">{task.description}</td>
                        <td className="px-4 py-3 text-gray-500">{task.assignee || '-'}</td>
                        <td className="px-4 py-3 text-gray-500">{task.created_by || '-'}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            task.status === 'Open' ? 'bg-red-100 text-red-600' :
                            task.status === 'InProgress' ? 'bg-yellow-100 text-yellow-600' :
                            'bg-green-100 text-green-600'
                          }`}>{task.status}</span>
                        </td>
                        <td className="px-4 py-3 text-gray-500">{new Date(task.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {tasks.length === 0 && <p className="text-center text-gray-500 py-10">No tasks yet. Create tasks from the Revit add-in or from a chat message.</p>}
              </div>
            )}

            {activeTab === 'chat' && (
              <div className="bc-chat-layout">
                {/* conversation list */}
                <div className="bc-chat-list bg-white rounded-xl shadow flex flex-col overflow-hidden">
                  <div className="p-3 border-b flex justify-between items-center">
                    <h2 className="font-semibold text-gray-700">Chat</h2>
                    <button onClick={() => {
                        const hasFiles = (openedProject?.files?.length || 0) > 0
                        const hasFolders = folders.length > 0
                        setNcLevel(hasFiles ? 'model' : (hasFolders ? 'folder' : 'project'))
                        setNcFolderId(''); setNcFileId('')
                        setShowNewConvModal(true)
                      }}
                      className="bg-blue-700 hover:bg-blue-800 text-white px-2.5 py-1 rounded-lg text-sm">+ New</button>
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    {conversations.length === 0 ? (
                      <p className="text-gray-400 text-sm text-center py-8 px-3">No conversations yet. Start one with "+ New".</p>
                    ) : (() => {
                      // Sort: by level (project > folder > model), then newest activity first
                      const sorted = [...conversations].sort((a, b) => {
                        const oa = LEVEL_META[normLevel(a)].order
                        const ob = LEVEL_META[normLevel(b)].order
                        if (oa !== ob) return oa - ob
                        const da = a.last_message_at ? new Date(a.last_message_at).getTime() : 0
                        const db = b.last_message_at ? new Date(b.last_message_at).getTime() : 0
                        return db - da
                      })

                      const ConvRow = (conv) => {
                        const meta = LEVEL_META[normLevel(conv)]
                        return (
                          <div key={conv.id} onClick={() => openConversation(conv)}
                            className={`pl-2.5 pr-3 py-2.5 cursor-pointer border-b border-l-4 ${meta.border} transition
                              ${selectedConv?.id === conv.id ? 'bg-blue-50' : 'bg-white hover:bg-gray-50'}`}>
                            <div className="flex items-center gap-2">
                              <span className="text-base">{conv.type === 'group' ? '👥' : '👤'}</span>
                              <span className="flex-1 font-medium text-sm text-gray-800 truncate">{convTitle(conv)}</span>
                              {conv.last_message_at && (
                                <span className="text-[10px] text-gray-400 flex-shrink-0">{new Date(conv.last_message_at).toLocaleDateString()}</span>
                              )}
                            </div>
                            <div className="mt-1 ml-7">
                              <span className={`inline-block text-[10px] font-semibold px-1.5 py-0.5 rounded ${meta.badge}`}>
                                {meta.icon} {convLevelName(conv)}
                              </span>
                            </div>
                          </div>
                        )
                      }

                      return ['project', 'folder', 'model'].map(lvl => {
                        const items = sorted.filter(c => normLevel(c) === lvl)
                        if (items.length === 0) return null
                        const meta = LEVEL_META[lvl]
                        return (
                          <div key={lvl}>
                            <div className="px-3 py-1.5 bg-gray-100 border-b sticky top-0 z-10">
                              <span className="text-[10px] font-bold uppercase tracking-wider text-gray-500">
                                {meta.icon} {meta.header}
                              </span>
                            </div>
                            {items.map(ConvRow)}
                          </div>
                        )
                      })
                    })()}
                  </div>
                </div>

                {/* conversation pane */}
                <div className="flex-1 bg-white rounded-xl shadow flex flex-col relative overflow-hidden">
                  {selectedConv ? (
                    <>
                      <div className="p-3 border-b flex items-center justify-between bg-blue-700 rounded-t-xl">
                        <div>
                          <h2 className="font-semibold text-white">
                            {selectedConv.type === 'group' ? '👥' : '👤'} {convTitle(selectedConv)}
                          </h2>
                          <p className="text-blue-200 text-xs">
                            {convLevelLabel(selectedConv)}
                            {selectedConv.type === 'group' && ` · ${(selectedConv.members || []).length} members`}
                          </p>
                        </div>
                        <button onClick={() => leaveConversation(selectedConv)}
                          className="text-blue-100 hover:text-white text-xs border border-blue-400 rounded px-2 py-1">Leave</button>
                      </div>

                      <div className="flex-1 overflow-y-auto p-4 space-y-3">
                        {convMessages.map(m => {
                          return (
                            <div key={m.id} className="flex flex-col group">
                              <div className="flex items-center gap-2 mb-1">
                                <div className="w-7 h-7 bg-blue-700 rounded-full flex items-center justify-center text-white text-xs font-bold">
                                  {m.sender[0].toUpperCase()}
                                </div>
                                <span className="text-xs font-medium text-blue-700">{memberName(m.sender)}</span>
                                <span className="text-xs text-gray-400">{new Date(m.created_at).toLocaleTimeString()}</span>
                                <button onClick={() => convertMessageToTask(m)}
                                  className="opacity-0 group-hover:opacity-100 transition text-[11px] text-gray-500 hover:text-blue-700 border border-gray-200 rounded px-1.5 py-0.5"
                                  title="Convert to task">→ Task</button>
                              </div>
                              <div className="ml-9 bg-gray-100 rounded-lg px-3 py-2 text-sm max-w-lg">
                                {m.message}
                                {m.element_name && (<div className="mt-1 text-blue-600 text-xs font-medium">🔗 {m.element_name}</div>)}
                                {attachmentsMap[m.id]?.map(att => (
                                  <div key={att.id} className="mt-2">
                                    {att.resource_type === 'image' ? (
                                      <div className="relative inline-block">
                                        <a href={att.file_url} target="_blank" rel="noreferrer">
                                          <img src={att.file_url} alt={att.file_name} className="max-w-xs rounded-lg border" />
                                        </a>
                                        <a href={att.file_url.replace('/upload/', '/upload/fl_attachment/')}
                                          className="absolute top-2 right-2 bg-black/60 hover:bg-black/80 text-white w-8 h-8 rounded-full flex items-center justify-center"><DownloadIcon size={16} /></a>
                                      </div>
                                    ) : (
                                      <div className="flex items-center gap-2 bg-white border rounded-lg p-2">
                                        <a href={att.file_url} target="_blank" rel="noreferrer" className="flex items-center gap-2 flex-1 hover:bg-gray-50 rounded p-1">
                                          <span className="text-2xl">📄</span>
                                          <div>
                                            <div className="font-medium text-gray-700">{att.file_name}</div>
                                            <div className="text-xs text-gray-500">{(att.file_size / 1024).toFixed(1)} KB</div>
                                          </div>
                                        </a>
                                        <a href={att.file_url.replace('/upload/', '/upload/fl_attachment/')}
                                          className="bg-blue-700 hover:bg-blue-800 text-white p-2 rounded"><DownloadIcon size={16} /></a>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )
                        })}
                        <div ref={convEndRef} />
                      </div>

                      {showScrollBtn && (
                        <button onClick={() => convEndRef.current?.scrollIntoView({ behavior: 'smooth' })}
                          className="absolute bottom-20 left-1/2 -translate-x-1/2 bg-blue-700 hover:bg-blue-800 text-white w-10 h-10 rounded-full shadow-lg flex items-center justify-center z-10">
                          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                        </button>
                      )}

                      <div className="p-3 border-t flex gap-2 items-center">
                        <input type="file" ref={convFileRef} onChange={handleConvFileSelect} accept=".jpg,.jpeg,.png,.gif,.pdf,.dwg,.rvt" style={{ display: 'none' }} />
                        <button onClick={() => convFileRef.current?.click()} disabled={uploading}
                          className="bg-gray-200 hover:bg-gray-300 text-gray-700 w-10 h-10 rounded-lg text-xl font-bold transition disabled:opacity-50">
                          {uploading ? '⏳' : '+'}
                        </button>
                        <input value={newConvMessage} onChange={e => setNewConvMessage(e.target.value)}
                          onKeyDown={e => e.key === 'Enter' && sendConvMessage()}
                          onPaste={handlePaste}
                          placeholder="Type a message..."
                          className="flex-1 border border-gray-300 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                        <button onClick={sendConvMessage} className="bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-800 transition">Send</button>
                      </div>
                    </>
                  ) : (
                    <div className="flex-1 flex items-center justify-center text-gray-400">Select a conversation, or start a new one</div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'members' && (
              <div className="bg-white rounded-xl shadow p-6">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold text-gray-700">👥 Team Members</h3>
                  <button onClick={() => setShowAddMemberModal(true)}
                    className="bg-blue-700 hover:bg-blue-800 text-white px-3 py-1.5 rounded-lg text-sm">+ Add Member</button>
                </div>
                <div className="space-y-2">
                  {openedProject.members?.map(m => (
                    <div key={m.user_email} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-blue-700 rounded-full flex items-center justify-center text-white font-bold">
                          {(m.full_name || m.user_email)[0].toUpperCase()}
                        </div>

                        <div>
                          <p className="font-medium text-gray-800">{m.full_name || m.user_email}</p>
                          <p className="text-xs text-gray-500">{m.user_email}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <select value={m.role} onChange={e => updateMemberRole(m.user_email, e.target.value)}
                          className="text-sm border border-gray-300 rounded px-2 py-1 bg-white">
                          {ROLES.map(r => (<option key={r} value={r}>{r}</option>))}
                        </select>
                        <button onClick={() => removeMember(m.user_email)} className="text-red-600 hover:bg-red-50 px-2 py-1 rounded text-sm">✕</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'files' && (
              selectedFile ? (
                <div className="bg-white rounded-xl shadow p-6">
                  <button onClick={() => setSelectedFile(null)}
                    className="text-sm text-gray-500 hover:text-gray-700 mb-4">← Back to files</button>
                  <div className="flex items-center gap-3 mb-4">
                    <span className="text-3xl">📐</span>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-800">{selectedFile.file_name}</h3>
                      <p className="text-xs text-gray-500">Linked by {selectedFile.linked_by} on {new Date(selectedFile.linked_at).toLocaleDateString()}</p>
                    </div>
                  </div>
                  <div className="space-y-2 text-sm border-t pt-4">
                    <div className="flex justify-between"><span className="text-gray-500">File name</span><span className="font-medium text-gray-800">{selectedFile.file_name}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">Linked by</span><span className="font-medium text-gray-800">{selectedFile.linked_by || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">Linked at</span><span className="font-medium text-gray-800">{selectedFile.linked_at ? new Date(selectedFile.linked_at).toLocaleString() : '—'}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">On web (3D)</span>
                      <span className={`font-medium ${isOnWeb(selectedFile) ? 'text-green-600' : 'text-gray-400'}`}>
                        {isOnWeb(selectedFile) ? 'Ready' : 'Not on web yet'}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-2 mt-6 pt-4 border-t">
                    <button onClick={() => open3D(selectedFile)}
                      className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm">🧊 Open 3D</button>
                    <button onClick={() => { unlinkFile(selectedFile.id, selectedFile.file_name); setSelectedFile(null) }}
                      className="text-red-600 hover:bg-red-50 px-3 py-2 rounded-lg text-sm">✕ Unlink</button>
                  </div>
                </div>
              ) : (
                <div className="bg-white rounded-xl shadow p-6">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-semibold text-gray-700">📐 Revit Files</h3>
                    {isManager && (
                      <button onClick={() => setNewFolderParent(null)}
                        className="bg-blue-700 hover:bg-blue-800 text-white px-3 py-1.5 rounded-lg text-sm">
                        + New folder
                      </button>
                    )}
                  </div>

                  <p className="text-xs text-gray-500 mb-3">
                    Manage the models linked from Revit. Select published models to open them together in 3D.
                  </p>

                  {newFolderParent === null && (
                    <NewFolderInput onCreate={(name) => createFolder(null, name)}
                      onCancel={() => setNewFolderParent(undefined)} />
                  )}

                  {(() => {
                    const allFiles = openedProject.files || []
                    const rootFolders = folders.filter(f => f.parent_id === null)
                    const childFolders = (pid) => folders.filter(f => f.parent_id === pid)
                    const filesIn = (folderId) => allFiles.filter(f => f.folder_id === folderId)
                    const noFolder = allFiles.filter(f => !f.folder_id)

                    const FileRow = ({ f }) => {
                      const onWeb = isOnWeb(f)
                      const checked = federatedSel.has(f.id)
                      return (
                        <div className={`flex items-center gap-3 p-2 rounded-lg transition ml-6
                          ${checked ? 'bg-blue-50' : 'bg-gray-50 hover:bg-gray-100'}`}>
                          <input type="checkbox"
                            checked={checked}
                            disabled={!onWeb}
                            onChange={() => toggleFederated(f.id)}
                            title={onWeb ? 'Select for federated 3D' : 'Not on web yet — open it in Revit and press "Web"'}
                            className="w-4 h-4 accent-blue-700 disabled:opacity-40 disabled:cursor-not-allowed" />
                          <button onClick={() => open3D(f)}
                            className="text-xl hover:scale-110 transition" title="Open 3D">🧊</button>
                          <div className="flex-1 cursor-pointer min-w-0" onClick={() => setSelectedFile(f)}>
                            <p className="font-medium text-gray-800 truncate">{f.file_name}</p>
                          </div>
                          {!onWeb && (
                            <span className="text-[10px] font-medium text-gray-500 bg-gray-200 rounded px-1.5 py-0.5 flex-shrink-0">
                              not on web
                            </span>
                          )}
                          <button onClick={() => unlinkFile(f.id, f.file_name)}
                            className="text-red-600 hover:bg-red-50 px-2 py-1 rounded text-sm"
                            title="Unlink">✕</button>
                        </div>
                      )
                    }

                    const FolderNode = ({ folder, level }) => {
                      const isOpen = expandedFolders[folder.id] !== false
                      const toggle = () => setExpandedFolders(prev => ({ ...prev, [folder.id]: prev[folder.id] === false ? true : false }))
                      return (
                      <div className="mb-1">
                        <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-gray-50"
                          style={{ marginLeft: level * 12 }}>
                          <button onClick={toggle} className="text-gray-400 text-xs w-3">{isOpen ? '▾' : '▸'}</button>
                          <span className="text-base">📁</span>
                          <span className="font-medium text-gray-700 flex-1 cursor-pointer" onClick={toggle}>{folder.name}</span>
                          {isManager && (
                            <>
                              {level === 0 && (
                                <button onClick={() => setNewFolderParent(folder.id)}
                                  className="text-xs text-blue-700 hover:bg-blue-50 px-2 py-0.5 rounded">+ sub</button>
                              )}
                              <button onClick={() => renameFolder(folder.id, folder.name)}
                                className="text-xs text-gray-500 hover:bg-gray-100 px-1.5 py-0.5 rounded" title="Rename">✏️</button>
                              <button onClick={() => deleteFolder(folder.id, folder.name)}
                                className="text-xs text-red-600 hover:bg-red-50 px-1.5 py-0.5 rounded" title="Delete">🗑</button>
                            </>
                          )}
                        </div>
                        {isOpen && (
                          <>
                            {newFolderParent === folder.id && (
                              <div style={{ marginLeft: (level + 1) * 12 }}>
                                <NewFolderInput onCreate={(name) => createFolder(folder.id, name)}
                                  onCancel={() => setNewFolderParent(undefined)} />
                              </div>
                            )}
                            {filesIn(folder.id).map(f => <FileRow key={f.id} f={f} />)}
                            {childFolders(folder.id).map(cf => (
                              <FolderNode key={cf.id} folder={cf} level={level + 1} />
                            ))}
                          </>
                        )}
                      </div>
                      )
                    }

                    if (allFiles.length === 0 && folders.length === 0) {
                      return <p className="text-gray-500 text-sm text-center py-4">No folders or files yet. {isManager ? 'Create a folder to organize models.' : ''}</p>
                    }

                    return (
                      <div className="space-y-1">
                        {rootFolders.map(rf => <FolderNode key={rf.id} folder={rf} level={0} />)}
                        {noFolder.length > 0 && (
                          <div className="mb-1 mt-2">
                            <div className="flex items-center gap-2 px-2 py-1.5 text-gray-500">
                              <span className="text-base">📂</span>
                              <span className="font-medium flex-1">No folder</span>
                            </div>
                            {noFolder.map(f => <FileRow key={f.id} f={f} />)}
                          </div>
                        )}
                      </div>
                    )
                  })()}
                </div>
              )
            )}

            {activeTab === 'settings' && (
              <div className="bg-white rounded-xl shadow p-6">
                <h3 className="text-lg font-semibold text-gray-700 mb-2">⚙️ Settings</h3>
                <p className="text-gray-500 text-sm">Coming soon.</p>
              </div>
            )}
          </main>
        </div>
      )}

      {/* ---------- FEDERATED SELECTION BAR ---------- */}
      {openedProject && activeTab === 'files' && federatedSel.size > 0 && !viewerFiles && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 bg-white rounded-full shadow-xl border border-gray-200 flex items-center gap-3 pl-5 pr-3 py-2">
          <span className="text-sm text-gray-700">
            <span className="font-bold text-blue-700">{federatedSel.size}</span> model(s) selected
          </span>
          <button onClick={clearFederated}
            className="text-sm text-gray-500 hover:bg-gray-100 rounded-full px-3 py-1.5">Clear</button>
          <button onClick={openFederated}
            className="bg-blue-700 hover:bg-blue-800 text-white text-sm font-medium rounded-full px-4 py-1.5">
            🧊 Open 3D ({federatedSel.size})
          </button>
        </div>
      )}

      {/* ---------- NEW CONVERSATION MODAL ---------- */}
      {showNewConvModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold text-gray-800 mb-4">New conversation</h2>

            <div className="inline-flex bg-gray-200 rounded-lg p-1 mb-4">
              <button onClick={() => { setNcType('dm'); setNcMembers([]) }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium transition ${ncType === 'dm' ? 'bg-white text-blue-700 shadow' : 'text-gray-600'}`}>
                👤 Direct
              </button>
              <button onClick={() => { setNcType('group'); setNcMembers([]) }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium transition ${ncType === 'group' ? 'bg-white text-blue-700 shadow' : 'text-gray-600'}`}>
                👥 Group
              </button>
            </div>

            <div className="space-y-3">
              {ncType === 'group' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Group name *</label>
                  <input value={ncName} onChange={e => setNcName(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" placeholder="e.g. Structure team" />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  {ncType === 'dm' ? 'Person *' : 'Members *'}
                </label>
                <div className="border border-gray-300 rounded-lg max-h-40 overflow-y-auto">
                  {projectMembersExceptMe.length === 0 ? (
                    <p className="text-xs text-gray-400 p-3">No other members in this project yet.</p>
                  ) : projectMembersExceptMe.map(m => {
                    const checked = ncMembers.includes(m.user_email)
                    return (
                      <label key={m.user_email}
                        className="flex items-center gap-2 px-3 py-2 hover:bg-gray-50 cursor-pointer text-sm border-b last:border-b-0">
                        <input
                          type={ncType === 'dm' ? 'radio' : 'checkbox'}
                          name="conv-members"
                          checked={checked}
                          onChange={() => {
                            if (ncType === 'dm') setNcMembers([m.user_email])
                            else setNcMembers(prev => checked ? prev.filter(e => e !== m.user_email) : [...prev, m.user_email])
                          }} />
                        <span className="text-gray-800">{m.full_name || m.user_email}</span>
                        <span className="text-xs text-gray-400">{m.user_email}</span>
                      </label>
                    )
                  })}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Level (where it shows)</label>
                <select value={ncLevel} onChange={e => { setNcLevel(e.target.value); setNcFolderId(''); setNcFileId('') }}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white">
                  <option value="project">🌐 Project — visible everywhere</option>
                  <option value="folder">📁 Folder/Discipline</option>
                  <option value="model">🧊 Model</option>
                </select>
              </div>

              {ncLevel === 'folder' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Folder *</label>
                  <select value={ncFolderId} onChange={e => setNcFolderId(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white">
                    <option value="">Select folder...</option>
                    {folders.map(f => {
                      const parent = f.parent_id ? folders.find(p => p.id === f.parent_id) : null
                      return <option key={f.id} value={f.id}>{parent ? `${parent.name} / ${f.name}` : f.name}</option>
                    })}
                  </select>
                </div>
              )}

              {ncLevel === 'model' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Model *</label>
                  <select value={ncFileId} onChange={e => setNcFileId(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white">
                    <option value="">Select model...</option>
                    {(openedProject.files || []).map(f => (
                      <option key={f.id} value={f.id}>{f.file_name}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button onClick={closeNewConvModal}
                className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg text-sm">Cancel</button>
              <button onClick={createConversation}
                className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm font-medium">Create</button>
            </div>
          </div>
        </div>
      )}

      {showNewProjectModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold text-gray-800 mb-4">Create New Project</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Project Name *</label>
                <input value={newProjectName} onChange={e => setNewProjectName(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" placeholder="e.g. Office Tower A" autoFocus />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                <textarea value={newProjectDesc} onChange={e => setNewProjectDesc(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" rows={3} />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Deadline</label>
                <input type="date" value={newProjectDeadline} onChange={e => setNewProjectDeadline(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => { setShowNewProjectModal(false); setNewProjectName(''); setNewProjectDesc(''); setNewProjectDeadline('') }}
                className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg text-sm">Cancel</button>
              <button onClick={createProject} className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm font-medium">Create</button>
            </div>
          </div>
        </div>
      )}

      {showAddMemberModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold text-gray-800 mb-4">Add Team Member</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">User Email *</label>
                <input value={newMemberEmail} onChange={e => setNewMemberEmail(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" placeholder="user@example.com" autoFocus />
                <p className="text-xs text-gray-500 mt-1">User must have an account already</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                <select value={newMemberRole} onChange={e => setNewMemberRole(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white">
                  {ROLES.map(r => (<option key={r} value={r}>{r}</option>))}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => { setShowAddMemberModal(false); setNewMemberEmail(''); setNewMemberRole('BIM Specialist') }}
                className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg text-sm">Cancel</button>
              <button onClick={addMember} className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm font-medium">Add Member</button>
            </div>
          </div>
        </div>
      )}

      {/* Live 3D scene (single or multiple models, added/removed from the sidebar) */}
      {viewerFiles && (
        <Suspense fallback={<div className="bc-viewer bc-empty" role="status"><Icon name="model" size={34} /><h3>Opening 3D workspace…</h3><p>The viewer is loading.</p><button className="bc-button" onClick={() => setViewerFiles(null)}>Back to models</button></div>}><Viewer
          files={viewerFiles}
          projectName={openedProject.name}
          projectId={openedProject.id}
          folders={folders}
          projectFiles={openedProject.files || []}
          projectMembers={openedProject.members || []}
          token={token}
          onClose={() => { setViewerFiles(null); setActiveTab('models') }}
          modelControls={<ModelBrowser scene files={openedProject.files || []} folders={folders} selected={new Set(viewerFiles.map(file => file.id))} onToggle={id => toggleSceneModel(openedProject.files.find(file => file.id === id))} />}
        /></Suspense>
      )}
    </div>
  )
}

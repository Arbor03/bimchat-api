import Icon from '../components/Icon'
import { useEffect, useRef, useState } from 'react'
import axios from 'axios'
import * as OBC from '@thatopen/components'
import * as FRAGS from '@thatopen/fragments'
import * as THREE from 'three'

import { API } from '../api'

// Visual + ordering config for conversation levels (project > folder > model)
const LEVEL_META = {
  project: { order: 0, icon: '🌐', header: 'Project',               border: 'border-l-indigo-500', badge: 'bg-indigo-100 text-indigo-700' },
  folder:  { order: 1, icon: '📁', header: 'Folders / Disciplines', border: 'border-l-amber-500',  badge: 'bg-amber-100 text-amber-700' },
  model:   { order: 2, icon: '🧊', header: 'Models',                border: 'border-l-teal-500',   badge: 'bg-teal-100 text-teal-700' },
}

// 3D viewer + side panel (Tasks | Chat). The scene is "live": models can be
// added/removed at any time (driven by `files` from the dashboard sidebar).
// The 3D world is built ONCE; a separate effect loads/disposes models as `files`
// changes, so toggling a model does not rebuild the whole viewer.
//
// Active-model rule (Opsioni A): clicking an element only SELECTS it (highlight,
// properties, link). It does NOT change the chat context. You "enter" a model
// explicitly: double-click a model (or pick it in the "Active model" dropdown).
// Double-click empty space exits to project/folder context.
function emailFromToken(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    const payload = JSON.parse(decodeURIComponent(escape(atob(part))))
    return payload.email || null
  } catch { return null }
}

const ANNOT_COLORS = ['#e74c3c', '#f1c40f', '#2ecc71', '#3498db', '#000000']
const ANNOT_TOOLS = [
  { id: 'select', label: '⤢ Select' },
  { id: 'pen', label: '✏️ Pen' },
  { id: 'highlight', label: '🖍 Highlight' },
  { id: 'text', label: '🅰 Text' },
  { id: 'callout', label: '💬 Callout' },
  { id: 'cloud', label: '☁ Cloud' },
  { id: 'cloudtext', label: '☁🅰 Revision' },
  { id: 'arrow', label: '➦ Arrow' },
  { id: 'rect', label: '▭ Rect' },
  { id: 'stamp', label: '🔖 Stamp' },
]

// Floating, draggable, resizable annotate window. Annotations stay editable
// (select / move / resize / re-edit / delete) and are flattened only on Send.
function AnnotateModal({ imageUrl, onCancel, onSend }) {
  const canvasRef = useRef(null)
  const imgRef = useRef(null)
  const scrollRef = useRef(null)
  const [imgLoaded, setImgLoaded] = useState(false)
  const [imgVer, setImgVer] = useState(0)

  const [tool, setTool] = useState('pen')
  const [color, setColor] = useState('#e74c3c')
  const [width, setWidth] = useState(3)
  const [fontSize, setFontSize] = useState(28)
  const [stampKind, setStampKind] = useState('check')   // check | cross | rev
  const stampKindRef = useRef('check'); useEffect(() => { stampKindRef.current = stampKind }, [stampKind])
  const revNumRef = useRef(1)   // auto-incrementing Δ number

  const [shapes, setShapes] = useState([])
  const shapesRef = useRef([])
  useEffect(() => { shapesRef.current = shapes }, [shapes])
  const idRef = useRef(1)
  const histRef = useRef({ past: [], future: [] })   // undo/redo stacks of shape snapshots
  const prevShapesRef = useRef([])
  const skipHistRef = useRef(false)
  const zoomAnchorRef = useRef(null)   // {ix,iy,clientX,clientY} to zoom around cursor
  const mountedRef = useRef(false)
  const [histTick, setHistTick] = useState(0)        // re-render so button states update

  const [selId, setSelId] = useState(null)
  const selIdRef = useRef(null)
  const calloutTargetRef = useRef(null)   // 1st click of a callout (leader start)
  const cloudTextPendingRef = useRef(null) // cloud drawn, waiting for the text click
  useEffect(() => { selIdRef.current = selId }, [selId])

  // zoom / fit
  const natRef = useRef({ w: 0, h: 0 })
  const fitRef = useRef(1)
  const [zoom, setZoom] = useState(1) // canvas px -> CSS px
  const zoomRef = useRef(1); useEffect(() => { zoomRef.current = zoom }, [zoom])
  const userZoomedRef = useRef(false)  // true once the user zooms manually

  // floating window position + size
  const [pos, setPos] = useState({ x: 70, y: 70 })
  const [size, setSize] = useState({ w: 720, h: 560 })
  const [full, setFull] = useState(false)
  const dragRef = useRef(null)
  const resizeRef = useRef(null)

  // inline text editor overlay
  const [editor, setEditor] = useState(null) // { kind, cx, cy, target, text, editId? }
  const editorInputRef = useRef(null)

  const toolRef = useRef(tool); useEffect(() => { toolRef.current = tool }, [tool])
  const colorRef = useRef(color); useEffect(() => { colorRef.current = color }, [color])
  const widthRef = useRef(width); useEffect(() => { widthRef.current = width }, [width])
  const fontSizeRef = useRef(fontSize); useEffect(() => { fontSizeRef.current = fontSize }, [fontSize])
  const interRef = useRef(null) // active interaction {mode,...}

  // load base image, compute fit
  useEffect(() => {
    const img = new Image()
    img.onload = () => {
      imgRef.current = img
      natRef.current = { w: img.naturalWidth, h: img.naturalHeight }
      userZoomedRef.current = false
      setShapes([])            // drop annotations from the previous screenshot
      setSelId(null); selIdRef.current = null
      setEditor(null)
      setImgLoaded(true)
      setImgVer(v => v + 1)    // force the sizing effect to run for EVERY new image
    }
    img.src = imageUrl
  }, [imageUrl])

  // The <canvas> only mounts after imgLoaded, so size it HERE (canvas now
  // exists) — not inside img.onload, where canvasRef was still null and the
  // canvas stayed at its default 300x150 (which clipped the screenshot). Runs
  // on every new image (imgVer) so a 2nd/3rd capture resizes instead of
  // stretching the old canvas.
  useEffect(() => {
    if (!imgLoaded) return
    const c = canvasRef.current
    if (c) { c.width = natRef.current.w; c.height = natRef.current.h }
    redraw()
    requestAnimationFrame(() => { fitToWindow(); requestAnimationFrame(fitToWindow) })
  }, [imgVer])

  const areaSize = () => {
    const el = scrollRef.current
    if (el && el.clientWidth > 20 && el.clientHeight > 20) return { w: el.clientWidth - 8, h: el.clientHeight - 8 }
    return { w: size.w - 24, h: size.h - 150 }
  }
  const fitToWindow = () => {
    const n = natRef.current
    if (!n.w) return
    const a = areaSize()
    const f = Math.min(a.w / n.w, a.h / n.h, 1) || 1
    fitRef.current = f
    setZoom(f)
  }

  // Re-fit whenever the scroll area gets/changes its real size (fixes the
  // "image shows only a corner" race where fit ran before layout settled).
  useEffect(() => {
    const el = scrollRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => { if (!userZoomedRef.current) fitToWindow() })
    ro.observe(el)
    return () => ro.disconnect()
  }, [imgLoaded])

  // keep fit correct as the window is resized / toggled fullscreen
  useEffect(() => { if (imgLoaded && !userZoomedRef.current) requestAnimationFrame(fitToWindow) }, [size.w, size.h, full])

  // zoom around the cursor: after the canvas resized, scroll so the anchored
  // image point stays under the mouse
  useEffect(() => {
    const a = zoomAnchorRef.current
    const c = canvasRef.current, sc = scrollRef.current
    if (!a || !c || !sc) return
    const rect = c.getBoundingClientRect()
    sc.scrollLeft += rect.left - (a.clientX - a.ix * zoom)
    sc.scrollTop += rect.top - (a.clientY - a.iy * zoom)
    zoomAnchorRef.current = null
  }, [zoom])

  // ---------- drawing primitives ----------
  const drawArrow = (ctx, x1, y1, x2, y2, lw) => {
    const head = Math.max(10, lw * 3)
    const ang = Math.atan2(y2 - y1, x2 - x1)
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke()
    ctx.beginPath(); ctx.moveTo(x2, y2)
    ctx.lineTo(x2 - head * Math.cos(ang - Math.PI / 6), y2 - head * Math.sin(ang - Math.PI / 6))
    ctx.lineTo(x2 - head * Math.cos(ang + Math.PI / 6), y2 - head * Math.sin(ang + Math.PI / 6))
    ctx.closePath(); ctx.fillStyle = ctx.strokeStyle; ctx.fill()
  }
  const drawCloud = (ctx, x, y, w, h) => {
    const x0 = Math.min(x, x + w), y0 = Math.min(y, y + h)
    const ww = Math.abs(w), hh = Math.abs(h)
    if (ww < 6 || hh < 6) return
    const r = Math.max(8, Math.min(ww, hh) / 6)
    const scallop = (ax, ay, bx, by, nx, ny) => {
      const dx = bx - ax, dy = by - ay, len = Math.hypot(dx, dy)
      const n = Math.max(2, Math.round(len / (r * 1.8)))
      for (let i = 0; i < n; i++) {
        const ex = ax + dx * (i + 1) / n, ey = ay + dy * (i + 1) / n
        const sx = ax + dx * i / n, sy = ay + dy * i / n
        const cx = (sx + ex) / 2 + nx * r, cy = (sy + ey) / 2 + ny * r
        ctx.quadraticCurveTo(cx, cy, ex, ey)
      }
    }
    ctx.beginPath(); ctx.moveTo(x0, y0)
    scallop(x0, y0, x0 + ww, y0, 0, -1)
    scallop(x0 + ww, y0, x0 + ww, y0 + hh, 1, 0)
    scallop(x0 + ww, y0 + hh, x0, y0 + hh, 0, 1)
    scallop(x0, y0 + hh, x0, y0, -1, 0)
    ctx.closePath(); ctx.stroke()
  }
  const fontPx = (s) => s.fontSize ? s.fontSize : Math.max(14, s.width * 6)
  const textLines = (s) => String(s.text).split('\n')
  const textBox = (ctx, s) => {
    const fs = fontPx(s); ctx.font = `bold ${fs}px sans-serif`
    const lines = textLines(s)
    const tw = Math.max(1, ...lines.map(l => ctx.measureText(l).width))
    return { w: tw, h: lines.length * fs * 1.2, fs, lines }
  }
  const drawText = (ctx, s) => {
    const b = textBox(ctx, s)
    ctx.textBaseline = 'top'; ctx.fillStyle = s.color
    b.lines.forEach((ln, i) => ctx.fillText(ln, s.x, s.y + i * b.fs * 1.2))
  }
  const drawCallout = (ctx, s) => {
    const b = textBox(ctx, s); const padX = 4, padY = 2
    const bw = b.w + padX * 2
    const bh = b.h + padY * 2
    const underlineY = s.y + bh
    // leader: from the target point to the LEFT end of the underline
    if (s.target) {
      ctx.strokeStyle = s.color; ctx.lineWidth = s.width
      ctx.beginPath(); ctx.moveTo(s.target.x, s.target.y); ctx.lineTo(s.x, underlineY); ctx.stroke()
      if (!s._noDot) {
        ctx.beginPath(); ctx.arc(s.target.x, s.target.y, Math.max(3, s.width), 0, Math.PI * 2)
        ctx.fillStyle = s.color; ctx.fill()
      }
    }
    // subtle background for legibility (no border box)
    ctx.fillStyle = 'rgba(255,255,255,0.85)'; ctx.fillRect(s.x, s.y, bw, bh)
    // text
    ctx.fillStyle = s.color; ctx.textBaseline = 'top'
    b.lines.forEach((ln, i) => ctx.fillText(ln, s.x + padX, s.y + padY + i * b.fs * 1.2))
    // the single underline below the text
    ctx.strokeStyle = s.color; ctx.lineWidth = s.width
    ctx.beginPath(); ctx.moveTo(s.x, underlineY); ctx.lineTo(s.x + bw, underlineY); ctx.stroke()
  }
  const drawCloudText = (ctx, s) => {
    drawCloud(ctx, s.x, s.y, s.w, s.h)
    const cx = s.x + s.w / 2, cy = s.y + s.h / 2     // logical anchor = cloud center (stable)
    const b = textBox(ctx, s)
    const px = s.tx, py = s.ty + b.h + 4              // text underline-left (matches drawCallout)
    drawCallout(ctx, { ...s, x: s.tx, y: s.ty, target: null })
    // leader from center to text, but visible only OUTSIDE the virtual rect
    const dx = px - cx, dy = py - cy
    const tX = Math.abs(dx) > 1e-3 ? (s.w / 2) / Math.abs(dx) : Infinity
    const tY = Math.abs(dy) > 1e-3 ? (s.h / 2) / Math.abs(dy) : Infinity
    const t = Math.min(tX, tY, 1)                     // exit point on the rectangle edge
    const edge = { x: cx + dx * t, y: cy + dy * t }
    ctx.strokeStyle = s.color; ctx.lineWidth = s.width
    ctx.beginPath(); ctx.moveTo(edge.x, edge.y); ctx.lineTo(px, py); ctx.stroke()
  }
  const drawStamp = (ctx, s) => {
    const sz = s.fontSize || 28
    const x = s.x, y = s.y   // center
    ctx.save()
    ctx.strokeStyle = s.color; ctx.fillStyle = s.color
    ctx.lineWidth = Math.max(2, s.width); ctx.lineCap = 'round'; ctx.lineJoin = 'round'
    if (s.kind === 'check') {
      ctx.beginPath(); ctx.moveTo(x - sz * 0.4, y); ctx.lineTo(x - sz * 0.08, y + sz * 0.38); ctx.lineTo(x + sz * 0.45, y - sz * 0.42); ctx.stroke()
    } else if (s.kind === 'cross') {
      ctx.beginPath(); ctx.moveTo(x - sz * 0.4, y - sz * 0.4); ctx.lineTo(x + sz * 0.4, y + sz * 0.4)
      ctx.moveTo(x + sz * 0.4, y - sz * 0.4); ctx.lineTo(x - sz * 0.4, y + sz * 0.4); ctx.stroke()
    } else if (s.kind === 'rev') {
      const w = sz * 1.8, h = sz * 1.4
      drawCloud(ctx, x - w / 2, y - h / 2, w, h)
      ctx.fillStyle = s.color; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
      ctx.font = `bold ${sz * 0.8}px sans-serif`
      ctx.fillText('Δ' + s.num, x, y + sz * 0.02)
      ctx.textAlign = 'start'
    }
    ctx.restore()
  }
  const drawShape = (ctx, s) => {
    ctx.strokeStyle = s.color; ctx.fillStyle = s.color
    ctx.lineWidth = s.width; ctx.lineJoin = 'round'; ctx.lineCap = 'round'
    if (s.tool === 'pen') { ctx.beginPath(); s.points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)); ctx.stroke() }
    else if (s.tool === 'highlight') {
      ctx.save()
      ctx.globalAlpha = 0.35; ctx.lineWidth = s.width * 5; ctx.lineCap = 'round'; ctx.lineJoin = 'round'
      ctx.beginPath(); s.points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)); ctx.stroke()
      ctx.restore()
    }
    else if (s.tool === 'rect') ctx.strokeRect(s.x, s.y, s.w, s.h)
    else if (s.tool === 'arrow') drawArrow(ctx, s.x1, s.y1, s.x2, s.y2, s.width)
    else if (s.tool === 'cloud') drawCloud(ctx, s.x, s.y, s.w, s.h)
    else if (s.tool === 'text') drawText(ctx, s)
    else if (s.tool === 'callout') drawCallout(ctx, s)
    else if (s.tool === 'cloudtext') drawCloudText(ctx, s)
    else if (s.tool === 'stamp') drawStamp(ctx, s)
  }

  // ---------- geometry helpers ----------
  const bbox = (s) => {
    const ctx = canvasRef.current?.getContext('2d')
    if (s.tool === 'rect' || s.tool === 'cloud') return { x: Math.min(s.x, s.x + s.w), y: Math.min(s.y, s.y + s.h), w: Math.abs(s.w), h: Math.abs(s.h) }
    if (s.tool === 'arrow') return { x: Math.min(s.x1, s.x2), y: Math.min(s.y1, s.y2), w: Math.abs(s.x2 - s.x1), h: Math.abs(s.y2 - s.y1) }
    if (s.tool === 'pen' || s.tool === 'highlight') {
      const xs = s.points.map(p => p.x), ys = s.points.map(p => p.y)
      return { x: Math.min(...xs), y: Math.min(...ys), w: Math.max(...xs) - Math.min(...xs), h: Math.max(...ys) - Math.min(...ys) }
    }
    if (ctx && (s.tool === 'text' || s.tool === 'callout')) {
      const b = textBox(ctx, s)
      if (s.tool === 'callout') return { x: s.x, y: s.y, w: b.w + 8, h: b.h + 4 }
      return { x: s.x, y: s.y, w: b.w, h: b.h }
    }
    if (ctx && s.tool === 'cloudtext') {
      const b = textBox(ctx, s)
      const x0 = Math.min(s.x, s.tx), y0 = Math.min(s.y, s.ty)
      const x1 = Math.max(s.x + s.w, s.tx + b.w + 8), y1 = Math.max(s.y + s.h, s.ty + b.h + 4)
      return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
    }
    if (s.tool === 'stamp') {
      const sz = s.fontSize || 28
      if (s.kind === 'rev') { const w = sz * 1.8, h = sz * 1.4; return { x: s.x - w / 2, y: s.y - h / 2, w, h } }
      const d = sz * 0.95; return { x: s.x - d / 2, y: s.y - d / 2, w: d, h: d }
    }
    return { x: s.x || 0, y: s.y || 0, w: 0, h: 0 }
  }
  const handlesOf = (s) => {
    if (s.tool === 'arrow') return [{ id: 'p1', x: s.x1, y: s.y1 }, { id: 'p2', x: s.x2, y: s.y2 }]
    if (s.tool === 'callout') {
      const b = bbox(s); const hs = [{ id: 'box', x: b.x, y: b.y }]
      if (s.target) hs.push({ id: 'target', x: s.target.x, y: s.target.y })
      return hs
    }
    if (s.tool === 'rect' || s.tool === 'cloud') {
      const b = bbox(s)
      return [
        { id: 'tl', x: b.x, y: b.y }, { id: 'tr', x: b.x + b.w, y: b.y },
        { id: 'br', x: b.x + b.w, y: b.y + b.h }, { id: 'bl', x: b.x, y: b.y + b.h },
      ]
    }
    if (s.tool === 'cloudtext') {
      return [
        { id: 'tl', x: s.x, y: s.y }, { id: 'tr', x: s.x + s.w, y: s.y },
        { id: 'br', x: s.x + s.w, y: s.y + s.h }, { id: 'bl', x: s.x, y: s.y + s.h },
        { id: 'text', x: s.tx, y: s.ty },
      ]
    }
    return []
  }
  const hitShape = (px, py) => {
    const arr = shapesRef.current
    for (let i = arr.length - 1; i >= 0; i--) {
      const s = arr[i]
      if (s.tool === 'arrow') {
        if (distToSeg(px, py, s.x1, s.y1, s.x2, s.y2) < Math.max(8, s.width + 6) / zoomRef.current) return s
      } else {
        const b = bbox(s); const pad = 6 / zoomRef.current
        if (px >= b.x - pad && px <= b.x + b.w + pad && py >= b.y - pad && py <= b.y + b.h + pad) return s
      }
    }
    return null
  }
  const distToSeg = (px, py, x1, y1, x2, y2) => {
    const dx = x2 - x1, dy = y2 - y1
    const t = Math.max(0, Math.min(1, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy || 1)))
    return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))
  }

  // ---------- redraw ----------
  const redraw = (preview) => {
    const c = canvasRef.current, img = imgRef.current
    if (!c || !img) return
    const ctx = c.getContext('2d')
    ctx.clearRect(0, 0, c.width, c.height)
    ctx.drawImage(img, 0, 0)
    for (const s of shapesRef.current) drawShape(ctx, s)
    if (preview) drawShape(ctx, preview)
    // selection overlay (not exported — we deselect before Send)
    const sel = shapesRef.current.find(s => s.id === selIdRef.current)
    if (sel) {
      const z = zoomRef.current, b = bbox(sel)
      ctx.save()
      ctx.strokeStyle = '#2563eb'; ctx.lineWidth = 1 / z; ctx.setLineDash([5 / z, 4 / z])
      ctx.strokeRect(b.x, b.y, b.w, b.h); ctx.setLineDash([])
      const hs = 8 / z
      ctx.fillStyle = '#fff'; ctx.strokeStyle = '#2563eb'; ctx.lineWidth = 1.5 / z
      for (const h of handlesOf(sel)) {
        ctx.beginPath(); ctx.rect(h.x - hs / 2, h.y - hs / 2, hs, hs); ctx.fill(); ctx.stroke()
      }
      ctx.restore()
    }
  }
  useEffect(() => { if (imgLoaded) redraw() }, [imgLoaded, shapes, selId, zoom])

  const toCanvasXY = (e) => {
    const c = canvasRef.current, rect = c.getBoundingClientRect()
    return { x: (e.clientX - rect.left) * (c.width / rect.width), y: (e.clientY - rect.top) * (c.height / rect.height) }
  }
  const cssOf = (cx, cy) => ({ left: cx * zoom, top: cy * zoom })

  // ---------- inline text editing ----------
  const openEditorFor = (s) => {
    setSelId(s.id)
    const cx = s.tool === 'cloudtext' ? s.tx : s.x
    const cy = s.tool === 'cloudtext' ? s.ty : s.y
    setEditor({ kind: s.tool, cx, cy, target: s.target || null, text: s.text, editId: s.id })
    setTimeout(() => editorInputRef.current?.focus(), 0)
  }
  const commitEditor = () => {
    setEditor(ed => {
      if (!ed) return null
      const txt = (ed.text || '').trim()
      if (ed.editId != null) {
        setShapes(prev => prev.map(s => s.id === ed.editId ? (txt ? { ...s, text: txt } : s) : s)
          .filter(s => !(s.id === ed.editId && !txt)))
      } else if (txt) {
        const shape = ed.kind === 'callout'
          ? { id: idRef.current++, tool: 'callout', color: colorRef.current, width: widthRef.current, fontSize: fontSizeRef.current, x: ed.cx, y: ed.cy, target: ed.target, text: txt }
          : ed.kind === 'cloudtext'
          ? { id: idRef.current++, tool: 'cloudtext', color: colorRef.current, width: widthRef.current, fontSize: fontSizeRef.current, x: ed.cloud.x, y: ed.cloud.y, w: ed.cloud.w, h: ed.cloud.h, tx: ed.cx, ty: ed.cy, text: txt }
          : { id: idRef.current++, tool: 'text', color: colorRef.current, width: widthRef.current, fontSize: fontSizeRef.current, x: ed.cx, y: ed.cy, text: txt }
        setShapes(prev => [...prev, shape])
      }
      return null
    })
  }

  // ---------- pointer interaction ----------
  const onDown = (e) => {
    if (editor) { commitEditor(); return }
    const p = toCanvasXY(e)
    const t = toolRef.current

    if (t === 'select') {
      // 1) handle of selected shape?
      const sel = shapesRef.current.find(s => s.id === selIdRef.current)
      if (sel) {
        const hs = 9 / zoomRef.current
        for (const h of handlesOf(sel)) {
          if (Math.abs(p.x - h.x) <= hs && Math.abs(p.y - h.y) <= hs) {
            interRef.current = { mode: 'resize', id: sel.id, handle: h.id, start: p }
            return
          }
        }
      }
      // 2) hit a shape -> select + move
      const hitS = hitShape(p.x, p.y)
      if (hitS) {
        setSelId(hitS.id); selIdRef.current = hitS.id
        interRef.current = { mode: 'move', id: hitS.id, last: p }
        redraw()
        return
      }
      // 3) empty -> deselect
      setSelId(null); selIdRef.current = null; redraw()
      return
    }

    // drawing tools
    setSelId(null); selIdRef.current = null
    if (t === 'text') { setEditor({ kind: 'text', cx: p.x, cy: p.y, target: null, text: '', editId: null }); setTimeout(() => editorInputRef.current?.focus(), 0); return }
    if (t === 'callout') {
      if (calloutTargetRef.current == null) {
        // 1st click: set where the leader starts
        calloutTargetRef.current = { x: p.x, y: p.y }
      } else {
        // 2nd click: set text position, then open the editor
        const target = calloutTargetRef.current
        calloutTargetRef.current = null
        setEditor({ kind: 'callout', cx: p.x, cy: p.y, target, text: '', editId: null })
        setTimeout(() => editorInputRef.current?.focus(), 0)
      }
      return
    }
    if (t === 'cloudtext') {
      if (cloudTextPendingRef.current == null) {
        // phase 1: drag out the cloud rectangle
        interRef.current = { mode: 'cloudtextdraw', x: p.x, y: p.y, w: 0, h: 0, _sx: p.x, _sy: p.y }
      } else {
        // phase 2: click places the text, then the editor opens
        const cloud = cloudTextPendingRef.current
        cloudTextPendingRef.current = null
        setEditor({ kind: 'cloudtext', cx: p.x, cy: p.y, cloud, text: '', editId: null })
        setTimeout(() => editorInputRef.current?.focus(), 0)
      }
      return
    }
    if (t === 'stamp') {
      const kind = stampKindRef.current
      const shape = { id: idRef.current++, tool: 'stamp', kind, color: colorRef.current, width: widthRef.current, fontSize: fontSizeRef.current, x: p.x, y: p.y }
      if (kind === 'rev') { shape.num = revNumRef.current; revNumRef.current += 1 }
      setShapes(prev => [...prev, shape])
      setSelId(shape.id); selIdRef.current = shape.id
      return
    }
    if (t === 'pen' || t === 'highlight') { interRef.current = { mode: 'draw', shape: { id: idRef.current++, tool: t, color: colorRef.current, width: widthRef.current, points: [p] } } }
    else { interRef.current = { mode: 'draw', shape: { id: idRef.current++, tool: t, color: colorRef.current, width: widthRef.current, x: p.x, y: p.y, w: 0, h: 0, x1: p.x, y1: p.y, x2: p.x, y2: p.y, _sx: p.x, _sy: p.y } } }
  }

  const onMove = (e) => {
    const p = toCanvasXY(e)
    // callout: after the 1st click, preview the leader following the cursor
    if (toolRef.current === 'callout' && calloutTargetRef.current && !interRef.current) {
      redraw({ tool: 'callout', color: colorRef.current, width: widthRef.current, x: p.x, y: p.y, target: calloutTargetRef.current, text: '…' })
      return
    }
    // cloudtext phase 2: cloud is drawn, preview text+leader following cursor
    if (toolRef.current === 'cloudtext' && cloudTextPendingRef.current && !interRef.current) {
      const cl = cloudTextPendingRef.current
      redraw({ tool: 'cloudtext', color: colorRef.current, width: widthRef.current, x: cl.x, y: cl.y, w: cl.w, h: cl.h, tx: p.x, ty: p.y, text: '…' })
      return
    }
    const it = interRef.current
    if (!it) return

    // cloudtext phase 1: dragging the cloud rectangle
    if (it.mode === 'cloudtextdraw') {
      it.x = Math.min(it._sx, p.x); it.y = Math.min(it._sy, p.y)
      it.w = Math.abs(p.x - it._sx); it.h = Math.abs(p.y - it._sy)
      redraw({ tool: 'cloud', color: colorRef.current, width: widthRef.current, x: it.x, y: it.y, w: it.w, h: it.h })
      return
    }

    if (it.mode === 'draw') {
      const d = it.shape
      if (d.tool === 'pen' || d.tool === 'highlight') d.points.push(p)
      else if (d.tool === 'arrow') { d.x2 = p.x; d.y2 = p.y }
      else { d.x = Math.min(d._sx, p.x); d.y = Math.min(d._sy, p.y); d.w = p.x - d._sx; d.h = p.y - d._sy }
      redraw(d); return
    }
    if (it.mode === 'move') {
      const s = shapesRef.current.find(x => x.id === it.id); if (!s) return
      const dx = p.x - it.last.x, dy = p.y - it.last.y; it.last = p
      translateShape(s, dx, dy); redraw(); return
    }
    if (it.mode === 'resize') {
      const s = shapesRef.current.find(x => x.id === it.id); if (!s) return
      applyResize(s, it.handle, p); redraw(); return
    }
  }

  const onUp = (e) => {
    const it = interRef.current; interRef.current = null
    if (!it) return
    if (it.mode === 'cloudtextdraw') {
      if (it.w < 5 || it.h < 5) { cloudTextPendingRef.current = null; redraw(); return }
      cloudTextPendingRef.current = { x: it.x, y: it.y, w: it.w, h: it.h }
      redraw()
      return
    }
    if (it.mode === 'draw') {
      const d = it.shape
      const tiny = (d.tool === 'rect' || d.tool === 'cloud') && Math.abs(d.w) < 3 && Math.abs(d.h) < 3
      const tinyArrow = d.tool === 'arrow' && Math.hypot(d.x2 - d.x1, d.y2 - d.y1) < 3
      if (tiny || tinyArrow) { redraw(); return }
      if (d.tool === 'rect' || d.tool === 'cloud') { d.x = Math.min(d.x, d.x + d.w); d.y = Math.min(d.y, d.y + d.h); d.w = Math.abs(d.w); d.h = Math.abs(d.h) }
      setShapes(prev => [...prev, d])
      return
    }
    if (it.mode === 'move' || it.mode === 'resize') {
      setShapes([...shapesRef.current]) // sync state
    }
  }

  const onDbl = (e) => {
    const p = toCanvasXY(e)
    const s = hitShape(p.x, p.y)
    if (s && (s.tool === 'text' || s.tool === 'callout' || s.tool === 'cloudtext')) openEditorFor(s)
  }

  const translateShape = (s, dx, dy) => {
    if (s.tool === 'pen' || s.tool === 'highlight') s.points.forEach(p => { p.x += dx; p.y += dy })
    else if (s.tool === 'arrow') { s.x1 += dx; s.y1 += dy; s.x2 += dx; s.y2 += dy }
    else if (s.tool === 'cloudtext') { s.x += dx; s.y += dy; s.tx += dx; s.ty += dy }
    else { s.x += dx; s.y += dy } // rect/cloud/text/callout box (callout target stays anchored)
  }
  const applyResize = (s, handle, p) => {
    if (s.tool === 'arrow') { if (handle === 'p1') { s.x1 = p.x; s.y1 = p.y } else { s.x2 = p.x; s.y2 = p.y }; return }
    if (s.tool === 'callout') { if (handle === 'target') s.target = { x: p.x, y: p.y }; else { s.x = p.x; s.y = p.y }; return }
    if (s.tool === 'cloudtext') {
      if (handle === 'text') { s.tx = p.x; s.ty = p.y; return }
      let x0 = s.x, y0 = s.y, x1 = s.x + s.w, y1 = s.y + s.h
      if (handle === 'tl') { x0 = p.x; y0 = p.y } else if (handle === 'tr') { x1 = p.x; y0 = p.y }
      else if (handle === 'br') { x1 = p.x; y1 = p.y } else if (handle === 'bl') { x0 = p.x; y1 = p.y }
      s.x = Math.min(x0, x1); s.y = Math.min(y0, y1); s.w = Math.abs(x1 - x0); s.h = Math.abs(y1 - y0); return
    }
    if (s.tool === 'rect' || s.tool === 'cloud') {
      const b = bbox(s)
      let x0 = b.x, y0 = b.y, x1 = b.x + b.w, y1 = b.y + b.h
      if (handle === 'tl') { x0 = p.x; y0 = p.y } else if (handle === 'tr') { x1 = p.x; y0 = p.y }
      else if (handle === 'br') { x1 = p.x; y1 = p.y } else if (handle === 'bl') { x0 = p.x; y1 = p.y }
      s.x = Math.min(x0, x1); s.y = Math.min(y0, y1); s.w = Math.abs(x1 - x0); s.h = Math.abs(y1 - y0)
    }
  }

  // selected-shape style edits via toolbar
  const applyColor = (c) => {
    setColor(c)
    if (selId != null) setShapes(prev => prev.map(s => s.id === selId ? { ...s, color: c } : s))
  }
  const applyWidth = (w) => {
    setWidth(w)
    if (selId != null) setShapes(prev => prev.map(s => s.id === selId ? { ...s, width: w } : s))
  }
  const applyFontSize = (fs) => {
    setFontSize(fs)
    if (selId != null) setShapes(prev => prev.map(s =>
      (s.id === selId && (s.tool === 'text' || s.tool === 'callout' || s.tool === 'cloudtext' || s.tool === 'stamp')) ? { ...s, fontSize: fs } : s))
  }
  const deleteSelected = () => { if (selId != null) { setShapes(prev => prev.filter(s => s.id !== selId)); setSelId(null) } }

  // Turn a selected plain Text into a Callout by adding a leader (default
  // target below-left; the user can then drag the target handle).
  const addLeaderToText = () => {
    if (selId == null) return
    const ctx = canvasRef.current?.getContext('2d')
    setShapes(prev => prev.map(s => {
      if (s.id !== selId || s.tool !== 'text') return s
      const b = ctx ? textBox(ctx, s) : { w: 80, h: 20 }
      return { ...s, tool: 'callout', target: { x: s.x + 20, y: s.y + b.h + 70 } }
    }))
  }

  // record every shape change into the undo history (skip our own undo/redo)
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; prevShapesRef.current = shapes; return }
    if (skipHistRef.current) { skipHistRef.current = false; prevShapesRef.current = shapes; return }
    histRef.current.past.push(prevShapesRef.current)
    histRef.current.future = []
    prevShapesRef.current = shapes
    setHistTick(t => t + 1)
  }, [shapes])

  const undo = () => {
    const h = histRef.current
    if (!h.past.length) return
    const prev = h.past.pop()
    h.future.push(prevShapesRef.current)
    skipHistRef.current = true; prevShapesRef.current = prev
    setShapes(prev); setSelId(null); setEditor(null); setHistTick(t => t + 1)
  }
  const redo = () => {
    const h = histRef.current
    if (!h.future.length) return
    const next = h.future.pop()
    h.past.push(prevShapesRef.current)
    skipHistRef.current = true; prevShapesRef.current = next
    setShapes(next); setSelId(null); setEditor(null); setHistTick(t => t + 1)
  }
  const clearAll = () => { setShapes([]); setSelId(null) }

  // keyboard: Esc exits tool/editor; Delete removes selection
  useEffect(() => {
    const onKey = (e) => {
      const mod = e.ctrlKey || e.metaKey
      if (mod && (e.key === 'z' || e.key === 'Z')) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return }
      if (mod && (e.key === 'y' || e.key === 'Y')) { e.preventDefault(); redo(); return }
      if (e.key === 'Escape') { if (editor) setEditor(null); else if (calloutTargetRef.current) { calloutTargetRef.current = null; redraw() } else if (cloudTextPendingRef.current) { cloudTextPendingRef.current = null; redraw() } else if (interRef.current) { interRef.current = null; redraw() } else { setSelId(null); setTool('select') } }
      else if ((e.key === 'Delete' || e.key === 'Backspace') && !editor && selIdRef.current != null) { e.preventDefault(); deleteSelected() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [editor, selId])

  const handleSend = () => {
    setSelId(null); selIdRef.current = null
    commitEditor()
    setTimeout(() => {
      const c = canvasRef.current; if (!c) { onCancel(); return }
      redraw()
      c.toBlob((blob) => { if (!blob) { onCancel(); return } onSend(new File([blob], `annotated_${Date.now()}.png`, { type: 'image/png' })) }, 'image/png')
    }, 40)
  }

  // ---------- window drag / resize / fullscreen ----------
  const onHeaderDown = (e) => {
    if (full) return
    dragRef.current = { dx: e.clientX - pos.x, dy: e.clientY - pos.y }
    const move = (ev) => { if (dragRef.current) setPos({ x: Math.max(0, ev.clientX - dragRef.current.dx), y: Math.max(0, ev.clientY - dragRef.current.dy) }) }
    const up = () => { dragRef.current = null; window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
    window.addEventListener('mousemove', move); window.addEventListener('mouseup', up)
  }
  const onResizeDown = (e) => {
    e.stopPropagation()
    resizeRef.current = { sx: e.clientX, sy: e.clientY, w: size.w, h: size.h }
    const move = (ev) => {
      if (!resizeRef.current) return
      setSize({ w: Math.max(420, resizeRef.current.w + (ev.clientX - resizeRef.current.sx)), h: Math.max(360, resizeRef.current.h + (ev.clientY - resizeRef.current.sy)) })
    }
    const up = () => { resizeRef.current = null; window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
    window.addEventListener('mousemove', move); window.addEventListener('mouseup', up)
  }

  const winStyle = full
    ? { left: 0, top: 0, width: '100vw', height: '100vh' }
    : { left: pos.x, top: pos.y, width: size.w, height: size.h }

  const pct = Math.round((zoom / (fitRef.current || 1)) * 100)
  const selShape = shapes.find(s => s.id === selId)
  const editorFs = (selShape?.fontSize || fontSize) * zoom

  return (
    <div className="fixed z-[60] bg-white shadow-2xl border border-gray-300 flex flex-col select-none"
      style={{ ...winStyle, borderRadius: full ? 0 : 8 }}>

      {/* header */}
      <div onMouseDown={onHeaderDown}
        className="bg-gray-800 text-white px-3 py-2 flex items-center justify-between cursor-move flex-shrink-0"
        style={{ borderTopLeftRadius: full ? 0 : 8, borderTopRightRadius: full ? 0 : 8 }}>
        <span className="font-semibold text-sm">Annotate Screenshot</span>
        <div className="flex items-center gap-2">
          <button onClick={() => setFull(f => !f)} className="text-gray-300 hover:text-white text-sm" title="Fullscreen">{full ? '🗗' : '🗖'}</button>
          <button onClick={onCancel} className="text-gray-300 hover:text-white text-lg leading-none">✕</button>
        </div>
      </div>

      {/* toolbar */}
      <div className="px-2 py-2 border-b flex items-center gap-1.5 flex-wrap flex-shrink-0">
        {ANNOT_TOOLS.map(t => (
          <button key={t.id} onClick={() => { commitEditor(); calloutTargetRef.current = null; cloudTextPendingRef.current = null; setTool(t.id); if (t.id !== 'select') setSelId(null) }}
            className={`px-2 py-1 rounded text-xs ${tool === t.id ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}>{t.label}</button>
        ))}
        <span className="w-px h-5 bg-gray-300 mx-1" />
        {ANNOT_COLORS.map(c => (
          <button key={c} onClick={() => applyColor(c)}
            className={`w-5 h-5 rounded ${color === c ? 'ring-2 ring-offset-1 ring-gray-700' : ''}`} style={{ backgroundColor: c }} />
        ))}
        <span className="w-px h-5 bg-gray-300 mx-1" />
        <span className="text-[11px] text-gray-500">Line</span>
        <input type="range" min="1" max="12" value={width} onChange={e => applyWidth(parseInt(e.target.value))} className="w-16 accent-blue-600" />
        <span className="w-px h-5 bg-gray-300 mx-1" />
        <span className="text-[11px] text-gray-500">Text</span>
        <input type="range" min="12" max="80" value={selShape?.fontSize || fontSize} onChange={e => applyFontSize(parseInt(e.target.value))} className="w-16 accent-blue-600" />
        <span className="w-px h-5 bg-gray-300 mx-1" />
        <span className="text-[11px] text-gray-500">Zoom</span>
        <input type="range" min="20" max="400" value={pct}
          onChange={e => { userZoomedRef.current = true; setZoom((parseInt(e.target.value) / 100) * (fitRef.current || 1)) }} className="w-20 accent-blue-600" />
        <span className="text-[11px] text-gray-400 w-9">{pct}%</span>
        <button onClick={() => { userZoomedRef.current = false; fitToWindow() }} className="px-2 py-1 rounded text-xs bg-gray-100 hover:bg-gray-200 text-gray-700">⤢ Fit</button>
        <span className="w-px h-5 bg-gray-300 mx-1" />
        <button onClick={undo} disabled={histRef.current.past.length === 0}
          className={`px-2 py-1 rounded text-xs ${histRef.current.past.length === 0 ? 'bg-gray-50 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}>↶ Undo</button>
        <button onClick={redo} disabled={histRef.current.future.length === 0}
          className={`px-2 py-1 rounded text-xs ${histRef.current.future.length === 0 ? 'bg-gray-50 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}>↷ Redo</button>
        <button onClick={deleteSelected} disabled={selId == null}
          className={`px-2 py-1 rounded text-xs ${selId == null ? 'bg-gray-50 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}>🗑 Delete</button>
        <button onClick={clearAll} className="px-2 py-1 rounded text-xs bg-gray-100 hover:bg-gray-200 text-gray-700">Clear</button>
        {selShape?.tool === 'text' && (
          <button onClick={addLeaderToText} className="px-2 py-1 rounded text-xs bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200">+ leader</button>
        )}
        {tool === 'stamp' && (
          <>
            <span className="w-px h-5 bg-gray-300 mx-1" />
            {[{ k: 'check', l: '✓' }, { k: 'cross', l: '✗' }, { k: 'rev', l: 'Δ' }].map(o => (
              <button key={o.k} onClick={() => setStampKind(o.k)}
                className={`px-2 py-1 rounded text-xs ${stampKind === o.k ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}>{o.l}</button>
            ))}
            {stampKind === 'rev' && (
              <button onClick={() => { revNumRef.current = 1 }} className="px-2 py-1 rounded text-xs bg-gray-100 hover:bg-gray-200 text-gray-600" title="Reset Δ counter to 1">↺Δ</button>
            )}
          </>
        )}
      </div>

      {/* canvas scroll area */}
      <div ref={scrollRef} className="flex-1 overflow-auto bg-gray-100 relative"
        onWheel={e => {
          e.preventDefault()
          const c = canvasRef.current
          if (c) {
            const rect = c.getBoundingClientRect()
            const z0 = zoomRef.current || 1
            zoomAnchorRef.current = { ix: (e.clientX - rect.left) / z0, iy: (e.clientY - rect.top) / z0, clientX: e.clientX, clientY: e.clientY }
          }
          userZoomedRef.current = true
          setZoom(z => Math.max((fitRef.current || 1) * 0.2, Math.min((fitRef.current || 1) * 4, z - e.deltaY * 0.0015 * z)))
        }}>
        <div className="relative" style={{ width: imgLoaded ? natRef.current.w * zoom : 'auto', height: imgLoaded ? natRef.current.h * zoom : 'auto', margin: 'auto' }}>
          {imgLoaded ? (
            <canvas ref={canvasRef}
              onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp} onDoubleClick={onDbl}
              style={{ width: natRef.current.w * zoom, height: natRef.current.h * zoom, cursor: tool === 'select' ? 'default' : 'crosshair', background: '#fff', display: 'block' }} />
          ) : <p className="text-gray-500 p-8">Loading…</p>}

          {editor && (
            <textarea ref={editorInputRef} value={editor.text}
              onChange={e => setEditor(ed => ({ ...ed, text: e.target.value }))}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); commitEditor() } }}
              onBlur={commitEditor}
              className="absolute outline-none bg-white/90 border border-blue-500 px-1 py-0 resize-none"
              style={{ left: cssOf(editor.cx, editor.cy).left, top: cssOf(editor.cx, editor.cy).top, color, fontWeight: 'bold', fontSize: `${editorFs}px`, lineHeight: 1.2, minWidth: 60, minHeight: editorFs * 1.4 }} />
          )}
        </div>
      </div>

      {/* footer */}
      <div className="px-3 py-2 border-t flex justify-between items-center flex-shrink-0">
        <span className="text-[11px] text-gray-400">
          {tool === 'select' ? 'Click to select · drag to move · handles to resize · double-click text to edit · Del to remove'
            : tool === 'callout' ? 'Click the leader point, then click where the text goes'
            : tool === 'cloudtext' ? 'Drag to draw the cloud, then click where the text goes'
            : tool === 'stamp' ? 'Pick ✓ / ✗ / Δ, then click to place it'
            : tool === 'text' ? 'Click to place text, then type'
            : 'Esc to exit tool · scroll or slider to zoom · Ctrl+Z undo / Ctrl+Y redo'}
        </span>
        <div className="flex gap-2">
          <button onClick={onCancel} className="px-4 py-1.5 rounded bg-gray-200 hover:bg-gray-300 text-gray-700 text-sm">Cancel</button>
          <button onClick={handleSend} className="px-5 py-1.5 rounded bg-green-600 hover:bg-green-700 text-white text-sm font-medium">Send →</button>
        </div>
      </div>

      {/* resize handle */}
      {!full && (
        <div onMouseDown={onResizeDown}
          className="absolute bottom-0 right-0 w-4 h-4 cursor-nwse-resize"
          style={{ background: 'linear-gradient(135deg, transparent 50%, #9ca3af 50%)' }} />
      )}
    </div>
  )
}

export default function Viewer({
  files = [], projectName, projectId,
  folders = [], projectFiles = [], projectMembers = [],
  token, userEmail: userEmailProp, onClose, modelControls
}) {
  const userEmail = userEmailProp || emailFromToken(token)

  const modelList = Array.isArray(files) ? files : []
  const filesKey = modelList.map(m => m.id).join(',')
  const multi = modelList.length > 1

  const containerRef = useRef(null)
  const componentsRef = useRef(null)
  const fragsRef = useRef(null)
  const worldRef = useRef(null)
  const casterRef = useRef(null)
  const clipperRef = useRef(null)
  const screenshotRendererRef = useRef(null)   // reusable offscreen renderer for captures
  const chatEndRef = useRef(null)

  const modelIdToFileIdRef = useRef({})   // 'file-12' -> 12
  const loadedModelIdsRef = useRef(new Set())
  const baseChildrenRef = useRef([])      // grid/lights present before any model
  const syncRunningRef = useRef(false)
  const syncPendingRef = useRef(false)
  const filesRef = useRef(modelList)
  useEffect(() => { filesRef.current = modelList }, [filesKey])

  const fileIdOfModelId = (mId) => modelIdToFileIdRef.current[mId]
  const nameOfFile = (fid) =>
    (filesRef.current.find(m => m.id === fid)?.name) ||
    (projectFiles || []).find(f => f.id === fid)?.file_name || 'Model'

  const [worldReady, setWorldReady] = useState(false)
  const [firstSync, setFirstSync] = useState(false)
  const [modelStatus, setModelStatus] = useState({}) // fileId -> 'pending'|'ready'|'error'
  const [errorMsg, setErrorMsg] = useState('')

  const [selected, setSelected] = useState(null) // { name, ifcGuid, elementId, elementName, localId, modelId, fileId }
  const selectedRef = useRef(null)
  useEffect(() => { selectedRef.current = selected }, [selected])

  // whole-model selection (federated view, before entering any model)
  const [selectedModel, setSelectedModel] = useState(null) // { fileId, modelId, name }
  const selBoxRef = useRef(null)        // THREE.Box3Helper for the selected model
  const dimStateRef = useRef(new Map()) // mesh.uuid -> { mesh, original material }

  // which model is "entered" (active chat context). Default: the only model if
  // there is exactly one, otherwise none (project/folder context).
  const [activeFileId, setActiveFileId] = useState(modelList.length === 1 ? modelList[0].id : null)
  const activeFileIdRef = useRef(activeFileId)
  useEffect(() => { activeFileIdRef.current = activeFileId }, [activeFileId])

  const [activeTab, setActiveTab] = useState('chat') // chat | tasks
  const [sectionActive, setSectionActive] = useState(false)
  const [sectionPad, setSectionPad] = useState(0.6)
  const sectionBaseBoxRef = useRef(null)
  const [contextMenu, setContextMenu] = useState(null)
  const [clipMode, setClipMode] = useState(false)
  const clipModeRef = useRef(false)
  const [planesVisible, setPlanesVisible] = useState(true)
  const [showProps, setShowProps] = useState(false)
  const [props, setProps] = useState(null)
  const [loadingProps, setLoadingProps] = useState(false)
  useEffect(() => { clipModeRef.current = clipMode }, [clipMode])

  const [users, setUsers] = useState([])

  // ---------- chat (conversations) ----------
  const [conversations, setConversations] = useState([])
  const [selectedConv, setSelectedConv] = useState(null)
  const [convMessages, setConvMessages] = useState([])
  const [newConvMessage, setNewConvMessage] = useState('')
  // attachments: a pending file (capture / file / paste) waiting to be sent,
  // and a map messageId -> attachments for inline display.
  const [pendingFile, setPendingFile] = useState(null)        // File
  const [pendingPreview, setPendingPreview] = useState(null)  // object URL (image only)
  const [attByMsg, setAttByMsg] = useState({})
  const attByMsgRef = useRef({})
  useEffect(() => { attByMsgRef.current = attByMsg }, [attByMsg])
  const fileInputRef = useRef(null)
  const [captureMenuOpen, setCaptureMenuOpen] = useState(false)
  const [regionMode, setRegionMode] = useState(false)
  const [regionRect, setRegionRect] = useState(null)
  const regionStartRef = useRef(null)
  const regionRectRef = useRef(null)
  const [annotUrl, setAnnotUrl] = useState(null)   // object URL of a freshly captured shot
  const [showNewConvModal, setShowNewConvModal] = useState(false)
  const [ncType, setNcType] = useState('dm')
  const [ncName, setNcName] = useState('')
  const [ncMembers, setNcMembers] = useState([])
  const [ncLevel, setNcLevel] = useState(modelList.length === 1 ? 'model' : 'project')
  const [ncFolderId, setNcFolderId] = useState('')
  const [ncFileId, setNcFileId] = useState(modelList.length === 1 ? String(modelList[0].id) : '')

  // tasks
  const [tasks, setTasks] = useState([])
  const [showNewTask, setShowNewTask] = useState(false)
  const [newTaskDesc, setNewTaskDesc] = useState('')
  const [newTaskAssignee, setNewTaskAssignee] = useState('')

  const headers = { Authorization: `Bearer ${token}` }
  const pn = encodeURIComponent(projectName || '')

  // effective file id for new messages / tasks: the selected element's model,
  // else the active model. (Element links keep their own model regardless.)
  const effectiveFileId = () =>
    selectedRef.current?.fileId ?? activeFileIdRef.current ?? (modelList.length === 1 ? modelList[0].id : null)

  // ---------- data loaders ----------
  const loadUsers = async () => {
    if (!projectName) return
    try {
      const res = await axios.get(`${API}/users/${pn}`, { headers })
      setUsers(res.data)
    } catch {}
  }
  const loadTasks = async () => {
    if (!projectName) return
    try {
      const tfid = activeFileId ?? (modelList.length === 1 ? modelList[0].id : null)
      const url = tfid ? `${API}/tasks/${pn}?fileId=${tfid}` : `${API}/tasks/${pn}`
      const res = await axios.get(url, { headers })
      setTasks(res.data)
    } catch {}
  }
  const loadConversations = async () => {
    if (!projectId) return
    try {
      const res = await axios.get(`${API}/conversations?project_id=${projectId}`, { headers })
      setConversations(res.data)
    } catch {}
  }
  const loadConvMessages = async (id) => {
    try {
      const res = await axios.get(`${API}/conversations/${id}/messages`, { headers })
      setConvMessages(res.data)
    } catch {}
  }

  // poll the active tab
  useEffect(() => {
    if (!worldReady) return
    let iv = null
    if (activeTab === 'tasks') {
      loadUsers(); loadTasks(); iv = setInterval(loadTasks, 3000)
    } else if (activeTab === 'chat') {
      loadUsers(); loadConversations()
      if (selectedConv) {
        loadConvMessages(selectedConv.id)
        iv = setInterval(() => loadConvMessages(selectedConv.id), 3000)
      } else {
        iv = setInterval(loadConversations, 8000)
      }
    }
    return () => { if (iv) clearInterval(iv) }
  }, [worldReady, activeTab, selectedConv, projectId, activeFileId])

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [convMessages])
  useEffect(() => { if (convMessages.length) loadMissingAttachments(convMessages) }, [convMessages])
  useEffect(() => {
    if (!regionMode) return
    const onKey = (e) => { if (e.key === 'Escape') { setRegionMode(false); setRegionRect(null); regionStartRef.current = null } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [regionMode])

  // ---------- camera fit over all loaded models ----------
  const fitToLoaded = async () => {
    const world = worldRef.current
    const fragments = fragsRef.current
    if (!world || !fragments) return
    try {
      const box = new THREE.Box3()
      let any = false
      for (const [, model] of fragments.list) {
        if (model?.object) { box.expandByObject(model.object); any = true }
      }
      if (!any) return
      const center = new THREE.Vector3()
      const size = new THREE.Vector3()
      box.getCenter(center)
      box.getSize(size)
      const radius = Math.max(size.x, size.y, size.z) || 10
      const d = radius * 1.6
      await world.camera.controls.setLookAt(
        center.x + d, center.y + d, center.z + d,
        center.x, center.y, center.z, false
      )
      const sphere = new THREE.Sphere()
      box.getBoundingSphere(sphere)
      if (sphere.radius > 0) await world.camera.controls.fitToSphere(sphere, true)
    } catch (e) { console.warn('fit failed', e) }
  }

  // ---------- whole-model selection box (Revit-group style) ----------
  const clearModelBox = () => {
    const world = worldRef.current
    if (selBoxRef.current) {
      try { world?.scene.three.remove(selBoxRef.current) } catch {}
      try { selBoxRef.current.geometry?.dispose?.() } catch {}
      selBoxRef.current = null
    }
  }

  const showModelBox = (modelId) => {
    const world = worldRef.current
    const fragments = fragsRef.current
    if (!world || !fragments) return
    clearModelBox()
    const model = fragments.list.get(modelId)
    if (!model?.object) return
    try {
      const box = new THREE.Box3().setFromObject(model.object)
      if (box.isEmpty()) return
      const helper = new THREE.Box3Helper(box, new THREE.Color('#3b82f6'))
      helper.userData.__bimchatKeep = true   // don't let the ghost-cleaner remove it
      world.scene.three.add(helper)
      selBoxRef.current = helper
    } catch (e) { console.warn('model box failed', e) }
  }

  // ---------- dim non-active models (ghosting) ----------
  // Clones each affected mesh's material so dimming one model never bleeds into
  // another (That Open can share materials). Restored on un-dim.
  const setModelDimmed = (modelId, dim) => {
    const model = fragsRef.current?.list.get(modelId)
    if (!model?.object) return
    model.object.traverse(o => {
      if (!o.isMesh) return
      if (dim) {
        if (dimStateRef.current.has(o.uuid)) return
        const orig = o.material
        const arr = Array.isArray(orig) ? orig : [orig]
        const clones = arr.map(m => {
          const c = m.clone()
          c.transparent = true
          c.opacity = 0.8
          c.depthWrite = false
          return c
        })
        dimStateRef.current.set(o.uuid, { mesh: o, original: orig })
        o.material = Array.isArray(orig) ? clones : clones[0]
      } else {
        const saved = dimStateRef.current.get(o.uuid)
        if (!saved) return
        const cur = o.material
        const curArr = Array.isArray(cur) ? cur : [cur]
        o.material = saved.original
        curArr.forEach(c => { try { c.dispose?.() } catch {} })
        dimStateRef.current.delete(o.uuid)
      }
    })
  }

  const applyDim = (activeFid) => {
    const fragments = fragsRef.current
    if (!fragments) return
    for (const [modelId] of fragments.list) {
      const fid = modelIdToFileIdRef.current[modelId]
      setModelDimmed(modelId, activeFid != null && fid !== activeFid)
    }
    try { fragments.core.update(true) } catch {}
  }

  // when the active model changes, reset selection, redraw the box, re-dim
  useEffect(() => {
    if (!worldReady) return
    clearModelBox()
    setSelectedModel(null)
    setSelected(null)
    ;(async () => {
      try { await fragsRef.current?.resetHighlight() } catch {}
      applyDim(activeFileId)
      try { await fragsRef.current?.core.update(true) } catch {}
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeFileId, worldReady])

  // ===================================================================
  // EFFECT A — build the 3D world ONCE (no model loading here)
  // ===================================================================
  useEffect(() => {
    if (!containerRef.current) return
    let disposed = false

    const build = async () => {
      try {
        const components = new OBC.Components()
        componentsRef.current = components

        const worlds = components.get(OBC.Worlds)
        const world = worlds.create()
        world.scene = new OBC.SimpleScene(components)
        world.renderer = new OBC.SimpleRenderer(components, containerRef.current, { preserveDrawingBuffer: true })
        world.camera = new OBC.OrthoPerspectiveCamera(components)

        // Mouse like Revit: middle = pan, wheel = zoom
        try {
          const ctrls = world.camera.controls
          ctrls.mouseButtons.left = 1
          ctrls.mouseButtons.middle = 2
          ctrls.mouseButtons.right = 0
          ctrls.mouseButtons.wheel = 16
        } catch {}

        components.init()
        world.scene.setup()
        world.scene.three.background = null

        const grids = components.get(OBC.Grids)
        grids.create(world)

        // snapshot the "furniture" (grid, lights) so we can detect stray model
        // meshes later and clear ghosts on removal
        baseChildrenRef.current = [...world.scene.three.children]

        setTimeout(() => {
          try {
            containerRef.current?.querySelectorAll('[data-thatopen-logo]')
              .forEach(el => el.remove())
          } catch {}
        }, 0)

        const workerUrl = await OBC.FragmentsManager.getWorker()
        const fragments = components.get(OBC.FragmentsManager)
        fragments.init(workerUrl)
        fragsRef.current = fragments
        worldRef.current = world

        world.camera.controls.addEventListener('update', () => fragments.core.update())
        world.onCameraChanged.add((camera) => {
          for (const [, model] of fragments.list) model.useCamera(camera.three)
          fragments.core.update(true)
        })
        // add a model to the scene as soon as it is loaded
        fragments.list.onItemSet.add(({ value: model }) => {
          model.useCamera(world.camera.three)
          world.scene.three.add(model.object)
          fragments.core.update(true)
        })
        // remove a model's object from the scene when it is disposed
        fragments.list.onItemDeleted.add((ev) => {
          try {
            const obj = ev?.value?.object
            if (obj) world.scene.three.remove(obj)
          } catch {}
        })
        fragments.core.models.materials.list.onItemSet.add(({ value: material }) => {
          if (!('isLodMaterial' in material && material.isLodMaterial)) {
            material.polygonOffset = true
            material.polygonOffsetUnits = 1
            material.polygonOffsetFactor = Math.random()
          }
        })

        // raycaster + element selection (does NOT change active model)
        const casters = components.get(OBC.Raycasters)
        const caster = casters.get(world)
        casterRef.current = caster
        const highlightColor = new THREE.Color('#3b82f6')

        const onClick = async () => {
          if (clipModeRef.current) {
            try {
              const plane = clipperRef.current?.create(world)
              try {
                const ctrls = plane?.controls || plane?._controls
                if (ctrls) {
                  if (typeof ctrls.setSize === 'function') ctrls.setSize(0.4)
                  else ctrls.size = 0.4
                }
              } catch {}
              await fragsRef.current?.core.update(true)
            } catch (e) { console.warn('clip create failed:', e) }
            setClipMode(false)
            return
          }
          try {
            const result = await caster.castRay()
            const activeFid = activeFileIdRef.current

            // empty space -> clear element + whole-model selection
            if (!result) {
              await fragments.resetHighlight()
              await fragments.core.update(true)
              setSelected(null)
              setSelectedModel(null)
              clearModelBox()
              return
            }

            const mId = result.fragments.modelId
            const localId = result.localId
            const model = fragments.list.get(mId)
            if (!model) return
            const clickedFileId = fileIdOfModelId(mId)

            // CASE 1 — no model entered: select the WHOLE clicked model (Revit-group style)
            if (activeFid == null) {
              await fragments.resetHighlight()
              await fragments.core.update(true)
              setSelected(null)
              setSelectedModel({ fileId: clickedFileId, modelId: mId, name: nameOfFile(clickedFileId) })
              showModelBox(mId)
              return
            }

            // CASE 2 — inside a model: ignore clicks on OTHER models
            if (clickedFileId !== activeFid) return

            // CASE 3 — element selection within the active model
            let ifcGuid = null
            try {
              const guids = await model.getGuidsByLocalIds([localId])
              ifcGuid = guids && guids[0] ? guids[0] : null
            } catch {}

            let name = ''
            try {
              const [data] = await model.getItemsData([localId])
              if (data && data.Name && 'value' in data.Name) name = data.Name.value
            } catch {}

            let elementId = -1
            let elementName = name
            if (ifcGuid && clickedFileId != null) {
              try {
                const r = await axios.get(`${API}/element-mapping/${clickedFileId}/resolve`,
                  { params: { guid: ifcGuid }, headers })
                if (r.data.found) { elementId = r.data.elementId; elementName = r.data.elementName || name }
              } catch {}
            }

            const modelIdMap = { [mId]: new Set([localId]) }
            await fragments.resetHighlight()
            await fragments.highlight(
              { color: highlightColor, renderedFaces: FRAGS.RenderedFaces.TWO, opacity: 1, transparent: false },
              modelIdMap
            )
            await fragments.core.update(true)

            setSelected({
              name: name || elementName || '(no name)',
              ifcGuid, elementId, elementName, localId, modelId: mId, fileId: clickedFileId
            })
          } catch (e) { console.error('select error:', e) }
        }
        containerRef.current.addEventListener('click', onClick)

        // double-click = explicit model enter/exit
        const onDblClick = async () => {
          if (clipModeRef.current) return
          try {
            const result = await caster.castRay()
            if (result) {
              const fid = fileIdOfModelId(result.fragments.modelId)
              if (fid != null) setActiveFileId(fid)            // enter that model
            } else if (filesRef.current.length > 1) {
              setActiveFileId(null)                            // exit to project/folder
            }
          } catch {}
        }
        containerRef.current.addEventListener('dblclick', onDblClick)

        const onContextMenu = async (ev) => {
          ev.preventDefault()
          if (!clipModeRef.current) await onClick()
          setContextMenu({ x: ev.clientX, y: ev.clientY })
        }
        containerRef.current.addEventListener('contextmenu', onContextMenu)

        const clipper = components.get(OBC.Clipper)
        clipper.enabled = true
        try {
          clipper.config.visible = true
          clipper.config.opacity = 0.25
          clipper.config.size = 5
          clipper.config.color = new THREE.Color('#3b82f6')
        } catch {}
        clipperRef.current = clipper

        components._onClick = onClick
        components._onDblClick = onDblClick
        components._onContextMenu = onContextMenu
        components._container = containerRef.current

        if (!disposed) setWorldReady(true)
      } catch (err) {
        console.error('World build error:', err)
        if (!disposed) { setErrorMsg(err.message || 'Failed to start 3D.'); setWorldReady(true); setFirstSync(true) }
      }
    }

    build()
    return () => {
      disposed = true
      try {
        const c = componentsRef.current
        if (c && c._container) {
          if (c._onClick) c._container.removeEventListener('click', c._onClick)
          if (c._onDblClick) c._container.removeEventListener('dblclick', c._onDblClick)
          if (c._onContextMenu) c._container.removeEventListener('contextmenu', c._onContextMenu)
        }
        c?.dispose?.()
      } catch {}
      try { screenshotRendererRef.current?.dispose?.(); screenshotRendererRef.current = null } catch {}
      componentsRef.current = null
      loadedModelIdsRef.current = new Set()
      modelIdToFileIdRef.current = {}
    }
  }, [])

  // ===================================================================
  // EFFECT B — sync loaded models with `files` (live add / remove)
  // ===================================================================
  useEffect(() => {
    if (!worldReady) return
    let cancelled = false
    let retry = null

    // Remove any mesh left in the scene that is NOT base furniture and NOT
    // backed by a currently-loaded model (kills "ghost" leftovers after dispose).
    const clearStrayObjects = () => {
      const world = worldRef.current
      const fragments = fragsRef.current
      if (!world || !fragments) return
      const base = new Set(baseChildrenRef.current)
      const keep = new Set()
      for (const [, model] of fragments.list) { if (model?.object) keep.add(model.object) }
      for (const child of [...world.scene.three.children]) {
        if (base.has(child) || keep.has(child) || child.userData?.__bimchatKeep) continue
        try {
          world.scene.three.remove(child)
          child.traverse?.(o => { try { o.geometry?.dispose?.() } catch {} })
        } catch {}
      }
    }

    const sync = async () => {
      // serialize: never run two syncs at once (fast toggling caused ghosts)
      if (syncRunningRef.current) { syncPendingRef.current = true; return }
      syncRunningRef.current = true
      try {
        const fragments = fragsRef.current
        const world = worldRef.current
        if (!fragments || !world) return

        const want = filesRef.current               // latest list (not stale closure)
        const desired = new Set(want.map(f => `file-${f.id}`))
        const loaded = loadedModelIdsRef.current

        // remove models no longer desired
        for (const modelId of [...loaded]) {
          if (!desired.has(modelId)) {
            try {
              const m = fragments.list.get(modelId)
              if (m?.object) world.scene.three.remove(m.object)
              await fragments.core.disposeModel(modelId)
            } catch (e) { console.warn('dispose failed', modelId, e) }
            loaded.delete(modelId)
            delete modelIdToFileIdRef.current[modelId]
          }
        }

        const wasEmpty = loaded.size === 0
        let addedAny = false
        let anyPending = false
        const statusUpdates = {}

        for (const f of want) {
          const modelId = `file-${f.id}`
          if (loaded.has(modelId)) { statusUpdates[f.id] = 'ready'; continue }
          try {
            const st = await axios.get(`${API}/web-export/${f.id}/status`, { headers })
            if (cancelled) return
            if (!(st.data.status === 'ready' && st.data.hasFrag)) {
              statusUpdates[f.id] = st.data.status === 'error' ? 'error' : 'pending'
              if (st.data.status !== 'error') anyPending = true
              continue
            }
            const urlRes = await axios.get(`${API}/web-export/${f.id}/frag-url`, { headers })
            const fragUrl = urlRes.data.downloadUrl
            if (!fragUrl) { statusUpdates[f.id] = 'error'; continue }
            const resp = await fetch(fragUrl)
            if (!resp.ok) { statusUpdates[f.id] = 'error'; continue }
            const buffer = await resp.arrayBuffer()
            if (cancelled) return
            await fragments.core.load(buffer, { modelId })
            loaded.add(modelId)
            modelIdToFileIdRef.current[modelId] = f.id
            statusUpdates[f.id] = 'ready'
            addedAny = true
          } catch (e) {
            console.warn('load failed', f.id, e)
            statusUpdates[f.id] = 'error'
          }
        }

        if (cancelled) return
        clearStrayObjects()                     // wipe any ghost meshes
        await fragments.core.update(true)
        applyDim(activeFileIdRef.current)        // keep non-active models ghosted
        // freshly-loaded models stream their meshes in slightly later — re-dim
        setTimeout(() => { if (!cancelled) applyDim(activeFileIdRef.current) }, 400)
        setModelStatus(prev => ({ ...prev, ...statusUpdates }))

        if (wasEmpty && addedAny) await fitToLoaded()
        setFirstSync(true)

        if (anyPending && !cancelled) retry = setTimeout(sync, 4000)
      } finally {
        syncRunningRef.current = false
        // if files changed while we were busy, run once more with the latest list
        if (syncPendingRef.current && !cancelled) { syncPendingRef.current = false; sync() }
      }
    }

    sync()
    return () => { cancelled = true; if (retry) clearTimeout(retry) }
  }, [worldReady, filesKey])

  // keep active model valid as `files` changes
  const prevCountRef = useRef(modelList.length)
  useEffect(() => {
    const ids = modelList.map(f => f.id)
    const prevCount = prevCountRef.current
    setActiveFileId(prev => {
      // the active model was removed
      if (prev != null && !ids.includes(prev)) return ids.length === 1 ? ids[0] : null
      // a single model auto-enters
      if (prev == null && ids.length === 1) return ids[0]
      // grew from one model to several -> drop back to federated view
      if (prev != null && prevCount <= 1 && ids.length > 1) return null
      return prev
    })
    prevCountRef.current = ids.length
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filesKey])

  // ---------- focus an element from a stored link (element_id + file_id) ----------
  const focusElement = async (elementId, linkFileId) => {
    if (!elementId || elementId === -1) return
    const fragments = fragsRef.current
    if (!fragments) return
    const fid = linkFileId ?? activeFileIdRef.current ?? (modelList.length === 1 ? modelList[0].id : null)
    if (!fid) return
    const modelId = `file-${fid}`
    const model = fragments.list.get(modelId)
    if (!model) { alert('That model is not in the scene. Add it from the list first.'); return }

    let ifcGuid = null
    let resolvedName = ''
    try {
      const r = await axios.get(`${API}/element-mapping/${fid}/by-element`,
        { params: { elementId }, headers })
      if (r.data.found) { ifcGuid = r.data.ifcGuid; resolvedName = r.data.elementName || '' }
    } catch {}
    if (!ifcGuid) return

    let localIds = []
    try { localIds = await model.getLocalIdsByGuids([ifcGuid]) } catch {}
    const localId = localIds && localIds.length ? localIds[0] : null
    if (localId === null || localId === undefined) return

    const modelIdMap = { [modelId]: new Set([localId]) }
    try {
      await fragments.resetHighlight()
      await fragments.highlight(
        { color: new THREE.Color('#3b82f6'), renderedFaces: FRAGS.RenderedFaces.TWO, opacity: 1, transparent: false },
        modelIdMap
      )
      await fragments.core.update(true)
    } catch {}

    setSelected({ name: resolvedName || '(no name)', ifcGuid, elementId, elementName: resolvedName, localId, modelId, fileId: fid })
    await sectionBoxForLocalId(localId, modelId)
  }

  // ---------- section box ----------
  const applyClippingFromBox = async (baseBox, pad, doFit) => {
    const world = worldRef.current
    if (!baseBox || !world) return
    const box = baseBox.clone().expandByScalar(pad)
    const renderer = world.renderer.three
    renderer.localClippingEnabled = true
    const min = box.min, max = box.max
    renderer.clippingPlanes = [
      new THREE.Plane(new THREE.Vector3(1, 0, 0), -min.x),
      new THREE.Plane(new THREE.Vector3(-1, 0, 0), max.x),
      new THREE.Plane(new THREE.Vector3(0, 1, 0), -min.y),
      new THREE.Plane(new THREE.Vector3(0, -1, 0), max.y),
      new THREE.Plane(new THREE.Vector3(0, 0, 1), -min.z),
      new THREE.Plane(new THREE.Vector3(0, 0, -1), max.z),
    ]
    await fragsRef.current?.core.update(true)
    if (doFit) {
      try {
        const sphere = new THREE.Sphere()
        box.getBoundingSphere(sphere)
        if (sphere.radius > 0) await world.camera.controls.fitToSphere(sphere, true)
      } catch {}
    }
  }

  const sectionBoxForLocalId = async (localId, modelId) => {
    if (localId == null) return
    const mId = modelId || selectedRef.current?.modelId
    if (!mId) return
    try {
      const modelIdMap = { [mId]: new Set([localId]) }
      const boxer = componentsRef.current.get(OBC.BoundingBoxer)
      boxer.list.clear()
      await boxer.addFromModelIdMap(modelIdMap)
      const box = boxer.get()
      boxer.list.clear()
      if (!box) return
      sectionBaseBoxRef.current = box.clone()
      await applyClippingFromBox(box, sectionPad, true)
      setSectionActive(true)
    } catch (e) { console.warn('section box failed:', e) }
  }

  const onSectionPadChange = async (val) => {
    setSectionPad(val)
    if (sectionActive && sectionBaseBoxRef.current) {
      await applyClippingFromBox(sectionBaseBoxRef.current, val, false)
    }
  }

  const applySectionBox = async () => {
    const sel = selectedRef.current
    if (!sel || sel.localId == null) return
    await sectionBoxForLocalId(sel.localId, sel.modelId)
  }

  const clearSectionBox = async () => {
    const world = worldRef.current
    if (!world) return
    try {
      world.renderer.three.clippingPlanes = []
      await fragsRef.current?.core.update(true)
    } catch {}
    sectionBaseBoxRef.current = null
    setSectionActive(false)
  }

  // ---------- hide / isolate ----------
  const hideSelected = async () => {
    const sel = selectedRef.current
    if (!sel || sel.localId == null) return
    try {
      const hider = componentsRef.current.get(OBC.Hider)
      await hider.set(false, { [sel.modelId]: new Set([sel.localId]) })
      await fragsRef.current?.core.update(true)
    } catch (e) { console.warn('hide failed:', e) }
    setContextMenu(null)
  }

  const isolateSelected = async () => {
    const sel = selectedRef.current
    if (!sel || sel.localId == null) return
    try {
      const hider = componentsRef.current.get(OBC.Hider)
      await hider.isolate({ [sel.modelId]: new Set([sel.localId]) })
      await fragsRef.current?.core.update(true)
    } catch (e) { console.warn('isolate failed:', e) }
    setContextMenu(null)
  }

  const showAll = async () => {
    try {
      const hider = componentsRef.current.get(OBC.Hider)
      await hider.set(true)
      await fragsRef.current?.core.update(true)
    } catch (e) { console.warn('show all failed:', e) }
    setContextMenu(null)
  }

  // ---------- manual clipping planes ----------
  const toggleClipMode = () => setClipMode(prev => !prev)
  const deleteAllClips = () => { try { clipperRef.current?.deleteAll() } catch {} }
  const deleteClipHere = async () => {
    try {
      clipperRef.current?.delete(worldRef.current)
      await fragsRef.current?.core.update(true)
    } catch (e) { console.warn('clip delete failed:', e) }
    setContextMenu(null)
  }
  const togglePlanesVisible = () => {
    const clipper = clipperRef.current
    if (!clipper) return
    const next = !planesVisible
    try {
      clipper.config.visible = next
      for (const [, plane] of clipper.list) {
        try {
          if ('visible' in plane) plane.visible = next
          const ctrls = plane.controls || plane._controls
          if (ctrls) ctrls.visible = next
          if (plane.helper) plane.helper.visible = next
        } catch {}
      }
      worldRef.current?.renderer?.three && fragsRef.current?.core.update(true)
    } catch {}
    setPlanesVisible(next)
  }

  // ---------- chat actions ----------
  const clearPending = () => {
    if (pendingPreview) { try { URL.revokeObjectURL(pendingPreview) } catch {} }
    setPendingFile(null); setPendingPreview(null)
  }

  const openConversation = (conv) => {
    setSelectedConv(conv)
    setAttByMsg({}); attByMsgRef.current = {}
    clearPending()
    loadConvMessages(conv.id)
  }

  // capture the current 3D view as a PNG and stage it for sending
  // The model's WebGL canvas has a large backing buffer. A stray/secondary
  // canvas (default 300x150) was being read instead, so the capture only got
  // the top-left 300x150 region. Scan the WHOLE document and pick the canvas
  // with the largest backing buffer — that's the real 3D viewport.
  const getGLCanvas = () => {
    const rendererCanvas = worldRef.current?.renderer?.three?.domElement || null
    let best = rendererCanvas
    let bestArea = best ? best.width * best.height : 0
    for (const c of document.querySelectorAll('canvas')) {
      const area = c.width * c.height
      if (area > bestArea) { best = c; bestArea = area }
    }
    return best
  }

  // top-left) limits it to a region; null = full view.
  const grabCanvasFile = async (crop) => {
    const world = worldRef.current
    const container = containerRef.current
    if (!world || !container) return null
    const canvas = getGLCanvas()
    if (!canvas) { alert('3D canvas not ready.'); return null }

    // Read the exact frame that's on screen RIGHT NOW — synchronously, before
    // any await/render. preserveDrawingBuffer keeps the displayed frame, so this
    // matches the screen (the same way the chat screenshot worked).
    let outCanvas = canvas
    if (crop && crop.w > 4 && crop.h > 4) {
      const rect = canvas.getBoundingClientRect()
      const sx = canvas.width / rect.width
      const sy = canvas.height / rect.height
      let srcX = Math.round(crop.x * sx), srcY = Math.round(crop.y * sy)
      let srcW = Math.round(crop.w * sx), srcH = Math.round(crop.h * sy)
      srcX = Math.max(0, Math.min(srcX, canvas.width - 1))
      srcY = Math.max(0, Math.min(srcY, canvas.height - 1))
      srcW = Math.max(1, Math.min(srcW, canvas.width - srcX))
      srcH = Math.max(1, Math.min(srcH, canvas.height - srcY))
      const c = document.createElement('canvas')
      c.width = srcW; c.height = srcH
      c.getContext('2d').drawImage(canvas, srcX, srcY, srcW, srcH, 0, 0, srcW, srcH)
      outCanvas = c
    }

    try {
      const dataUrl = outCanvas.toDataURL('image/png')
      const blob = await (await fetch(dataUrl)).blob()
      return new File([blob], `screenshot_${Date.now()}.png`, { type: 'image/png' })
    } catch (e) { alert('Capture failed: ' + e.message); return null }
  }

  const stagePending = (file) => {
    if (!file) return
    clearPending()
    setPendingFile(file)
    setPendingPreview(URL.createObjectURL(file))
  }

  // open the annotate modal with a freshly captured shot
  const openAnnot = (file) => {
    if (!file) return
    if (annotUrl) { try { URL.revokeObjectURL(annotUrl) } catch {} }
    setAnnotUrl(URL.createObjectURL(file))
  }
  const closeAnnot = () => {
    if (annotUrl) { try { URL.revokeObjectURL(annotUrl) } catch {} }
    setAnnotUrl(null)
  }

  const captureActiveView = async () => {
    setCaptureMenuOpen(false)
    openAnnot(await grabCanvasFile(null))
  }

  const startRegionCapture = () => {
    setCaptureMenuOpen(false)
    setRegionRect(null)
    regionStartRef.current = null
    setRegionMode(true)
  }

  const onRegionMouseDown = (e) => {
    const canvas = getGLCanvas()
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    regionStartRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top }
    const r0 = { x: regionStartRef.current.x, y: regionStartRef.current.y, w: 0, h: 0 }
    regionRectRef.current = r0
    setRegionRect(r0)
  }
  const onRegionMouseMove = (e) => {
    if (!regionStartRef.current) return
    const canvas = getGLCanvas()
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const cx = e.clientX - rect.left, cy = e.clientY - rect.top
    const s = regionStartRef.current
    const r = { x: Math.min(s.x, cx), y: Math.min(s.y, cy), w: Math.abs(cx - s.x), h: Math.abs(cy - s.y) }
    regionRectRef.current = r
    setRegionRect(r)
  }
  const onRegionMouseUp = async () => {
    const r = regionRectRef.current   // read the latest rect (state can lag)
    setRegionMode(false)
    regionStartRef.current = null
    regionRectRef.current = null
    setRegionRect(null)
    if (r && r.w > 4 && r.h > 4) openAnnot(await grabCanvasFile(r))
  }

  const onPickFile = (e) => {
    const f = e.target.files && e.target.files[0]
    if (!f) return
    if (f.size > 10 * 1024 * 1024) { alert('File too large (max 10 MB)'); e.target.value = ''; return }
    clearPending()
    setPendingFile(f)
    if (f.type.startsWith('image/')) setPendingPreview(URL.createObjectURL(f))
    e.target.value = ''
  }

  const onPasteInput = (e) => {
    const items = e.clipboardData?.items
    if (!items) return
    for (const it of items) {
      if (it.type && it.type.startsWith('image/')) {
        const blob = it.getAsFile()
        if (blob) {
          const file = new File([blob], `paste_${Date.now()}.png`, { type: blob.type || 'image/png' })
          clearPending()
          setPendingFile(file)
          setPendingPreview(URL.createObjectURL(file))
          e.preventDefault()
        }
        break
      }
    }
  }

  const isImageAtt = (att) =>
    att.resource_type === 'image' ||
    (att.file_type && att.file_type.startsWith('image/')) ||
    /\.(png|jpe?g|gif|webp)$/i.test(att.file_name || '') ||
    /\.(png|jpe?g|gif|webp)(\?|$)/i.test(att.file_url || '') ||
    /\/image\/upload\//.test(att.file_url || '')

  const loadMissingAttachments = async (messages) => {
    const have = attByMsgRef.current
    const missing = messages.filter(m => !(m.id in have))
    if (missing.length === 0) return
    const updates = {}
    await Promise.all(missing.map(async (m) => {
      try {
        const r = await axios.get(`${API}/attachments/message/${m.id}`, { headers })
        updates[m.id] = r.data || []
      } catch { updates[m.id] = [] }
    }))
    setAttByMsg(prev => ({ ...prev, ...updates }))
  }

  const sendConvMessage = async () => {
    if ((!newConvMessage.trim() && !pendingFile) || !selectedConv) return
    const sel = selectedRef.current
    try {
      const msgText = newConvMessage.trim() ||
        (pendingFile ? `📷 ${pendingFile.name}` : '')
      const res = await axios.post(`${API}/conversations/${selectedConv.id}/messages`, {
        message: msgText,
        element_id: sel?.elementId ?? -1,
        element_name: sel?.elementName ?? null,
        file_id: effectiveFileId()
      }, { headers })

      const messageId = res.data.id
      if (pendingFile && messageId) {
        const fd = new FormData()
        fd.append('file', pendingFile)
        fd.append('message_id', messageId)
        await axios.post(`${API}/attachments/upload`, fd, { headers: { Authorization: `Bearer ${token}` } })
        // Fetch this message's attachments directly so it shows immediately
        // (don't rely on the list-reload effect, which can race the DB write).
        try {
          const ar = await axios.get(`${API}/attachments/message/${messageId}`, { headers })
          setAttByMsg(prev => ({ ...prev, [messageId]: ar.data || [] }))
        } catch {}
      }

      setNewConvMessage('')
      clearPending()
      loadConvMessages(selectedConv.id)
    } catch (err) { alert('Send failed: ' + (err.response?.data?.error || err.message)) }
  }

  const leaveConversation = async () => {
    if (!selectedConv) return
    if (!confirm('Leave this conversation?')) return
    try {
      await axios.delete(`${API}/conversations/${selectedConv.id}/members/${encodeURIComponent(userEmail)}`, { headers })
      setSelectedConv(null); setConvMessages([])
      setAttByMsg({}); attByMsgRef.current = {}; clearPending()
      loadConversations()
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  const convertMessageToTask = async (m) => {
    if (!confirm('Create a task from this message?')) return
    try {
      await axios.post(`${API}/tasks/from-message`, { message_id: m.id }, { headers })
      loadTasks()
      alert('Task created.')
    } catch (err) { alert('Failed: ' + (err.response?.data?.error || err.message)) }
  }

  const closeNewConvModal = () => {
    setShowNewConvModal(false)
    setNcType('dm'); setNcName(''); setNcMembers([])
    setNcLevel(modelList.length === 1 ? 'model' : 'project'); setNcFolderId('')
    setNcFileId(modelList.length === 1 ? String(modelList[0].id) : '')
  }

  const createConversation = async () => {
    if (ncType === 'group' && !ncName.trim()) { alert('Group name is required'); return }
    if (ncMembers.length === 0) { alert('Select at least one member'); return }
    if (ncType === 'dm' && ncMembers.length !== 1) { alert('A DM needs exactly one other person'); return }
    if (ncLevel === 'folder' && !ncFolderId) { alert('Select a folder'); return }
    if (ncLevel === 'model' && !ncFileId) { alert('Select a model'); return }

    const body = { project_id: projectId, type: ncType, level: ncLevel, members: ncMembers }
    if (ncType === 'group') body.name = ncName.trim()
    if (ncLevel === 'folder') body.folder_id = parseInt(ncFolderId)
    if (ncLevel === 'model') body.file_id = parseInt(ncFileId)

    try {
      const res = await axios.post(`${API}/conversations`, body, { headers })
      closeNewConvModal()
      const newId = res.data.conversation_id
      const list = (await axios.get(`${API}/conversations?project_id=${projectId}`, { headers })).data
      setConversations(list)
      const conv = list.find(c => c.id === newId)
      if (conv) openConversation(conv)
    } catch (err) {
      alert('Failed: ' + (err.response?.data?.error || err.message))
    }
  }

  // ---------- task actions ----------
  const createTask = async () => {
    if (!newTaskDesc.trim() || !projectName) return
    const sel = selectedRef.current
    try {
      await axios.post(`${API}/tasks`, {
        id: crypto.randomUUID(),
        project_name: projectName,
        description: newTaskDesc,
        assignee: newTaskAssignee || '',
        created_by: userEmail || '',
        element_id: sel?.elementId ?? -1,
        element_name: sel?.elementName ?? '',
        view_name: '',
        status: 'Open',
        file_id: effectiveFileId()
      }, { headers })
      setNewTaskDesc(''); setNewTaskAssignee(''); setShowNewTask(false)
      loadTasks()
    } catch (err) { alert('Create failed: ' + (err.response?.data?.error || err.message)) }
  }

  const updateTaskStatus = async (taskId, status) => {
    try {
      await axios.put(`${API}/tasks/${taskId}`, { status }, { headers })
      loadTasks()
    } catch (err) { alert('Update failed: ' + (err.response?.data?.error || err.message)) }
  }

  const statusColor = (s) =>
    s === 'Open' ? '#E74C3C' : s === 'InProgress' ? '#F39C12' : '#27AE60'

  useEffect(() => {
    if (showProps && selected && selected.localId != null) loadProperties()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.localId, selected?.ifcGuid])

  // ---------- properties ----------
  const asArray = (x) => Array.isArray(x) ? x : (x ? [x] : [])
  const attrVal = (a) => (a && typeof a === 'object' && 'value' in a) ? a.value : a
  const fmtVal = (v) => {
    if (v === null || v === undefined || v === '') return '—'
    if (typeof v === 'boolean') return v ? 'Yes' : 'No'
    if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(3)
    return String(v)
  }
  const parseItemData = (data) => {
    const attributes = []
    const psets = []
    if (!data) return { attributes, psets }
    for (const key of Object.keys(data)) {
      if (key === 'IsDefinedBy' || key === 'DefinesOcurrence') continue
      const val = data[key]
      if (val && typeof val === 'object' && 'value' in val && !Array.isArray(val)) {
        attributes.push({ name: key, value: fmtVal(val.value) })
      }
    }
    for (const rel of asArray(data.IsDefinedBy)) {
      for (const pset of asArray(rel?.RelatingPropertyDefinition || rel)) {
        const psetName = attrVal(pset?.Name) || 'Property Set'
        const list = []
        for (const p of asArray(pset?.HasProperties)) {
          const pname = attrVal(p?.Name)
          const pval = attrVal(p?.NominalValue)
          if (pname != null) list.push({ name: String(pname), value: fmtVal(pval) })
        }
        if (list.length) psets.push({ name: String(psetName), props: list })
      }
    }
    return { attributes, psets }
  }
  const loadProperties = async () => {
    const sel = selectedRef.current
    if (!sel || sel.localId == null) return
    const model = fragsRef.current?.list.get(sel.modelId)
    if (!model) return
    setShowProps(true); setLoadingProps(true); setProps(null)
    try {
      const [data] = await model.getItemsData([sel.localId], {
        attributesDefault: true,
        relations: {
          IsDefinedBy: { attributes: true, relations: true },
          DefinesOcurrence: { attributes: false, relations: false },
        },
      })
      setProps(parseItemData(data))
    } catch (e) {
      console.warn('properties failed:', e)
      setProps({ attributes: [], psets: [] })
    }
    setLoadingProps(false)
  }

  // ---------- conversation display helpers ----------
  const memberName = (email) => {
    const m = (projectMembers || []).find(x => x.user_email === email)
    if (m?.full_name) return m.full_name
    const u = users.find(x => x.email === email)
    return u?.full_name || email
  }
  const normLevel = (conv) => (LEVEL_META[conv.level] ? conv.level : 'project')
  const convTitle = (conv) => {
    if (conv.type === 'group') return conv.name || 'Group'
    const others = (conv.members || []).filter(e => e !== userEmail)
    return others.map(memberName).join(', ') || 'Direct message'
  }
  const convLevelName = (conv) => {
    if (conv.level === 'folder') {
      const f = folders.find(x => x.id === conv.folder_id)
      return f ? f.name : 'Folder'
    }
    if (conv.level === 'model') {
      const file = (projectFiles || []).find(x => x.id === conv.file_id)
      return file ? file.file_name : 'Model'
    }
    return 'Project'
  }
  const convLevelLabel = (conv) => {
    if (conv.level === 'folder') {
      const f = folders.find(x => x.id === conv.folder_id)
      return f ? `📁 ${f.name}` : '📁 Folder'
    }
    if (conv.level === 'model') {
      const file = (projectFiles || []).find(x => x.id === conv.file_id)
      return file ? `🧊 ${file.file_name}` : '🧊 Model'
    }
    return '🌐 Project'
  }

  const folderChainOf = (fid) => {
    const set = new Set()
    const file = (projectFiles || []).find(f => f.id === fid)
    let cur = file?.folder_id ?? null
    let guard = 0
    while (cur && guard < 10) {
      set.add(cur)
      const parent = folders.find(f => f.id === cur)
      cur = parent ? parent.parent_id : null
      guard++
    }
    return set
  }

  // project always; folder = union of folder chains of all models in scene;
  // model-level only for the model you've entered (activeFileId).
  const folderScope = (() => {
    const set = new Set()
    for (const f of modelList) for (const x of folderChainOf(f.id)) set.add(x)
    return set
  })()

  const isConvVisible = (conv) => {
    const lvl = normLevel(conv)
    if (lvl === 'project') return true
    if (lvl === 'folder') return folderScope.has(conv.folder_id)
    if (lvl === 'model') return activeFileId != null && conv.file_id === activeFileId
    return true
  }

  const projectMembersExceptMe = (projectMembers || []).filter(m => m.user_email !== userEmail)
  const modelOptions = modelList.map(m => ({ id: m.id, file_name: m.name }))

  // ---------- UI ----------
  const ElementLink = ({ elementId, fileId: linkFileId, name, className = '' }) => {
    const clickable = elementId && elementId !== -1
    if (clickable) {
      return (
        <button onClick={() => focusElement(elementId, linkFileId)}
          className={`text-blue-600 text-xs font-medium hover:underline text-left ${className}`}
          title="Show in 3D">
          🔗 {name}
        </button>
      )
    }
    return <div className={`text-blue-600 text-xs font-medium ${className}`}>🔗 {name}</div>
  }

  const TabButton = ({ id, label }) => (
    <button onClick={() => setActiveTab(id)}
      className={`flex-1 py-2 text-sm font-medium ${activeTab === id ? 'is-active' : ''} ${activeTab === id
        ? 'bg-blue-700 text-white' : 'bg-white text-blue-700 hover:bg-blue-50'}`}>
      {label}
    </button>
  )

  const ElementChip = () => selected && (
    <div className="px-3 py-2 border-t bg-blue-50 flex items-center justify-between text-sm">
      <span className="text-blue-700 truncate">🔗 {selected.elementName || selected.name}</span>
      <button onClick={() => setSelected(null)}
        className="text-gray-500 hover:text-gray-700 text-xs ml-2">clear</button>
    </div>
  )

  const ConversationList = () => {
    const visible = conversations.filter(isConvVisible)
    if (visible.length === 0) {
      return <p className="text-gray-400 text-sm text-center py-8 px-3">No conversations for this context yet. Start one with “+ New”.</p>
    }
    const sorted = [...visible].sort((a, b) => {
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
          className={`pl-2.5 pr-3 py-2.5 cursor-pointer border-b border-l-4 ${meta.border} bg-white hover:bg-gray-50 transition`}>
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
  }

  const pendingCount = modelList.filter(f => modelStatus[f.id] === 'pending').length
  const overlayVisible = !worldReady || !firstSync

  return (
    <div className="bc-viewer" aria-label="3D workspace">
      <style>{`[data-thatopen-logo] { display: none !important; }`}</style>

      <header className="bc-scene-header"><div><h2>3D workspace</h2><p className="bc-muted">{projectName} · {modelList.length} models open</p></div><div className="bc-actions"><details className="bc-scene-models"><summary className="bc-button">Models in this view ({modelList.length})<Icon name="down" size={15} /></summary>{modelControls}</details><button className="bc-button" onClick={onClose}><Icon name="left" size={16} />Model selection</button></div></header>
      <div className="bc-viewer-body">
        {/* 3D viewport */}
        <div className="bc-viewport">
          <div ref={containerRef} className="absolute inset-0" />

          {/* region capture overlay */}
          {regionMode && (
            <div className="absolute inset-0 z-30 cursor-crosshair"
              onMouseDown={onRegionMouseDown} onMouseMove={onRegionMouseMove} onMouseUp={onRegionMouseUp}>
              <div className="absolute inset-0 bg-black/20" />
              {regionRect && regionRect.w > 0 && (
                <div className="absolute border-2 border-blue-400 bg-blue-400/10"
                  style={{ left: regionRect.x, top: regionRect.y, width: regionRect.w, height: regionRect.h }} />
              )}
              <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-black/70 text-white text-xs px-3 py-1.5 rounded-full">
                Drag to select a region · Esc to cancel
              </div>
            </div>
          )}

          {/* close button */}
          <button onClick={onClose}
            className="absolute top-4 left-4 z-10 bg-white/90 hover:bg-white text-gray-700 px-3 py-1.5 rounded shadow text-sm">
            ✕ Close 3D
          </button>

          {/* scene status bar */}
          <div className="absolute top-4 left-32 z-10 flex items-center gap-2">
            <div className="bg-white/90 rounded shadow px-3 py-1.5 text-sm text-gray-700">
              🗂 {modelList.length} model{modelList.length === 1 ? '' : 's'}
              {pendingCount > 0 && <span className="text-amber-600"> · {pendingCount} preparing…</span>}
            </div>
            {multi && (
              activeFileId != null ? (
                <div className="bg-blue-700 text-white rounded shadow px-3 py-1.5 text-sm flex items-center gap-2">
                  <span className="truncate max-w-[160px]">In: {nameOfFile(activeFileId)}</span>
                  <button onClick={() => setActiveFileId(null)} className="hover:bg-blue-800 rounded px-1.5 -mr-1">Exit</button>
                </div>
              ) : selectedModel ? (
                <div className="bg-blue-600 text-white rounded shadow px-3 py-1.5 text-sm flex items-center gap-2">
                  <span className="truncate max-w-[180px]">Model: {selectedModel.name}</span>
                  <button onClick={() => setActiveFileId(selectedModel.fileId)}
                    className="bg-white/20 hover:bg-white/30 rounded px-2 py-0.5 text-xs">Enter</button>
                </div>
              ) : (
                <div className="bg-amber-100 text-amber-800 rounded shadow px-3 py-1.5 text-sm">
                  Click a model to select · double-click to enter
                </div>
              )
            )}
          </div>

          {/* visualization toolbar */}
          {!overlayVisible && (
            <div className="absolute top-4 right-4 flex flex-col gap-1.5 items-end">
              <button onClick={applySectionBox} title="Section box around selected element"
                className={`w-9 h-9 rounded shadow flex items-center justify-center text-base ${sectionActive
                  ? 'bg-blue-700 text-white' : 'bg-white text-gray-700 hover:bg-gray-100'}`}>⬚</button>
              <button onClick={toggleClipMode} title="Create a cutting plane (click a surface)"
                className={`w-9 h-9 rounded shadow flex items-center justify-center ${clipMode
                  ? 'bg-blue-700 text-white' : 'bg-white text-gray-700 hover:bg-gray-100'}`}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                  <circle cx="12" cy="12" r="6.5" />
                  <path d="M12 5.5 L15 11 L9 11 Z" fill="currentColor" stroke="none" />
                  <line x1="2" y1="12" x2="22" y2="12" />
                </svg>
              </button>
              <button onClick={togglePlanesVisible} title={planesVisible ? 'Hide cut planes' : 'Show cut planes'}
                className={`w-9 h-9 rounded shadow flex items-center justify-center text-base ${!planesVisible
                  ? 'bg-blue-700 text-white' : 'bg-white text-gray-700 hover:bg-gray-100'}`}>
                {planesVisible ? '👁️' : '🙈'}
              </button>
              <button onClick={deleteAllClips} title="Delete all cutting planes"
                className="w-9 h-9 rounded shadow flex items-center justify-center text-base bg-white text-gray-700 hover:bg-gray-100">🗑</button>
              <button onClick={clearSectionBox} title="Exit section box"
                className="w-9 h-9 rounded shadow flex items-center justify-center text-base bg-white text-gray-700 hover:bg-gray-100">⊗</button>
              {clipMode && (
                <div className="bg-black/60 text-white text-[11px] px-2 py-1 rounded max-w-[160px] text-right mt-1">
                  Click a surface to cut
                </div>
              )}
            </div>
          )}

          {!overlayVisible && selected && (
            <div className="absolute top-16 left-4 w-72 flex flex-col gap-2">
              <div className="bg-white rounded-lg shadow-lg p-3 text-sm">
                <p className="font-semibold text-gray-800 mb-1">Selected element</p>
                {multi && selected.fileId != null && (
                  <p className="text-gray-700"><span className="text-gray-500">Model:</span> {nameOfFile(selected.fileId)}</p>
                )}
                <p className="text-gray-700"><span className="text-gray-500">Name:</span> {selected.name}</p>
                {selected.elementId > 0 && (
                  <p className="text-gray-700"><span className="text-gray-500">Element ID:</span> {selected.elementId}</p>
                )}
                <button onClick={loadProperties}
                  className="mt-2 bg-blue-700 hover:bg-blue-800 text-white px-2 py-1 rounded text-xs">📋 Properties</button>
                {sectionActive && (
                  <div className="mt-2">
                    <div className="flex justify-between text-xs text-gray-500 mb-1">
                      <span>Box size</span><span>{sectionPad.toFixed(1)} m</span>
                    </div>
                    <input type="range" min="-0.4" max="5" step="0.1" value={sectionPad}
                      onChange={e => onSectionPadChange(parseFloat(e.target.value))}
                      className="w-full accent-blue-700" />
                  </div>
                )}
              </div>

              {showProps && (
                <div className="bg-white rounded-lg shadow-lg max-h-[70vh] overflow-y-auto text-sm">
                  <div className="flex justify-between items-center px-3 py-2 border-b sticky top-0 bg-white">
                    <span className="font-semibold text-gray-800">Properties</span>
                    <button onClick={() => setShowProps(false)} className="text-gray-500 hover:text-gray-700 text-xs">✕</button>
                  </div>
                  {loadingProps && <p className="px-3 py-3 text-gray-500">Loading...</p>}
                  {!loadingProps && props && (
                    <div className="px-3 py-2">
                      {props.attributes.length > 0 && (
                        <div className="mb-2">
                          <p className="font-semibold text-gray-700 text-xs uppercase mb-1">Attributes</p>
                          {props.attributes.map((a, i) => (
                            <div key={i} className="flex justify-between gap-2 py-0.5 border-b border-gray-100">
                              <span className="text-gray-500 flex-shrink-0">{a.name}</span>
                              <span className="text-gray-800 text-right break-all">{a.value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {props.psets.map((ps, i) => (
                        <details key={i} className="mb-1" open>
                          <summary className="cursor-pointer font-semibold text-gray-700 text-xs py-1">{ps.name}</summary>
                          <div className="pl-1">
                            {ps.props.map((p, j) => (
                              <div key={j} className="flex justify-between gap-2 py-0.5 border-b border-gray-100">
                                <span className="text-gray-500 flex-shrink-0">{p.name}</span>
                                <span className="text-gray-800 text-right break-all">{p.value}</span>
                              </div>
                            ))}
                          </div>
                        </details>
                      ))}
                      {props.attributes.length === 0 && props.psets.length === 0 && (
                        <p className="text-gray-500 py-2">No properties found.</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {!overlayVisible && !selected && sectionActive && (
            <button onClick={clearSectionBox}
              className="absolute top-16 left-4 bg-gray-200 hover:bg-gray-300 text-gray-700 px-3 py-1.5 rounded text-xs shadow">
              ✕ Clear section
            </button>
          )}

          {/* context menu */}
          {contextMenu && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setContextMenu(null)} />
              <div className="fixed z-50 bg-white rounded-lg shadow-xl border border-gray-200 py-1 text-sm w-48"
                style={{ left: contextMenu.x, top: contextMenu.y }}>
                {selected && (
                  <>
                    <button onClick={isolateSelected} className="w-full text-left px-3 py-2 hover:bg-gray-100">🔆 Isolate</button>
                    <button onClick={hideSelected} className="w-full text-left px-3 py-2 hover:bg-gray-100">🚫 Hide</button>
                    <button onClick={() => { applySectionBox(); setContextMenu(null) }} className="w-full text-left px-3 py-2 hover:bg-gray-100">✂️ Section box</button>
                    <div className="border-t my-1" />
                  </>
                )}
                <button onClick={deleteClipHere} className="w-full text-left px-3 py-2 hover:bg-gray-100">🗑 Delete cut here</button>
                <button onClick={showAll} className="w-full text-left px-3 py-2 hover:bg-gray-100">👁️ Show all</button>
              </div>
            </>
          )}

          {!overlayVisible && !selected && modelList.length > 0 && (
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-black/60 text-white text-xs px-3 py-1.5 rounded-full">
              {multi ? 'Click an element to select · double-click a model to enter it' : 'Click an element to select it'}
            </div>
          )}

          {!overlayVisible && modelList.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center text-white text-center px-6">
              <p>No models in the scene.<br />Add models from the list on the left.</p>
            </div>
          )}

          {overlayVisible && (
            <div className="absolute inset-0 flex items-center justify-center text-white text-center px-6">
              {errorMsg ? <p className="text-red-300">Error: {errorMsg}</p> : (
                <div>
                  <div className="animate-spin h-8 w-8 border-2 border-white border-t-transparent rounded-full mx-auto mb-3" />
                  <p>Loading 3D...</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Side panel */}
        <div className="bc-viewer-panel">
          <div className="bc-panel-tabs flex border-b">
            <TabButton id="tasks" label="📋 Tasks" />
            <TabButton id="chat" label="💬 Chat" />
          </div>

          {/* CHAT */}
          {activeTab === 'chat' && (
            selectedConv ? (
              <>
                <div className="px-3 py-2 border-b bg-blue-700 flex items-center gap-2">
                  <button onClick={() => { setSelectedConv(null); setConvMessages([]); setAttByMsg({}); attByMsgRef.current = {}; clearPending() }}
                    className="text-white text-lg leading-none">←</button>
                  <div className="flex-1 min-w-0">
                    <p className="text-white text-sm font-semibold truncate">
                      {selectedConv.type === 'group' ? '👥' : '👤'} {convTitle(selectedConv)}
                    </p>
                    <p className="text-blue-200 text-[11px] truncate">
                      {convLevelLabel(selectedConv)}
                      {selectedConv.type === 'group' && ` · ${(selectedConv.members || []).length} members`}
                    </p>
                  </div>
                  <button onClick={leaveConversation}
                    className="text-blue-100 hover:text-white text-xs border border-blue-400 rounded px-2 py-1">Leave</button>
                </div>

                <div className="flex-1 overflow-y-auto p-3 space-y-3">
                  {convMessages.map(m => (
                    <div key={m.id} className="flex flex-col group">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-6 h-6 bg-blue-700 rounded-full flex items-center justify-center text-white text-xs font-bold">
                          {m.sender?.[0]?.toUpperCase() || '?'}
                        </div>
                        <span className="text-xs font-medium text-blue-700">{memberName(m.sender)}</span>
                        <span className="text-xs text-gray-400">{new Date(m.created_at).toLocaleTimeString()}</span>
                        <button onClick={() => convertMessageToTask(m)}
                          className="opacity-0 group-hover:opacity-100 transition text-[11px] text-gray-500 hover:text-blue-700 border border-gray-200 rounded px-1.5 py-0.5"
                          title="Convert to task">→ Task</button>
                      </div>
                      <div className="ml-8 bg-gray-100 rounded-lg px-3 py-2 text-sm">
                        {m.message}
                        {m.element_name && (
                          <ElementLink elementId={m.element_id} fileId={m.file_id} name={m.element_name} className="mt-1 block" />
                        )}
                        {(attByMsg[m.id] || []).map(att => (
                          isImageAtt(att) ? (
                            <a key={att.id} href={att.file_url} target="_blank" rel="noreferrer" className="block mt-2">
                              <img src={att.file_url} alt={att.file_name}
                                className="max-w-full max-h-56 rounded border border-gray-200" />
                            </a>
                          ) : (
                            <a key={att.id} href={att.file_url} target="_blank" rel="noreferrer"
                              className="mt-2 flex items-center gap-2 bg-white border border-gray-200 rounded px-2 py-1.5 hover:bg-gray-50">
                              <span className="text-lg">📄</span>
                              <span className="text-xs text-gray-700 truncate">{att.file_name}</span>
                            </a>
                          )
                        ))}
                      </div>
                    </div>
                  ))}
                  <div ref={chatEndRef} />
                </div>

                <ElementChip />

                {pendingFile && (
                  <div className="px-3 py-2 border-t bg-gray-50 flex items-center gap-2">
                    {pendingPreview ? (
                      <img src={pendingPreview} alt="preview" className="h-12 w-12 object-cover rounded border" />
                    ) : (
                      <span className="text-2xl">📄</span>
                    )}
                    <span className="flex-1 text-xs text-gray-600 truncate">{pendingFile.name}</span>
                    <button onClick={clearPending}
                      className="text-gray-500 hover:text-gray-700 text-xs">✕</button>
                  </div>
                )}

                <div className="p-3 border-t flex gap-2 items-center">
                  <input ref={fileInputRef} type="file" className="hidden"
                    accept=".jpg,.jpeg,.png,.gif,.pdf,.dwg,.rvt" onChange={onPickFile} />
                  <div className="relative flex-shrink-0">
                    <button onClick={() => setCaptureMenuOpen(o => !o)} title="Capture 3D view"
                      className="bg-gray-100 hover:bg-gray-200 text-gray-700 w-9 h-9 rounded-lg flex items-center justify-center">📷</button>
                    {captureMenuOpen && (
                      <>
                        <div className="fixed inset-0 z-40" onClick={() => setCaptureMenuOpen(false)} />
                        <div className="absolute bottom-11 left-0 z-50 bg-white rounded-lg shadow-xl border border-gray-200 py-1 w-44 text-sm">
                          <button onClick={captureActiveView}
                            className="w-full text-left px-3 py-2 hover:bg-gray-100">🖼️ Active View</button>
                          <button onClick={startRegionCapture}
                            className="w-full text-left px-3 py-2 hover:bg-gray-100">✂️ Select Region</button>
                        </div>
                      </>
                    )}
                  </div>
                  <button onClick={() => fileInputRef.current?.click()} title="Attach file"
                    className="bg-gray-100 hover:bg-gray-200 text-gray-700 w-9 h-9 rounded-lg flex items-center justify-center text-lg flex-shrink-0">+</button>
                  <input value={newConvMessage} onChange={e => setNewConvMessage(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && sendConvMessage()}
                    onPaste={onPasteInput}
                    placeholder={selected ? 'Message about this element...' : 'Type a message...'}
                    className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                  <button onClick={sendConvMessage}
                    className="bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-800 flex-shrink-0">Send</button>
                </div>
              </>
            ) : (
              <>
                <div className="px-3 py-2 border-b flex justify-between items-center">
                  <span className="font-semibold text-gray-700 text-sm">Chat</span>
                  <button onClick={() => setShowNewConvModal(true)}
                    className="bg-blue-700 hover:bg-blue-800 text-white px-2.5 py-1 rounded-lg text-xs">+ New</button>
                </div>
                <div className="flex-1 overflow-y-auto">
                  <ConversationList />
                </div>
              </>
            )
          )}

          {/* TASKS */}
          {activeTab === 'tasks' && (
            <>
              <div className="flex-1 overflow-y-auto p-3 space-y-2">
                {tasks.map(t => (
                  <div key={t.id} className="border border-gray-200 rounded-lg p-2">
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: statusColor(t.status) }} />
                      <span className="font-medium text-sm flex-1">{t.description}</span>
                    </div>
                    {t.assignee && <p className="text-xs text-gray-500 ml-5">→ {t.assignee}</p>}
                    {t.element_name && t.element_id !== -1 && (
                      <div className="ml-5"><ElementLink elementId={t.element_id} fileId={t.file_id} name={t.element_name} /></div>
                    )}
                    <div className="ml-5 mt-1">
                      <select value={t.status} onChange={e => updateTaskStatus(t.id, e.target.value)}
                        className="text-xs border border-gray-200 rounded px-1 py-0.5">
                        <option value="Open">Open</option>
                        <option value="InProgress">In Progress</option>
                        <option value="Closed">Closed</option>
                      </select>
                    </div>
                  </div>
                ))}
                {tasks.length === 0 && <p className="text-sm text-gray-400 text-center mt-4">No tasks yet.</p>}
              </div>

              {showNewTask ? (
                <div className="border-t p-3 space-y-2">
                  <input value={newTaskDesc} onChange={e => setNewTaskDesc(e.target.value)}
                    placeholder="Task description..."
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                  <select value={newTaskAssignee} onChange={e => setNewTaskAssignee(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                    <option value="">Assign to... (optional)</option>
                    {users.map(u => <option key={u.email} value={u.email}>{u.full_name || u.email}</option>)}
                  </select>
                  {selected && <div className="text-blue-700 text-sm">🔗 {selected.elementName || selected.name}</div>}
                  <div className="flex gap-2">
                    <button onClick={createTask}
                      className="flex-1 bg-blue-700 text-white py-2 rounded-lg text-sm font-medium hover:bg-blue-800">Create</button>
                    <button onClick={() => { setShowNewTask(false); setNewTaskDesc(''); setNewTaskAssignee('') }}
                      className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg text-sm">Cancel</button>
                  </div>
                </div>
              ) : (
                <div className="border-t p-3">
                  <button onClick={() => setShowNewTask(true)}
                    className="w-full bg-blue-700 text-white py-2 rounded-lg text-sm font-medium hover:bg-blue-800">
                    + New Task {selected ? '(linked to element)' : ''}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* ANNOTATE SCREENSHOT MODAL */}
      {annotUrl && (
        <AnnotateModal
          imageUrl={annotUrl}
          onCancel={closeAnnot}
          onSend={(file) => { stagePending(file); closeAnnot() }}
        />
      )}

      {/* NEW CONVERSATION MODAL */}
      {showNewConvModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold text-gray-800 mb-4">New conversation</h2>

            <div className="inline-flex bg-gray-200 rounded-lg p-1 mb-4">
              <button onClick={() => { setNcType('dm'); setNcMembers([]) }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium transition ${ncType === 'dm' ? 'bg-white text-blue-700 shadow' : 'text-gray-600'}`}>👤 Direct</button>
              <button onClick={() => { setNcType('group'); setNcMembers([]) }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium transition ${ncType === 'group' ? 'bg-white text-blue-700 shadow' : 'text-gray-600'}`}>👥 Group</button>
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
                <label className="block text-sm font-medium text-gray-700 mb-1">{ncType === 'dm' ? 'Person *' : 'Members *'}</label>
                <div className="border border-gray-300 rounded-lg max-h-40 overflow-y-auto">
                  {projectMembersExceptMe.length === 0 ? (
                    <p className="text-xs text-gray-400 p-3">No other members in this project yet.</p>
                  ) : projectMembersExceptMe.map(m => {
                    const checked = ncMembers.includes(m.user_email)
                    return (
                      <label key={m.user_email}
                        className="flex items-center gap-2 px-3 py-2 hover:bg-gray-50 cursor-pointer text-sm border-b last:border-b-0">
                        <input type={ncType === 'dm' ? 'radio' : 'checkbox'} name="conv-members" checked={checked}
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
                <select value={ncLevel}
                  onChange={e => {
                    const lvl = e.target.value
                    setNcLevel(lvl); setNcFolderId('')
                    setNcFileId(lvl === 'model'
                      ? String(activeFileId ?? (modelList[0]?.id ?? ''))
                      : '')
                  }}
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
                    {modelOptions.map(f => (
                      <option key={f.id} value={f.id}>{f.file_name}{f.id === activeFileId ? ' (active)' : ''}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button onClick={closeNewConvModal} className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg text-sm">Cancel</button>
              <button onClick={createConversation} className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded-lg text-sm font-medium">Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

'use strict';
// Pure policy: no filesystem, database, network or ownership mutations.
// Call only with a complete, authorized project catalog, never with a filtered UI search.
const modelExtensions = new Set(['rvt', 'rfa', 'ifc', 'nwd', 'nwc', 'dwg', 'dgn', '3dm', 'skp', 'pln', 'pla', 'rte', 'rft', 'ifczip', 'frag']);
function need(value, code) { if (!value) { const error = new Error(code); error.code = code; throw error; } }
function pathKey(value, allowRoot = false) {
  need(typeof value === 'string', 'INVALID_PATH');
  if (allowRoot && value === '') return '';
  const path = value.replace(/\\/g, '/').normalize('NFC');
  need(path.length > 0 && path.length <= 1024, 'INVALID_PATH');
  const parts = path.split('/');
  need(parts.every(part => part && part !== '.' && part !== '..' && !/[\x00-\x1f:*?"<>|]/.test(part) && !/[ .]$/.test(part) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)), 'INVALID_PATH');
  return path.toLowerCase();
}
const parent = path => path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
const contains = (folder, path) => folder === '' || path === folder || path.startsWith(folder + '/');
function compile({ folders, files, modelPaths = [], complete }) {
  need(complete === true && Array.isArray(folders) && Array.isArray(files), 'COMPLETE_CATALOG_REQUIRED');
  const byId = new Map(), byPath = new Map();
  for (const folder of folders) {
    const id = String(folder.id ?? '');
    const path = pathKey(folder.path);
    need(id && !byId.has(id) && !byPath.has(path), 'DUPLICATE_FOLDER');
    const entry = { ...folder, id, path };
    byId.set(id, entry); byPath.set(path, entry);
  }
  for (const folder of byId.values()) need(!parent(folder.path) || byPath.has(parent(folder.path)), 'MISSING_PARENT');
  const requiredTrees = new Set(), requiredFiles = new Set();
  const allFiles = new Set();
  for (const folder of byId.values()) if (folder.kind === 'model' || folder.kind === 'model-support' || folder.path.split('/').some(part => part.endsWith('_backup'))) requiredTrees.add(folder.path);
  const markModel = path => {
    requiredFiles.add(path);
    // A model in the project root must not force unrelated documentation folders local.
    const directory = parent(path);
    if (directory) requiredTrees.add(directory);
    if (/\.rvt$/.test(path)) requiredTrees.add(path.slice(0, -4) + '_backup');
  };
  for (const file of files) {
    const path = pathKey(file.path ?? file.relative_path);
    need(!allFiles.has(path), 'DUPLICATE_FILE'); allFiles.add(path);
    if (file.kind === 'model' || modelExtensions.has(path.split('.').pop())) markModel(path);
    if (file.kind === 'model-support') requiredFiles.add(path);
    const parts = path.split('/');
    const backup = parts.findIndex(part => part.endsWith('_backup'));
    if (backup >= 0) requiredTrees.add(parts.slice(0, backup + 1).join('/'));
    need(!parent(path) || byPath.has(parent(path)), 'MISSING_FILE_FOLDER');
  }
  // Explicit linked-model paths cover formats without a known extension and dependencies.
  for (const model of modelPaths) markModel(pathKey(model));
  function mandatory(path) { return requiredFiles.has(path) || [...requiredTrees].some(root => contains(root, path)); }
  function folderPolicy(folderId) {
    const folder = byId.get(String(folderId)); need(folder, 'FOLDER_NOT_FOUND');
    if ([...requiredTrees].some(root => contains(root, folder.path))) return 'always-local';
    if ([...requiredTrees, ...requiredFiles].some(path => contains(folder.path, path))) return 'contains-required';
    return 'optional';
  }
  function decision(filePath, preferences = []) {
    const path = pathKey(filePath);
    need(allFiles.has(path), 'FILE_NOT_IN_CATALOG');
    if (mandatory(path)) return { mode: 'local', reason: 'model-required' };
    let chosen = null;
    for (const preference of preferences) {
      need(['local', 'online-only'].includes(preference.mode), 'INVALID_MODE');
      const folder = byId.get(String(preference.folderId));
      // Removed folders must not redirect an old preference onto a newly reused path.
      if (folder && contains(folder.path, path) && (!chosen || folder.path.length > chosen.path.length)) chosen = { ...preference, path: folder.path };
    }
    return { mode: chosen?.mode || 'local', reason: chosen ? 'device-preference' : 'existing-sync-default' };
  }
  return { folderPolicy, decision, byId };
}
function setPreference({ catalog, actorId, device, folderId, mode, expectedRevision, revision, preferences }) {
  need(device && String(device.userId) === String(actorId) && !device.revoked, 'DEVICE_ACCESS_DENIED');
  need(device.protocol === 1, 'DRIVE_UPDATE_REQUIRED');
  need(Number.isSafeInteger(revision) && expectedRevision === revision, 'PREFERENCE_CHANGED');
  need(['local', 'online-only'].includes(mode), 'INVALID_MODE');
  const policy = catalog.folderPolicy(folderId);
  need(mode !== 'online-only' || policy !== 'always-local', 'MODEL_MUST_STAY_LOCAL');
  const next = preferences.filter(item => String(item.folderId) !== String(folderId));
  next.push({ folderId: String(folderId), mode });
  return { revision: revision + 1, preferences: next, status: 'pending', folderPolicy: policy };
}
function applicationStatus({ desiredRevision, appliedRevision, appliedCatalogRevision, catalogRevision, lastSeen, now = Date.now(), connected }) {
  if (!connected || !Number.isFinite(lastSeen) || now - lastSeen > 120000 || lastSeen > now + 30000) return 'offline';
  return desiredRevision === appliedRevision && catalogRevision === appliedCatalogRevision ? 'applied' : 'pending';
}
module.exports = { compile, setPreference, applicationStatus, pathKey };

'use strict';
// Catalog URLs are not an ownership-stream bootstrap or recovery capability.
const names = new Set(['users.dat', 'editingperms.dat', 'editingdeltas.dat', 'editingrequests.dat', 'worksetperms.dat']);
function unresolved() {
    return {status: 503, error: 'OWNERSHIP_DOWNLOAD_SCOPE_UNRESOLVED'};
}
function pathKey(value) {
    if (typeof value !== 'string' || !value.length) return null;
    const parts = value.replace(/\\/g, '/').split('/');
    // Reject ambiguous Windows aliases rather than treating them as unrelated.
    if (parts.some(p => !p || p === '.' || p === '..' || /[\x00-\x1f:*?"<>|]/.test(p) || /[ .]$/.test(p))) return null;
    return parts.join('/').toLowerCase();
}
module.exports = async function ownershipDownload(pool, file) {
    const target = pathKey(file.relative_path);
    if (!target) return unresolved();
    const parts = target.split('/');
    if (parts.length < 2 || !parts.at(-2).endsWith('_backup')) return null;
    const log = parts.at(-1) === parts.at(-2).slice(0, -7) + '.slog';
    if (!names.has(parts.at(-1)) && !log) return null;
    try {
        // LEFT JOIN preserves dangling/misbound stream identities so they fail closed.
        // No native-admission columns, feature toggle, plan call or DB writes.
        const {rows} = await pool.query(
            `SELECT m.file_id, m.project_id, m.head, cf.project_id AS catalog_project_id, cf.relative_path
             FROM bimchat_direct_ownership.model_streams m
             LEFT JOIN cloud_files cf ON cf.id = m.file_id
             WHERE m.project_id = $1`, [file.project_id]);
        let managed = false;
        for (const row of rows) {
            const central = pathKey(row.relative_path);
            if (String(row.project_id) !== String(file.project_id) ||
                String(row.catalog_project_id) !== String(file.project_id) || !central || !central.endsWith('.rvt')) return unresolved();
            const backup = central.slice(0, -4) + '_backup';
            if (parts.slice(0, -1).join('/') === backup) {
                if (!log) managed = true;
                else {
                    // Only a six-file stream owns SLOG. Never infer this from
                    // the extension alone or from another model's native flag.
                    if (!row.head || !Array.isArray(row.head.files)) return unresolved();
                    if (row.head.files.length === 6) {
                        const expected = [...names, central.split('/').at(-1).slice(0, -4) + '.slog'];
                        if (!row.head.files.every((f, i) => typeof f?.name === 'string' && f.name.toLowerCase() === expected[i])) return unresolved();
                        managed = true;
                    } else if (row.head.files.length !== 5 || !row.head.files.every((f,i) => f?.name === [...names][i])) return unresolved();
                }
            }
        }
        return managed ? {status: 409, error: 'OWNERSHIP_STREAM_DOWNLOAD_REQUIRED'} : null;
    } catch {
        // Missing schema/DB errors must never fall through to signing stale bytes.
        return unresolved();
    }
};

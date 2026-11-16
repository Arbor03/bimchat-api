# Existing web interface update — 16 November 2026

The real BIMChat dashboard now uses the approved light blue and white design. The authoritative web source is `web/` on branch `work/web-interface-20261116`. It connects to the existing production API; no API deployment is part of this update.

## Delivered

- English navigation, icons, collapsible sidebar, mobile drawer and responsive layouts.
- Project archive using existing Drive records, expandable folder tree, breadcrumbs, search, file metadata and version history. Downloads use the authenticated download endpoint, including its ownership restrictions.
- Compact 3D model browser with search, folder filtering, independent collapsible groups, multi-selection and disabled controls for models not ready to view.
- Existing federated viewer retained, with live model selection and chat open on the right. Heavy viewer code loads on demand.
- Updated login, project overview, tasks, conversations and team surfaces. Existing linked-model folder management remains available from Project files and 3D Models.
- Documentation navigation below 3D Models with an explicit empty state until deliverable services are implemented.

## Compatibility and installation

Installed in the existing `C:/Users/4/Desktop/bimchat-dashboard`, not a replacement sample site. Eleven source files were changed or added after backing up their prior contents. Dependencies, lockfile and Vite configuration were checked for equality and preserved. No environment files, model data, Revit, Drive, drivers or API configuration were changed.

Installation receipt: `incidents/20261116-api-startup/Web-install.json` in the PC1 workspace. Its backup manifest contains the previous and installed SHA-256 hashes and identifies newly added files. The previous contents are available there for a targeted rollback.

The current attachment presentation contract was preserved from the existing dashboard. The protected attachment/security candidate stays intact under `development/product-consolidation`; it is not silently mixed into this API-compatible graphical release. See `compatibility.json`.

## Validation

- Production build passed both in this repository and in the updated Desktop application (653 transformed modules).
- ESLint passed for the three new components and API configuration module.
- Browser checks used an explicitly synthetic loopback API (`tests/ui-fixture.cjs`), not production credentials or records: 20 models, filtering with selection retained, independent group collapse, multi-model workspace controls, chat default, archive navigation and version history, switching projects, and a 390 px mobile viewport without page-level horizontal overflow.
- Sidebar collapse verified at 72 px; temporary viewport override reset.
- Local built application login checked separately at `http://127.0.0.1:5190/`, connected to the normal production API by default.

Real model geometry loading and authenticated production write operations were not exercised. The existing large 3D viewer bundle still triggers Vite's size warning, although it is loaded separately from login/dashboard.

## Remaining product work

- Deliverable registers, sheet publication, markups and approval/revision workflows.
- Authoritative team/folder permission grants and Working/Coordination model classification. Current groups are actual folders; permissions are not inferred from folder names.
- Creation of arbitrary Drive archive folders (distinct from existing linked-model folder management).
- Protected attachment/security candidate integration and its server rollout, separately reviewed and tested.
- Authenticated checks with real projects and model geometry, plus performance work already recorded in project history.

## Run

With dependencies installed, use `npm run dev` or `npm run build` followed by `npm run preview`. The existing Desktop location supports the same workflow as before. The temporary PC1 review server uses port 5190 and is local to that machine.

For isolated UI verification, run `node tests/ui-fixture.cjs` and start Vite on 127.0.0.1:5187 with build-time `VITE_API_URL=http://127.0.0.1:5517`. This fixture is not part of the production bundle or Desktop installation.

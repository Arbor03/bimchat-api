# Development state — 16 November 2026

This branch preserves ongoing work against the current production source. It is not approved for production publication.

| Component | Location | State |
| --- | --- | --- |
| Production API baseline | Repository root | Same 103 runtime files as `main` at `934e7f2` |
| Collaboration API candidate and existing web | `product-consolidation/` | Preserved source with earlier local test evidence; not released |
| New English product interface | `../design-preview/index.html` | Exact snapshot of the currently published sample-data Site |
| Product decisions, audit and approvals | `../docs/product/` | Preserved project documents; distinguish approved decisions from proposals |
| Snapshot provenance | `state.json` | Hashes of all 142 preserved files, baseline commit and preview source revision |

The two web interfaces have different roles: `product-consolidation/web` is the existing application source; `design-preview` is the proposed design. The design still needs to be implemented against real authentication, permissions, file storage, model loading and collaboration APIs. Copying the preview into this branch does not implement those integrations.

Keep subsequent work on named branches and commit each coherent change. Integrate reviewed candidate changes into the runtime paths only when ready, then update the release manifest and validate before merging into `main`. Do not deploy this branch merely because its baseline API starts successfully.

The preserved candidate's preparation scripts, local PostgreSQL test setup and path assumptions describe its original PC1 workspace. Review and adapt those paths before rerunning them; dependency junctions, test databases, passwords and logs were not copied. The original files remain intact.

Revit, Drive and native driver sources still live under `ownership-native-gate` in the original workspace. They were not modified or migrated by this recovery. Bringing their current source and build provenance into a maintained repository remains an explicit follow-up.

## Remaining product work

- Measure ownership delay and agent/server round trips with two Revit users.
- Complete and validate client recovery, full Sync completion reporting and long-session behavior.
- Review the task/model identity and user-controlled transfer workflow before implementation.
- Integrate the proposed navigation, folder access, team sharing and role model with server authorization.
- Implement documentation deliverables, review/redline and formal revision as separate steps.
- Complete authenticated web/Revit integration testing before releasing the collaboration candidate.

The broader audit and architecture documents retain the detailed open items and the scope of user approvals.

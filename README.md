# BIMChat API — continuous source history

`main` is the production source. The runtime at the repository root is the complete reviewed SLOG wire release, restored on 16 November 2026. `release/manifest.json` identifies its 103 runtime files; `release/production.json` records matching public configuration and the recovery deployment.

The 16 November outage followed deployment of an older GitHub source revision while newer verified code existed only in release directories. This commit brings that code back into the same Git history. It does not reset the database, storage or client installations.

## Publication workflow

1. Make changes on a named development branch. Keep unfinished work committed there; do not silently replace `main` with an older directory.
2. Review and test the change. Update the runtime manifest and ownership review only as part of the corresponding reviewed release. Preserve the previous release in Git.
3. Run `node scripts/verify-release.cjs` before publishing. A source change without a matching reviewed manifest must fail this check. `--environment` also checks the four public deployment settings without reading or printing secrets.
4. Merge the verified change into `main`. Railway's existing GitHub source points to this branch. Stage any explicitly required configuration changes before deployment. Do not disable ownership checks to make startup succeed.
5. Record the exact Git commit and Railway deployment. Verify startup, authenticated-route rejection and relevant data-preservation checks; a platform SUCCESS flag alone is insufficient.

Emergency artifact publication is a recovery method, not a separate development history. If used, immediately reconcile the exact published bytes into Git before further work.

## Work still in development

The `work/product-continuity-20261116` branch preserves the collaboration candidate, original web source, current design preview and product decisions. It is not the production release and must not be deployed as part of this recovery. The design preview is published independently with sample data; it does not yet implement the production API or real model loading.

Existing native Revit/Drive/driver sources remain in the PC1 workspace. This recovery does not claim their migration into this API repository. Project-wide progress and remaining integration work are recorded in the development branch documentation.

## Local setup

Use `npm ci` to reproduce the locked dependencies. Keep credentials in local environment configuration or Railway's secret store. `.env` and installed dependencies must never be committed. The old ignore file was encoded incorrectly; the current UTF-8 ignore file and removal from the current tree correct tracking going forward, without rewriting history.

No real credentials are included in the new source tree. Historical revisions are preserved; removal from the latest tree does not remove historical secrets.

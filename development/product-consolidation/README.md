# Konsolidimi i pare i produktit - 15 nentor 2026

Gjendja: **kandidat lokal i testuar, jo deployment ose instalim**. User-i miratoi vazhdimin sipas rendit te raportit. Ky hap mbulon pjesen task/chat/attachments te P0-01 deri P0-04. Nuk mbyll te gjithe auditin dhe nuk eshte ende nje release per kliente.

## Burimi dhe ruajtja e punes ekzistuese

- `server/` nis nga artefakti aktual `ownership-native-gate/review/slog-wire-fix-20261115/server-release`, jo nga API-ja e vjeter ne Desktop. Modulet e ownership-it mbeten te pandryshuara.
- `chatAccess.js`, `chatRoutes.js`, `attachmentRoutes.js`, `attachmentStorage.js` u moren nga puna lokale `Desktop/BIMChat-API`; access dhe task-from-message u plotesuan ketu.
- Logjika e update-it te pjesshem dhe politika manager/creator/assignee u bashkuan ne `taskRoutes.js` me lejet e leximit, komentet, njoftimet dhe privatesine e mesazhit burim.
- `web/` eshte kopje e dashboard-it lokal. Burimi origjinal, Revit, Drive, driver-i, modeli dhe serveri online nuk u ndryshuan.
- `web/node_modules` eshte junction vetem per build drejt dependencies ekzistuese ne Desktop. Nuk eshte pjese e paketes per shperndarje.
- `prepare-candidate.cjs` rinderton vetem index-in nga baseline-i dhe prodhon krahasimin; nuk eshte instalues/deployer. `prepare-web.cjs` eshte transformim njehere mbi kopjen fillestare, jo per t'u ekzekutuar serish mbi kopjen e ndryshuar.

## Sjellja e re

1. Update vetem me `status` ruan assignee dhe view. Pranon alias-in legacy `viewName`; null/tekst bosh pastrojne fushen vetem kur dergohen shprehimisht. Task i munguar kthen 404.
2. Task-et dhe komentet kontrollojne anetaresine aktuale. Update/delete kerkon BIM Manager, krijuesin ose assignee-n. Caktimi i assignee kerkon anetar te projektit.
3. `created_by` dhe `author` merren nga JWT; projekti i komentit merret nga task-u. Klienti nuk mund t'i falsifikoje me trupin e kerkeses.
4. Task-u nga DM ruan kufirin e aksesit te mesazhit burim: nuk del per nje anetar tjeter ne lista, komente, njoftime ose attachments. Heqja nga projekti zbatohet edhe me token te leshuar para heqjes.
5. Rruget legacy te chat-it perjashtojne mesazhet e bisedave te reja. Lista e perdoruesve kufizohet tek projekti.
6. Attachments kane endpoint te autentikuar per metadata/content dhe kontroll te prindit para upload-it. Upload-et e reja Cloudinary perdorin authenticated storage. Shkarkimi nuk merr nje URL arbitrare nga mesazhi.
7. Dashboard dhe Viewer perdorin `ProtectedAttachment`: token vetem drejt API-se se konfiguruar, pa ndjekje redirects, pa token ne URL. Blob URLs pastrohen ne ndryshim sesioni/unmount; gabimi i aksesit ka mesazh/retry. Vetem formatet raster te lejuara shfaqen inline; dokumentet shkarkohen.
8. Migrimet shtese ne fund te initDB krijojne kolonat `messages.conversation_id`, `tasks.source_message_id`, `attachments.storage_type` edhe ne databaze bosh. Handler-at e vjeter u hoqen, nuk u lane perpara te rinjve.
9. Fshirja e nje task-u me attachments te veta/komenteve kthen 409 derisa ato te hiqen: nuk fshin metadata duke lene objekte storage pa reference. Kjo sjellje kerkon mesazh te pershtatshem ne UI para release-it.

## Verifikimi

- `tests/collaboration-http.cjs`: **19 skenare PASS**, me shume kerkesa HTTP per secilin, PostgreSQL real, JWT real dhe wrapper-in e writer fences aktiv gjate montimit te rrugeve.
- Skema u inicializua nga funksioni `initDB` i kandidatit. Montimi perdor modulet reale te kandidatit; procesi i plote i startup-it/ownership nuk u nis.
- Testet mbulojne anetar/joanetar/anetar te hequr, ndryshim te pjesshem, task te munguar, autor te falsifikuar, file/assignee te projektit tjeter, DM/legacy/attachments, rollback te krijimit ne deshtim te notification-it, fshirje dhe emra projektesh te perseritur.
- DB testimi u krijua me emer te rastesishem `product_test_<hex>`, ne cluster te ri ne `127.0.0.1:55439`; pas testit u fshi vetem DB e ketij ekzekutimi dhe u ndal vetem ky cluster. Nuk u lexua `.env` dhe nuk u perdor DB online.
- Storage ne testet HTTP eshte ne memorie. Nuk u dergua email, file Cloudinary ose model real.
- `tests/attachment-content.test.mjs`: **4 teste PASS** per endpoint/header, 401/403, gabim storage, mungese sesioni dhe kufi formatit inline.
- Web build: **PASS**, 650 module; paralajmerimi ekzistues i bundle-it te madh mbetet. Lint per dy modulet e reja: **PASS**.
- Syntax e moduleve JS te serverit: PASS. `source-manifest.json` regjistron ndryshimet kundrejt baseline-it dhe hash-et e kandidatit.

Evidenca: [HTTP](tests/http-results.log), [web tests](tests/web-tests.log), [web build](tests/web-build.log), [manifest](source-manifest.json).

## Kufizimet dhe puna pasuese

- Nuk eshte bere prova vizuale e autentikuar web/Revit me kete server kandidat. Burimi aktual Revit ka `AttachmentDownload` me Bearer dhe endpoint sipas ID-se, por DLL-ja e instaluar duhet verifikuar me test real perpara rollout-it. Web dhe API duhet te publikohen si kontrate e perbashket.
- Objekte Cloudinary historike me URL publike nuk behen private nga ndryshimi i endpoint-it. Nevojitet inventar dhe migrim i kontrolluar; nuk u ndryshuan objektet ekzistuese.
- Politika e edits ruan sjelljen lokale manager/creator/assignee. Roli Viewer/Client dhe nje matrice uniforme te drejtash ende duhet te konsolidohen ne te gjitha rruget e produktit. Ky ndryshim nuk eshte audit i plote i autorizimit te cdo endpoint-i.
- Njoftimet ende kane gjendjen historike `is_read` te perbashket; tani zbatojne aksesin e task-ut, por leximi individual per perdorues mbetet P1-07. Pagination >200 mesazhe mbetet e hapur.
- Listat verifikojne aksesin per task/attachment. Shtojne query dhe duhen matur/batch-uar per projekte te medha pa dobesuar privatesine.
- Attachment delete/storage compensation, startup/readiness dhe migrimet duhet te kalojne prova deshtimi. Nuk ka test real Cloudinary ne kete hap.
- Reset-i i fjalekalimit (P0-05), rikuperimi i agjentit (P0-06), Sync i plote, instaluesi, signing dhe performanca e ownership-it mbeten te hapura. Matjet e ownership-it mbeten per neser sipas vendimit ekzistues.
- Nuk ka deployment, restart, unload/reload driver-i, instalim ose ndryshim modeli nga ky hap. Nuk jepet komande instalimi para perfundimit te provave te kontrates dhe pergatitjes se release-it.

## Riperseritja e testeve

Modulet kerkojne dependencies te API-se (`NODE_PATH` mund te tregoje `Desktop/BIMChat-API/node_modules`). Testi PostgreSQL ka host/port/user testimi fikse; nis vetem cluster-in `tests/pgdata` te krijuar per kete pune dhe ndaloje pas testit. Mos ekzekuto initdb serish mbi cluster-in ekzistues. Kredenciali brenda testit eshte fiktiv dhe lokal.

```powershell
node tests/collaboration-http.cjs
node --test tests/attachment-content.test.mjs
```

Rreshti i pare kerkon DB-ne lokale te testimit aktive. Mos importo `server/index.js` per test, sepse nis serverin dhe lexon konfigurimin e zakonshem te prodhimit.

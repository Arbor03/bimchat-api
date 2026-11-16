# BIMChat - arkitektura e produktit dhe pervoja e perdoruesit

Data: 15 nentor 2026. Dokument projektimi per diskutim; nuk eshte implementim ose autorizim per deployment.

## 1. Drejtimi i kerkuar nga Arbori

Qellimi eshte thjeshtesia per bashkepunimin e projektit, duke perfshire persona pa pervoje BIM. Pamja grafike ekzistuese nuk pelqehet. Trimble Connect eshte reference per orientimin dhe organizimin, jo specifikim per kopjim te cdo funksioni.

Kerkesa aktive: te shqyrtohet arkitektura e plote PARA ndryshimeve te tjera ne produkt. Kandidati `product-consolidation-20261115` mbetet lokal dhe i papublikuar.

Te konfirmuara nga perdoruesi:
- Ne Revit: task-et e modelit aktiv dhe task-et e pergjithshme te projektit ne dy seksione te dallueshme.
- Duhet mundesi qe perdoruesi te kaloje task-e dhe mesazhe nga nje model te nje tjeter. Menyra copy/move dhe lejet e transferimit mbeten per t'u percaktuar.
- Dokumentacioni eshte regjister tabelar i gjithe produkteve per dorezim: modele, flete, raporte etj., perfshire produktet ende te pakrijuara.
- Eksport i fleteve nga Revit drejt web-it; kontroll dhe rikthim i shenimeve ne Revit.
- Shenime kontrolli dhe revizione zyrtare: TE DYJA, si dy hapa te vecante.
- Klikimi i `XXX - Piano terra` hap nje dosje pune me historikun, ecurine, input, output dhe ambientin e "copie rosse". Skedaret PDF/DWG jane rezultate te kesaj njesie pune.

Pjesa tjeter me poshte eshte propozim, jo liste vendimesh te miratuara.

## 2. Gjetjet mbi strukturen aktuale

Kontrolli u mbeshtet ne kodin lokal; ekranet e autentikuara te web-it nuk jane testuar me perdorues real gjate ketij rishikimi.

| Gjetja | Pasoja per perdoruesin |
|---|---|
| ROLES bashkon BIM Manager, BIM Specialist, Architect, Structural, MEP dhe Client | Nuk dallohet profesioni nga e drejta per te lexuar, publikuar ose administruar |
| Shtimi ne projekt kerkon qe personi te ekzistoje ne users | Bashkepunetori i ri has bllokim perpara se te hyje; mungon rruga e qarte ftese/pranim |
| Overview udhehiqet nga numerime dhe grafik task-esh | Nuk i pergjigjet drejtperdrejt pyetjes "Cfare duhet te bej une tani?" |
| Revit Files eshte hyrja kryesore per permbajtjen | Raportet, fletet PDF, dokumentet dhe dorzimet e planifikuara nuk kane vend te barabarte |
| Settings eshte Coming soon; gjithe aplikacioni ka vetem URL / | Mungon navigimi i qendrueshem dhe linku direkt drejt nje detyre/flete |
| Viewer-i ka model te zgjedhur, model aktiv, Enter/Exit dhe shume mjete teknike | Personi jo-BIM duhet te kuptoje mekaniken e viewer-it per te gjetur punen |
| Task-et ne Revit ngarkohen pa fileId dhe modeli lokal BimTask nuk ruan file_id | Task-et e modeleve te tjera perzihen; navigimi i elementit s'kontrollon modelin burim |
| Identiteti i modelit mbeshtetet te lidhja e ruajtur me rruge skedari | Riemertimi/kopjimi kerkojne politike te qarte identiteti |
| Shume gabime web kalojne ne console/catch bosh | Lista bosh mund te perceptohet si mungese pune edhe kur ngarkimi deshtoi |

Burime: Dashboard.jsx, Viewer.jsx, App.jsx ne web lokal; ChatPanel.xaml.cs, TaskLoading.cs, BimTask.cs ne add-in; rruget projects/members/link-file ne API.

## 3. Njerezit, aksesi dhe pergjegjesite

Propozim: llogaria identifikon personin; anetaresia jep aksesin ne projekt. Disiplina (Arkitekture/Strukture/MEP), kompania dhe pozicioni jane fusha te vecanta nga lejet. I njejti person mund te kete role te ndryshme ne projekte te ndryshme.

Tre profile fillestare te kuptueshme:

| Veprimi | Kontrollues | Bashkepunetor | Administrator projekti |
|---|---|---|---|
| Shikon permbajtjen ku ka akses | Po | Po | Po, brenda politikes se permbajtjes |
| Komenton dhe regjistron verejtje | Po, ne materialet e caktuara per kontroll | Po | Po |
| Ngarkon version pune / krijon output | Jo si parazgjedhje | Ne pjesen ku ka leje pune | Po |
| Administron regjistrin e dorezimeve | Jo | Pjesen e caktuar | Po |
| Fton persona / ndryshon aksesin | Jo | Jo si parazgjedhje | Po |
| Miraton nje dorezim zyrtar | Vetem kur eshte caktuar miratues | Vetem kur eshte caktuar miratues | Vetem sipas pergjegjesise se caktuar |

"Klient" nuk duhet te jete automatikisht nje nivel teknik i lejeve: mund te jete kontrollues ose miratues. Miratuesi eshte pergjegjesi mbi dorezimin/paketen, jo pasoje e njohurive BIM. Administrimi i projektit nuk propozohet si hyrje automatike ne DM private; kjo politike duhet vendosur shprehimisht.

Lejet kontrollohen ne server per objektin dhe projektin. Fshehja e butonit eshte ndihme vizuale, jo mbrojtje. Grupet e ekipit ndihmojne caktimin; dosjet nuk duhet te ndryshojne aksese pa nje politike te dukshme trashegimie. Shfaqet "Kush mund ta shohe" aty ku publikohet/ndahet permbajtja.

Rruga e hyrjes: ftese ne projekt -> identifikim/krijim llogarie -> pranimi i fteses -> projekti dhe puna e caktuar. Organizata mund te ekzistoje ne arkitekture pa e detyruar perdoruesin te kaloje ne nje ekran shtese kur ka vetem nje.

## 4. Navigimi i web-it

Hyrja personale: projektet e mia, puna qe pret mua dhe njoftimet e mia. Brenda nje projekti propozohet nje menu e qendrueshme:

1. **Permbledhje** - cfare pret veprim, dorezimet e aferta, ndryshimet e rendesishme.
2. **Dokumentacion** - regjistri i dorezimeve dhe dosjet e tyre te punes.
3. **Modele dhe skedare** - burimet dhe materialet e projektit, shikim 2D/3D sipas formatit.
4. **Detyra** - pune e caktuar; fillimisht "Te miat", me kalim te qarte te te gjitha detyrat e lejuara.
5. **Biseda** - komunikim projekti/ekipi/modeli dhe privat; audienca e dukshme.
6. **Ekipi** - njerezit dhe pergjegjesite. Administrimi dhe Settings vetem kur vlejne per perdoruesin.

Kerkimi dhe breadcrumbs tregojne gjithmone projektin dhe objektin aktiv. Linku i nje detyre/flete hap drejtperdrejt objektin pas login. Kthimi mbrapa ruan filtrin e listes.

Per personin jo-BIM: hap flete ose task -> sheh pamjen perkatese -> komenton/ben shenim -> dergon pergjigjen. Nuk kerkohet te zgjedhe IFC GUID, discipline teknike ose nje model aktiv perpara se te kuptoje kerkesen. Mjetet 3D te avancuara hapen sipas nevojes.

## 5. Dokumentacioni: produkti per dorezim si njesi pune

Nje rresht ekziston edhe perpara se te kete PDF, DWG ose model. Ai perfaqeson ate qe duhet prodhuar. Shembull: `A-101 - Piano terra`.

Kolonat fillestare: kodi, titulli, lloji, pergjegjesi, afati, gjendja e punes dhe revizioni i dorezuar. Disiplina, paketa, modeli burim, kontrolluesi dhe formatet mund te shfaqen sipas nevojes. Filtra te ruajtur: te miat, per kontroll, me afat te kaluar, sipas paketes/disiplines. Importi nga Excel eshte propozim pasues, jo funksion i ndertuar.

Klikimi hap dosjen e punes, me identitet te qendrueshem edhe nese emri ndryshon:

| Pjesa | Permbajtja |
|---|---|
| Ecuria | Pergjegjesi, kontrolluesi, afati, gjendja, veprimi i radhes, pengesat |
| Input | Materialet mbi te cilat bazohet puna: version modeli, rilevim, kerkese klienti, reference, flete e lidhur |
| Output | Versionet e prodhuara, formatet PDF/DWG/RVT/IFC/raport; prejardhja dhe publikimi |
| Copie rosse | Fleta ne nje version konkret, shenimet, pergjegjesit, pergjigjet dhe rikontrolli |
| Historiku | Kush ndryshoi cfare dhe kur; publikime, kontroll, vendime, ndryshim pergjegjesi, revizione |

Input dhe output jane lidhje me versione konkrete, jo kopje te pakontrolluara skedaresh. Nese nje input ka version te ri, dosja tregon "Input i perditesuar - duhet vleresuar"; nuk deklaron automatikisht se output-i ekzistues eshte i sakte ose i pavlefshem. Nje output mund te kete disa formate, por lidhja PDF/DWG me te njejtin version burim duhet te verifikohet.

Skedaret nuk jane dyfishuar mes Dokumentacion dhe Modele/skedare: regjistri i referon. Dosja e punes eshte nje objekt i vecante nga dosja fizike e storage-it.

## 6. Gjendjet: pune, kontroll, version dhe revizion

Propozim per rrjedhen e punes: Planifikuar -> Ne pergatitje -> Per kontroll -> Kerkon korrigjim / Miratuar -> Dorezuar. Perdoruesi sheh gjendjen dhe veprimin e vet, jo nje formular me gjithe tranzicionet teknike.

Nje version i ngarkuar (v1, v2, v3...) eshte snapshot i output-it. Revizioni zyrtar (p.sh. R00/R01 sipas rregullit te projektit) eshte nje leshim i kontrolluar. Shume versione pune mund te prodhojne nje revizion zyrtar. Miratimi, dorezimi dhe numerimi nuk aktivizohen thjesht sepse upload-i perfundoi.

Nje pakete dorezimi referon versione te sakta te disa produkteve. Pas leshimit, paketa ruhet ne histori; ndryshimi pasues krijon version/leshimin tjeter. Gjendja e transferimit teknik (ne ngarkim, ne perpunim, gati per shikim) mbahet vec nga statusi i punes.

## 7. Copie rosse dhe lidhja me detyrat

Shenimi ka autor, date, version flete, pozicion ne faqe, tekst, forme, pergjegjes dhe gjendje. Propozim: Hapur -> Ne trajtim -> Per rikontroll -> Mbyllur. Pergjegjesi e shenon gati; kontrolluesi konfirmon mbylljen sipas politikes se projektit.

Nje shenim qe kerkon veprim lidhet me nje detyre te vetme. Detyra ne liste dhe shenimi ne flete jane dy pamje te se njejtes ceshtje, jo dy probleme qe mbahen ne sinkron me dore. Shenimet vetem informuese mund te mbeten pa detyre.

Shenimet i perkasin versionit te kontrolluar. Kur fleta ndryshon madhesi, orientim, layout ose viewport-e, ato nuk vendosen verbërisht mbi versionin e ri. Pamja e vjeter dhe lidhja me historikun mbeten te hapshme; shenimet e bartura kerkojne verifikim.

## 8. Revit -> web -> Revit

Rrjedha e synuar:
1. Projektuesi zgjedh fletet dhe "Publiko per kontroll". Add-in i lidh me produktet ne regjister; perdoruesi konfirmon perputhjet e paqarta.
2. Eksportohen fletet dhe metadata: identitet modeli, identitet flete, numer/titull, madhesi/orientim, transformimi i faqes dhe versioni burim. Ngarkimi krijon output te ri; nuk mbishkruan nje dorezim historik.
3. Kontrolluesi hap fletën ne web, ben copie rosse dhe cakton veprimet pa instaluar Revit.
4. Revit shfaq shenimet ne fletën perkatese, me kontroll te versionit dhe vendndodhjes. Projektuesi korrigjon modelin/fleten dhe publikon versionin tjeter.
5. Kontrolluesi rikontrollon. Kur miratohet, personi i autorizuar nis revizionin zyrtar. Veprimet qe krijojne Revision/RevisionCloud ne Revit kalojne ne nje hap te kontrolluar; nuk jane pasoje automatike e nje shigjete te vizatuar ne web.

Fezibiliteti: ne RevitAPI.xml lokal te Revit 2024 u konfirmuan PDFExportOptions, Document.Export per PDF, Revision.Create, RevisionCloud.Create mbi ViewSheet dhe DWFImportOptions. Autodesk dokumenton ciklin DWF/Design Review/Link Markups ne Revit 2024. Kjo provon disa mekanizma baze, jo integrimin e plote BIMChat.

Propozim per web: PDF per shikim dhe shenime vektoriale te ruajtura vecmas. Rikthimi mbi fletën e punes kerkon spike teknik qe krahason nje shtrese shenimesh te add-in-it me rrugen DWF. Nuk pretendohet se shenimet web jane automatikisht te pajtueshme me DWF/Design Review. Nuk eshte zgjedhur ende implementimi.

Prova minimale para premtimit te funksionit: dy flete me permasa/orientime te ndryshme, ndryshim layout-i, eksport me emer te ndryshuar, rihapje modeli, dy perdorues, ribartje pa dublikim, reagim ndaj lidhjes se pasakte. Duhet verifikuar nese shtresa e shenimeve mund te jete e kontrollit dhe te mos perfshihet pa dashje ne printimin zyrtar.

Revizionet zyrtare duhet te kene nje autoritet per numerimin/leshimin. Serveri menaxhon workflow-n; add-in verifikon dhe raporton aplikimin ne Revit. Nese Revit eshte offline ose ka konflikt, statusi eshte "Ne pritje te aplikimit", jo "Perfunduar". Rregulli i numerimit dhe pika perfundimtare e leshimit mbeten vendime projektimi.

## 9. Modeli i te dhenave dhe pergjegjesite teknike

Propozim logjik: Person -> Anetaresi projekti -> Grup/discipline. Projekti permban modele, dokumente, produkte per dorezim, biseda dhe detyra. Modeli ka versione dhe flete; produkti per dorezim referon burimin dhe output-et. Sesioni i kontrollit lidhet me versionin; shenimi mund te lidhet me detyre; leshimi zyrtar referon output-et e miratuara.

Identifikuesit e qendrueshem jane lidhja kryesore. Emrat, sheet number dhe path-et jane atribute qe mund te ndryshojne. Elementi identifikohet bashke me modelin; fleta bashke me modelin dhe identitetin e saj. Per transferim modeli, bartja e punes ruan prejardhjen dhe verifikon lejet/lidhjet. Te dhenat historike pa file_id nuk duhen hamendesuar dhe rilidhur automatikisht.

Ndarja e pergjegjesive:
- Web: bashkepunim, registre, shqyrtim, 2D/3D dhe administrim sipas lejeve.
- Add-in: kontekst Revit, flete/elemente, eksport dhe aplikim i kontrolluar i veprimeve ne dokument.
- Drive: transport, radhe e qendrueshme, rikuperim dhe status transferimi.
- Driver: koordinim aksesi te skedaret ne nivel sistemi; nuk vendos rolet, statuset e dokumentacionit ose miratimin e fletes.
- API: autoritet per lejet dhe tranzicionet; DB per metadata/histori dhe object storage per byte/versione. Pune te renda ne radhe qe mund te rimerret pas deshtimit.

Per tani nje API e ndare ne module te qarta eshte me e pershtatshme se shume sherbime te reja: Identity/Access; Projects/Catalog; Collaboration; Documentation/Review; Model Publishing; Sync/Ownership. Kerkesat e perseritura per publikim/aplikim duhet te jene idempotente. Tranzicionet kane histori te autorit dhe versionit, jo vetem nje status te fundit.

## 10. Drejtimi grafik

Pamje e qete, sfond neutral, nje ngjyre kryesore per veprimet, ikona koherente me etiketa dhe tipografi e lexueshme. Tabelat e dokumentacionit jane qendra e punes; detajet hapen ne hapesire te bollshme me titullin dhe kontekstin te dukshëm. Grafiket perdoren vetem kur ndihmojne nje vendim.

Perdoruesi duhet te shohe cfare ka hapur, cilin version po kontrollon, kush duhet te veproje dhe cfare ndodh pas klikimit. Ngjyra e statusit shoqerohet me tekst. Mjetet teknike te viewer-it shfaqen kur nevojiten. Ne ekran te vogel lista dhe detajet hapen njera pas tjetres, me kthim te qarte.

Skica ilustruese e bisedes perdor te dhena fiktive; eshte drejtim per diskutim, jo dizajn final i miratuar dhe jo web i publikuar.

## 11. Prova e thjeshtesise

Testohen fillimisht pese detyra me nje person pa njohuri BIM: pranon ftese; gjen fletën per kontroll; le nje shenim; kupton kush po e trajton; gjen cfare eshte dorezuar zyrtarisht. Projektuesi teston publikimin/rikthimin e kontrollit; administratori teston ftese, kufij aksesi dhe caktim miratuesi.

Kriteri: rrjedha te perfundoje pa udhezim me goje, pa hyrje ne Revit per kontrolluesin, pa gabim projekti/modeli/versioni dhe me mesazh te kuptueshem kur mungon akses ose lidhja. Shpejtesia dhe numri i klikimeve maten gjate provës; nuk jane rezultate te pretenduara tani.

Rendi: dakordesimi i objekteve dhe roleve -> prototipi i regjistrit/dosjes se punes dhe tri rrjedhave -> prove me perdorues -> spike i fleteve/markups ne Revit 2024 -> plan migrimi/versionimi -> implementim i koordinuar. Puna e ownership-it dhe mbrojtjet ekzistuese ruhen gjate riorganizimit.

## Referenca

- [Trimble Connect: Roles](https://help.trimble.com/doc/trimble-connect/trimble-connect/connect-for-browser/team/roles): role administrimi te ndara nga profesioni; perdoret si reference, jo politike automatike e BIMChat.
- [Trimble Connect: Folder Permissions](https://help.trimble.com/doc/trimble-connect/trimble-connect/connect-for-browser/files-and-folders/folder-permissions): akses dhe trashegimi ne dosje. Nevojitet politika jone e qarte, sidomos per permbajtjen private.
- [Autodesk Revit 2024: Link DWF Markups](https://help.autodesk.com/cloudhelp/2024/ENU/Revit-DocumentPresent/files/GUID-CE67846D-C533-46DF-A702-7ECF2BB67DC8.htm): eksport flete, kontroll dhe rikthim markups. Nuk garanton pajtueshmeri me nje editor web te ri.
- Revit 2024 API lokale: `C:\Program Files\Autodesk\Revit 2024\RevitAPI.xml`, PDFExportOptions/Document.Export, Revision.Create, RevisionCloud.Create.
- [Audit i produktit](KONTROLLI-PRODUKTIT-20261115.md), [historiku](BIM-LINK-HISTORIKU.md).

## 2026-11-16 - Product language and project archive

User decisions: English is the base product language for international clients. Project files must provide folder navigation and storage for all project documentation, including files that are not deliverables. The user confirmed this interpretation.

Prototype: English navigation, statuses, descriptions, sample names and accessibility labels; Redline review replaces Copie rosse. Project files includes browsable folders, breadcrumbs, file details and links to deliverable inputs/outputs. Documentation remains the deliverable register and work/review history. Files should have one version history, referenced by deliverables instead of duplicated.

Scope: interactive sample-data design preview only. Real uploads, file content storage, permission enforcement and integrations are not implemented in this preview. Core application, Revit, Drive and driver are unchanged.
## 2026-11-16 - Model workspace and navigation feedback

User requested a separate 3D Models section, icons beside navigation items, a collapsible left menu, and plus/minus controls with distinct open/closed folder graphics.

The design preview now includes model cards, an illustrative model workspace with Whole building / Ground floor views, links to source files and related deliverables, inline navigation icons, a collapsed icon rail, and a hierarchical folder browser. Only folders with child folders have expand/collapse controls; selected folders are highlighted and use an open folder icon. Actual model loading and navigation remain unimplemented in this sample-data concept.
## 2026-11-16 - Multi-model opening and viewer chat

User direction: preserve the NEW proposed graphic style, reuse the old web model-opening workflow, allow multiple models to open together, and show chat on the right when the viewer opens.

Verified old source: Dashboard.jsx openFederated builds viewerFiles from selected IDs; toggleSceneModel adds/removes files while the viewer is open. Viewer.jsx accepts a files array and separately maintains an active model/chat context.

Prototype update: checkboxes and Open 3D for multiple sample models; live sample-scene add/remove controls; automatic right-hand chat with explicit project/model context (stacked below on narrow screens). Chat sending and real BIM model loading remain unimplemented. Existing application code is unchanged.
## 2026-11-16 - Requested role hierarchy and cross-team sharing

User requests: new folder operations; ordinary users limited to selected access paths; a proposed set of core web functions; a hierarchy of roles/capabilities; and separate Architecture/Structure/other teams able to edit their own folders and share selected models for viewing across teams.

Design proposal saved in ROLET-DHE-BASHKEPUNIMI-20261116.md. Role capability, team membership and folder grants are separate. Proposed defaults use internal working content and explicitly published shared versions, without duplicate file histories. Formal approval is separately assigned. This is a proposal, not implemented security or approval of every suggested role/policy.
## 2026-11-16 - Scalable model list and access groups

User approved replacing large model cards with a compact list and requested grouping between models the user works on and those shared for coordination.

Prototype now uses 20 sample models grouped as Working models (assigned to the example Architecture team) and Coordination models (published by other teams), with source team and View/Review/Edit labels. Search, building/discipline filters, select-filtered and cross-filter selection support opening both groups together. Viewer model controls are grouped in a bounded collapsible panel; chat remains on the right. Access badges are design examples, not server-enforced authorization.

Production grouping must use assigned work and effective resource grants, not filenames or discipline alone. Membership can span teams; avoid duplicate model rows and give the working classification precedence when a user has both work and coordination relationships to the same model.
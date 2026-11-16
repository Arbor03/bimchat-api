# BIMChat — Roles, teams and project access

Design proposal · 16 November 2026 · Not implemented authorization behavior.

The user requested an international product, project folders, access limited to selected paths, and collaboration between discipline teams. English is the base interface language. This document develops those requirements; the proposed role names, defaults and permission rules are not yet approved as a complete specification.

## 1. Structure

Organization → Project → Teams → Folders and files.

Deliverables reference file versions. Models reference source files. Tasks, discussions and reviews belong to an explicit project, model or deliverable context and audience.

An account can participate in multiple projects and teams, including projects owned by other organizations. Project membership does not automatically grant access to every project file. Discipline (Architecture, Structure, MEP) and company are attributes, not permission levels.

The effective authorization decision combines role capability, resource scope and relevant team/individual grants. A person may lead Architecture and have only View access to Structure's shared models in the same project.

## 2. Proposed role presets

| Role | Scope | Main capabilities | Boundary |
| --- | --- | --- | --- |
| Organization Owner | Organization administration | Create projects, appoint project administrators, manage organization membership and organization settings | Not a daily modeling role. Separate from project content grants and private conversations. Billing, if introduced, belongs here. |
| Project Admin | Assigned project | Configure teams, folder structure, project access, invitations, deliverable workflows and project records | Explicit broad project-document authority. Does not imply access to private direct messages or other projects. |
| Team Lead | Assigned team and managed folders | Organize team folders, assign work, manage deliverables, publish selected versions for coordination and share View/Review within project policy | Cannot grant access to another team's private material or exceed delegated sharing authority. Adding editors or external guests follows project policy. |
| Contributor | Assigned work areas | Create subfolders, upload files/new versions, prepare deliverables, edit assigned work, resolve review tasks and participate in permitted conversations | Cannot change team access or issue approved material merely because they can upload it. |
| Reviewer | Assigned review scope | View materials, create markups/comments, request changes, verify responses | Cannot modify the source model. Formal approval requires separate assignment as approver for the deliverable. |
| Viewer | Assigned viewing scope | Browse allowed folders, view permitted files/models and issued deliverables | No upload, source edit or review action by default. Download/export is separately configurable. |

Keep invitation UI short: team, allowed folder(s), access level. Present advanced role controls only to administrators/leads.

## 3. Folder access levels

- **View**: browse allowed content and open supported previews/models.
- **Review**: View plus review comments, markups and review-response workflow. Review attachments belong to the review; this is not permission to upload arbitrary source files.
- **Edit**: View plus working files, new versions and subfolders. Draft rename and recoverable deletion rules must respect authorship and folder scope. Published revisions remain immutable.
- **Manage**: organize the controlled subtree, configure its grants and perform structural operations according to project policy.
- **Download/export**: separately selectable on content the person can otherwise access.

Ordinary users should not see inaccessible folders, sibling names, document counts, search results or related activity. The sidebar starts at their allowed paths. An explicitly shared individual model can appear under Shared with me without exposing its parent folder.

Default access inheritance follows the parent folder. Restricted areas may deliberately stop inheritance; the UI must show that clearly. Applicable direct and group grants are additive within the selected scope, while the role still limits available actions. Before restricting/revoking access, show any remaining access from another team or direct grant; do not imply one grant removal revokes all access.

Actual authorization must be enforced by the server for files, model data, versions, search, activity, comments and downloads. Hiding UI controls alone is not access control. Requests must check project and resource identity rather than trusting a client-supplied folder path.

## 4. Architecture / Structure example

| Area | Architecture team | Structure team | Client reviewer |
| --- | --- | --- | --- |
| Architecture / Working | Edit | No access | No access |
| Architecture / Shared | Edit through publication workflow | View, or Review when requested | Only specifically assigned items |
| Structure / Working | No access | Edit | No access |
| Structure / Shared | View, or Review when requested | Edit through publication workflow | Only specifically assigned items |
| Issued deliverables | View according to scope | View according to scope | View/Review for assigned packages |

Working and Shared are suggested defaults, not fixed discipline names. Team and folder templates are configurable.

Sharing workflow:

1. Architecture prepares a model in its working area.
2. An authorized lead selects a version and chooses Share with team → Structure → View or Review.
3. Structure sees the shared model under Shared with me and can combine it with its own models in 3D Models.
4. Structure cannot edit Architecture's source. If Review was granted, comments and tasks reference the exact shared version and the intended audience.
5. The next internal save stays internal. A newly published coordination version can be announced to the receiving team.

For coordination, default to the latest explicitly published version, with change notifications. For a formal review or issued package, pin an exact version/revision. A review must not silently switch to a newer model while comments still refer to the old geometry.

Sharing uses references to canonical files/versions; it should not create duplicate files with separate histories. Show Shared with on the sender's side and Shared with me on the recipient's side. Revocation removes future online access after accounting for other grants; it cannot retract previously downloaded files.

## 5. Folder management experience

Primary actions: New folder, Upload files and Search. Context menu: Rename, Move, Copy link, Manage access and Move to trash, filtered by capability.

New folder defaults to its parent's access and displays that inheritance before creation. Manage access supports teams and named users, View/Review/Edit levels, optional download/export, and a clear effective-access summary. Invitations can start at one or more allowed folders rather than the full project root.

Move and rename preserve stable file/folder identities and deliverable links. A move that changes effective access requires an explicit access-impact preview. Deletion is recoverable and must not silently erase files referenced by official issued packages.

## 6. Recommended functional scope

### Foundation

1. Project/team invitation and scoped onboarding; role-aware home page.
2. Folder creation, upload, rename/move, access management and trash/restore.
3. File version history, upload progress, retry and clear completion states.
4. Search by filename, code, model, assignee, discipline, status and date, filtered by access.
5. Multi-model opening, add/remove/show/hide controls, explicit model context and side chat.
6. Deliverable register, inputs/outputs, work status, assignee, reviewer and due date.
7. Version-linked redline review → task → response → verification → formal approval/issue.
8. Contextual notifications, unread activity and audit history with audience filtering.

### Next stage

9. Saved coordination views and reusable model selections.
10. Downloadable issued packages with revision register and recipient/delivery history.
11. Project/folder/deliverable templates.
12. Controlled external guest invitations, expiry and access review.
13. Bulk operations and comparisons between file/model/drawing versions where supported.

Keep common actions visible and place uncommon administration in contextual menus. Revit/Drive sync health is operational status and must not be confused with a deliverable's approval or issue status.

## 7. Validation before implementation

- A Structure user can open the shared Architecture model alongside their own, but cannot enumerate or retrieve Architecture's working files.
- A restricted guest sees only the assigned folder and authorized related activity, including when using direct links.
- A reviewer can mark up a pinned revision without editing source files or publishing another revision.
- Removing one team grant reports any remaining direct/team access accurately.
- Moving a folder preserves links and previews any change in audience.
- A new model version does not reassign historical tasks or markups to the wrong version.
- Revoked access is rechecked for file/model delivery, search, notifications and existing sessions.

The deployed design preview currently demonstrates navigation, folders, sample file details, model selection and illustrative chat. Real storage, sharing enforcement, invitations, model loading and messaging require implementation and validation.

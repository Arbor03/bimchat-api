-- Additive migration. Run explicitly; never from an HTTP handler or app startup.
CREATE SCHEMA IF NOT EXISTS bimchat_archive;
CREATE TABLE IF NOT EXISTS bimchat_archive.projects (
 project_id integer PRIMARY KEY REFERENCES public.projects(id) ON DELETE CASCADE,
 revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
 folders jsonb NOT NULL DEFAULT '[]'::jsonb,
 retired_paths jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE TABLE IF NOT EXISTS bimchat_archive.devices (
 id uuid PRIMARY KEY,
 user_email text NOT NULL,
 secret_hash text NOT NULL,
 name text NOT NULL,
 protocol integer NOT NULL CHECK (protocol = 1),
 last_seen timestamptz NOT NULL DEFAULT now(),
 revoked boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS archive_device_owner ON bimchat_archive.devices(user_email);
CREATE TABLE IF NOT EXISTS bimchat_archive.device_projects (
 device_id uuid NOT NULL REFERENCES bimchat_archive.devices(id) ON DELETE CASCADE,
 project_id integer NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
 revision integer NOT NULL DEFAULT 1,
 preferences jsonb NOT NULL DEFAULT '[]'::jsonb,
 offered_token text,
 applied_token text,
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','conflict')),
 applied_at timestamptz,
 PRIMARY KEY(device_id,project_id)
);
CREATE TABLE IF NOT EXISTS bimchat_archive.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 project_id integer NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
 actor_email text NOT NULL,
 action text NOT NULL,
 folder_id uuid,
 revision integer NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);

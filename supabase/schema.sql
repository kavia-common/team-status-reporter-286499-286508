-- Team Status Reporter - Supabase/PostgreSQL Schema
-- Idempotent, safe to re-run. Uses Supabase auth.uid() where appropriate.

-- ===========================================================
-- 1) Extensions
-- ===========================================================
-- gen_random_uuid() preferred. Available via pgcrypto in Supabase.
create extension if not exists "pgcrypto";
-- Optional: uuid-ossp (not required if pgcrypto is present)
create extension if not exists "uuid-ossp";

-- ===========================================================
-- 2) Custom ENUM types
-- ===========================================================
-- report_status ENUM: ('draft','submitted','reviewed','archived')
do $$
begin
  if not exists (select 1 from pg_type where typname = 'report_status') then
    create type public.report_status as enum ('draft','submitted','reviewed','archived');
  end if;
  -- Ensure all values exist (idempotent)
  alter type public.report_status add value if not exists 'draft';
  alter type public.report_status add value if not exists 'submitted';
  alter type public.report_status add value if not exists 'reviewed';
  alter type public.report_status add value if not exists 'archived';
end
$$;

-- export_format ENUM: ('pdf','xlsx')
do $$
begin
  if not exists (select 1 from pg_type where typname = 'export_format') then
    create type public.export_format as enum ('pdf','xlsx');
  end if;
  alter type public.export_format add value if not exists 'pdf';
  alter type public.export_format add value if not exists 'xlsx';
end
$$;

-- ===========================================================
-- 3) Core tables
-- ===========================================================
-- Notes:
-- - All created in public schema.
-- - app_users.id maps 1:1 to auth.users.id (no FK across schemas to avoid privilege complexity).
-- - Use gen_random_uuid() defaults where requested.

-- app_users
create table if not exists public.app_users (
  id uuid primary key, -- maps to auth.users.id
  email text unique not null,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- teams
create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- team_memberships
create table if not exists public.team_memberships (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams(id) on delete cascade,
  user_id uuid not null references public.app_users(id) on delete cascade,
  role text not null check (role in ('member','manager','admin')),
  unique (team_id, user_id)
);

-- weekly_reports
create table if not exists public.weekly_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.app_users(id) on delete cascade,
  team_id uuid references public.teams(id) on delete set null,
  week_start date not null,
  week_end date not null,
  status public.report_status not null default 'draft',
  title text,
  content jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  submitted_at timestamptz,
  reviewed_at timestamptz,
  reviewer_id uuid references public.app_users(id) on delete set null,
  unique (user_id, week_start, week_end)
);

-- ai_summaries
create table if not exists public.ai_summaries (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.weekly_reports(id) on delete cascade,
  model text,
  prompt text,
  summary text,
  metadata jsonb default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (report_id)
);

-- exports
create table if not exists public.exports (
  id uuid primary key default gen_random_uuid(),
  report_id uuid references public.weekly_reports(id) on delete cascade,
  team_id uuid references public.teams(id) on delete cascade,
  requested_by uuid references public.app_users(id) on delete set null,
  format public.export_format not null,
  status text not null check (status in ('queued','success','failed')),
  file_path text,
  error text,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

-- activity_logs
create table if not exists public.activity_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references public.app_users(id) on delete set null,
  team_id uuid references public.teams(id) on delete set null,
  report_id uuid references public.weekly_reports(id) on delete set null,
  action text not null,
  details jsonb default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- ===========================================================
-- 4) Indexes
-- ===========================================================
-- weekly_reports
create index if not exists idx_weekly_reports_user_week on public.weekly_reports (user_id, week_start, week_end);
create index if not exists idx_weekly_reports_team on public.weekly_reports (team_id);
create index if not exists idx_weekly_reports_status on public.weekly_reports (status);
create index if not exists idx_weekly_reports_content_gin on public.weekly_reports using gin (content);

-- team_memberships
create index if not exists idx_team_memberships_user on public.team_memberships (user_id);
create index if not exists idx_team_memberships_team on public.team_memberships (team_id);

-- ai_summaries
create index if not exists idx_ai_summaries_report on public.ai_summaries (report_id);

-- exports
create index if not exists idx_exports_report on public.exports (report_id);
create index if not exists idx_exports_team on public.exports (team_id);
create index if not exists idx_exports_status on public.exports (status);

-- activity_logs
create index if not exists idx_activity_logs_actor on public.activity_logs (actor_id);
create index if not exists idx_activity_logs_report on public.activity_logs (report_id);
create index if not exists idx_activity_logs_team on public.activity_logs (team_id);

-- ===========================================================
-- 5) Triggers to auto-update updated_at
-- ===========================================================
create or replace function public.fn_set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Helper to create trigger if not exists
do $$
begin
  if not exists (select 1 from pg_trigger where tgname = 'trg_app_users_set_updated_at') then
    create trigger trg_app_users_set_updated_at
      before update on public.app_users
      for each row
      execute function public.fn_set_updated_at();
  end if;

  if not exists (select 1 from pg_trigger where tgname = 'trg_teams_set_updated_at') then
    create trigger trg_teams_set_updated_at
      before update on public.teams
      for each row
      execute function public.fn_set_updated_at();
  end if;

  if not exists (select 1 from pg_trigger where tgname = 'trg_weekly_reports_set_updated_at') then
    create trigger trg_weekly_reports_set_updated_at
      before update on public.weekly_reports
      for each row
      execute function public.fn_set_updated_at();
  end if;
end
$$;

-- ===========================================================
-- 7) Helper functions for role checks
-- ===========================================================
-- Checks if current user is a manager (manager or admin) of the specified team
create or replace function public.fn_is_team_manager(p_team_id uuid)
returns boolean
language sql
stable
as $$
  select exists (
    select 1
    from public.team_memberships tm
    where tm.team_id = p_team_id
      and tm.user_id = auth.uid()
      and tm.role in ('manager','admin')
  );
$$;

-- Checks if current user is an admin of the specified team
create or replace function public.fn_is_team_admin(p_team_id uuid)
returns boolean
language sql
stable
as $$
  select exists (
    select 1
    from public.team_memberships tm
    where tm.team_id = p_team_id
      and tm.user_id = auth.uid()
      and tm.role = 'admin'
  );
$$;

-- ===========================================================
-- 8) Convenience sync function for app_users
-- ===========================================================
-- Upserts the current authenticated user into app_users using auth.uid() and auth.email().
-- SECURITY DEFINER is used to allow insert despite RLS restrictions on app_users.
create or replace function public.fn_sync_app_user()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_email text;
  v_display_name text;
begin
  -- In Supabase, auth.email() returns the JWT email claim where available.
  begin
    v_email := auth.email();
  exception when others then
    v_email := null;
  end;

  if v_email is null then
    -- last resort: keep email blank if unavailable
    v_email := '';
  end if;

  v_display_name := nullif(split_part(v_email, '@', 1), '');

  insert into public.app_users (id, email, display_name)
  values (v_uid, v_email, coalesce(v_display_name, v_email))
  on conflict (id) do update
    set email = excluded.email,
        display_name = coalesce(excluded.display_name, public.app_users.display_name),
        updated_at = now();
end;
$$;

-- Grant execute on the sync function to authenticated users
do $$
begin
  grant execute on function public.fn_sync_app_user() to authenticated;
exception when others then
  -- ignore if role doesn't exist
  null;
end
$$;

-- ===========================================================
-- 6) Basic RLS setup and policies (Supabase compatible)
-- ===========================================================
-- Enable RLS on all tables that require it
alter table if exists public.app_users enable row level security;
alter table if exists public.teams enable row level security;
alter table if exists public.team_memberships enable row level security;
alter table if exists public.weekly_reports enable row level security;
alter table if exists public.ai_summaries enable row level security;
alter table if exists public.exports enable row level security;
alter table if exists public.activity_logs enable row level security;

-- app_users policies
do $$
begin
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='app_users' and policyname='select_own_app_user') then
    create policy "select_own_app_user"
      on public.app_users
      for select
      to authenticated
      using (id = auth.uid());
  end if;

  if not exists (select 1 from pg_policies where schemaname='public' and tablename='app_users' and policyname='update_own_app_user') then
    create policy "update_own_app_user"
      on public.app_users
      for update
      to authenticated
      using (id = auth.uid())
      with check (id = auth.uid());
  end if;

  -- Insert restricted to service_role (backend)
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='app_users' and policyname='insert_app_user_service') then
    create policy "insert_app_user_service"
      on public.app_users
      for insert
      to service_role
      with check (true);
  end if;
end
$$;

-- teams policies
do $$
begin
  -- Members can select teams they belong to
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='teams' and policyname='select_team_members') then
    create policy "select_team_members"
      on public.teams
      for select
      to authenticated
      using (
        exists (
          select 1 from public.team_memberships tm
          where tm.team_id = teams.id
            and tm.user_id = auth.uid()
        )
      );
  end if;

  -- Admins/Managers can insert/update teams
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='teams' and policyname='insert_teams_manager_or_admin') then
    create policy "insert_teams_manager_or_admin"
      on public.teams
      for insert
      to authenticated
      with check (
        -- Allow if user is currently a manager/admin of any existing team
        exists (
          select 1 from public.team_memberships tm
          where tm.user_id = auth.uid()
            and tm.role in ('manager','admin')
        )
      );
  end if;

  if not exists (select 1 from pg_policies where schemaname='public' and tablename='teams' and policyname='update_teams_manager_or_admin') then
    create policy "update_teams_manager_or_admin"
      on public.teams
      for update
      to authenticated
      using (public.fn_is_team_manager(teams.id) or public.fn_is_team_admin(teams.id))
      with check (public.fn_is_team_manager(teams.id) or public.fn_is_team_admin(teams.id));
  end if;

  -- Deletes restricted to admins
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='teams' and policyname='delete_teams_admin_only') then
    create policy "delete_teams_admin_only"
      on public.teams
      for delete
      to authenticated
      using (public.fn_is_team_admin(teams.id));
  end if;
end
$$;

-- team_memberships policies
do $$
begin
  -- Users can select their own membership rows; managers/admins can see/manage team memberships
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='team_memberships' and policyname='select_team_memberships_owner_or_manager') then
    create policy "select_team_memberships_owner_or_manager"
      on public.team_memberships
      for select
      to authenticated
      using (
        user_id = auth.uid()
        or public.fn_is_team_manager(team_id)
        or public.fn_is_team_admin(team_id)
      );
  end if;

  -- Managers/admins can insert memberships for their team
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='team_memberships' and policyname='insert_team_memberships_manager_admin') then
    create policy "insert_team_memberships_manager_admin"
      on public.team_memberships
      for insert
      to authenticated
      with check (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id));
  end if;

  -- Managers/admins can update memberships for their team
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='team_memberships' and policyname='update_team_memberships_manager_admin') then
    create policy "update_team_memberships_manager_admin"
      on public.team_memberships
      for update
      to authenticated
      using (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id))
      with check (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id));
  end if;

  -- Managers/admins can delete memberships for their team
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='team_memberships' and policyname='delete_team_memberships_manager_admin') then
    create policy "delete_team_memberships_manager_admin"
      on public.team_memberships
      for delete
      to authenticated
      using (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id));
  end if;
end
$$;

-- weekly_reports policies
do $$
begin
  -- Owner or team managers can select
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='weekly_reports' and policyname='select_weekly_reports_owner_or_manager') then
    create policy "select_weekly_reports_owner_or_manager"
      on public.weekly_reports
      for select
      to authenticated
      using (
        user_id = auth.uid()
        or (team_id is not null and public.fn_is_team_manager(team_id))
        or (team_id is not null and public.fn_is_team_admin(team_id))
      );
  end if;

  -- Owner can insert their own reports
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='weekly_reports' and policyname='insert_weekly_reports_owner') then
    create policy "insert_weekly_reports_owner"
      on public.weekly_reports
      for insert
      to authenticated
      with check (user_id = auth.uid());
  end if;

  -- Owner can update but cannot set status to 'reviewed'
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='weekly_reports' and policyname='update_weekly_reports_owner_no_review') then
    create policy "update_weekly_reports_owner_no_review"
      on public.weekly_reports
      for update
      to authenticated
      using (user_id = auth.uid())
      with check (user_id = auth.uid() and status <> 'reviewed');
  end if;

  -- Managers can update (e.g., mark as reviewed)
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='weekly_reports' and policyname='update_weekly_reports_manager') then
    create policy "update_weekly_reports_manager"
      on public.weekly_reports
      for update
      to authenticated
      using (team_id is not null and public.fn_is_team_manager(team_id))
      with check (true);
  end if;

  -- Owner can delete only if draft
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='weekly_reports' and policyname='delete_weekly_reports_owner_draft') then
    create policy "delete_weekly_reports_owner_draft"
      on public.weekly_reports
      for delete
      to authenticated
      using (user_id = auth.uid() and status = 'draft');
  end if;
end
$$;

-- ai_summaries policies
do $$
begin
  -- Owner of report OR team managers can select
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='ai_summaries' and policyname='select_ai_summaries_owner_or_manager') then
    create policy "select_ai_summaries_owner_or_manager"
      on public.ai_summaries
      for select
      to authenticated
      using (
        exists (
          select 1 from public.weekly_reports wr
          where wr.id = ai_summaries.report_id
            and (wr.user_id = auth.uid() or (wr.team_id is not null and (public.fn_is_team_manager(wr.team_id) or public.fn_is_team_admin(wr.team_id))))
        )
      );
  end if;

  -- Insert by service role or owner of report
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='ai_summaries' and policyname='insert_ai_summaries_owner_or_service') then
    create policy "insert_ai_summaries_owner_or_service"
      on public.ai_summaries
      for insert
      to authenticated
      with check (
        exists (
          select 1 from public.weekly_reports wr
          where wr.id = ai_summaries.report_id
            and wr.user_id = auth.uid()
        )
      );
  end if;

  -- Allow service role unrestricted insert/update/delete
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='ai_summaries' and policyname='service_ai_summaries_all') then
    create policy "service_ai_summaries_all"
      on public.ai_summaries
      for all
      to service_role
      using (true)
      with check (true);
  end if;

  -- Update by owner (non-service)
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='ai_summaries' and policyname='update_ai_summaries_owner') then
    create policy "update_ai_summaries_owner"
      on public.ai_summaries
      for update
      to authenticated
      using (
        exists (
          select 1 from public.weekly_reports wr
          where wr.id = ai_summaries.report_id
            and wr.user_id = auth.uid()
        )
      )
      with check (true);
  end if;

  -- Delete restricted to service role already covered by service_ai_summaries_all
end
$$;

-- exports policies
do $$
begin
  -- Requester and team managers can select
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='exports' and policyname='select_exports_requester_or_manager') then
    create policy "select_exports_requester_or_manager"
      on public.exports
      for select
      to authenticated
      using (
        requested_by = auth.uid()
        or (team_id is not null and (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id)))
        or (
          report_id is not null and exists (
            select 1 from public.weekly_reports wr
            where wr.id = exports.report_id
              and (wr.user_id = auth.uid() or (wr.team_id is not null and (public.fn_is_team_manager(wr.team_id) or public.fn_is_team_admin(wr.team_id))))
          )
        )
      );
  end if;

  -- Insert by requester (requested_by = auth.uid())
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='exports' and policyname='insert_exports_requester') then
    create policy "insert_exports_requester"
      on public.exports
      for insert
      to authenticated
      with check (requested_by = auth.uid());
  end if;

  -- Update by service role (e.g., status, file_path)
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='exports' and policyname='update_exports_service') then
    create policy "update_exports_service"
      on public.exports
      for update
      to service_role
      using (true)
      with check (true);
  end if;

  -- Delete restricted to service role (safety)
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='exports' and policyname='delete_exports_service') then
    create policy "delete_exports_service"
      on public.exports
      for delete
      to service_role
      using (true);
  end if;
end
$$;

-- activity_logs policies
do $$
begin
  -- Actors and team managers can select
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='activity_logs' and policyname='select_activity_logs_actor_or_manager') then
    create policy "select_activity_logs_actor_or_manager"
      on public.activity_logs
      for select
      to authenticated
      using (
        actor_id = auth.uid()
        or (team_id is not null and (public.fn_is_team_manager(team_id) or public.fn_is_team_admin(team_id)))
        or (
          report_id is not null and exists (
            select 1 from public.weekly_reports wr
            where wr.id = activity_logs.report_id
              and (wr.user_id = auth.uid() or (wr.team_id is not null and (public.fn_is_team_manager(wr.team_id) or public.fn_is_team_admin(wr.team_id))))
          )
        )
      );
  end if;

  -- Insert by service role or backend only
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='activity_logs' and policyname='insert_activity_logs_service') then
    create policy "insert_activity_logs_service"
      on public.activity_logs
      for insert
      to service_role
      with check (true);
  end if;
end
$$;

-- ===========================================================
-- 9) Notes
-- ===========================================================
-- - This script is idempotent and safe to re-run.
-- - Use public.fn_sync_app_user() after user sign-in to ensure app_users row exists.
-- - Policies prefer auth.uid() for identity mapping to app_users.id.
-- - Triggers maintain updated_at fields automatically.
-- - Indexes added for performance on common query patterns.

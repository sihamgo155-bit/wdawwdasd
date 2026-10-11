-- CIA Roleplay V2 schema and Row Level Security.
-- Run this in Supabase Dashboard -> SQL Editor.
-- IMPORTANT: after creating your first account, promote it to admin using the one-time SQL
-- statement in README.md. Do not expose service_role keys in browser code.

create extension if not exists pgcrypto;

do $$ begin
  create type public.app_role as enum ('member','staff','admin');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type public.application_status as enum ('pending','accepted','rejected');
exception when duplicate_object then null;
end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role public.app_role not null default 'member',
  created_at timestamptz not null default now()
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  nickname text not null check (char_length(nickname) between 2 and 40),
  discord_username text check (discord_username is null or char_length(discord_username) <= 80),
  age_bracket text not null check (age_bracket in ('Under 16','16–17','18+','Prefer not to say')),
  preferred_role text not null check (preferred_role in ('Recruit','Analyst','Operations','Administration')),
  motivation text not null check (char_length(motivation) between 20 and 700),
  status public.application_status not null default 'pending',
  created_at timestamptz not null default now()
);

create table if not exists public.missions (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 2 and 120),
  description text not null check (char_length(description) between 2 and 1000),
  priority text not null default 'normal' check (priority in ('low','normal','high')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.case_files (
  id uuid primary key default gen_random_uuid(),
  case_code text not null unique check (char_length(case_code) between 2 and 40),
  title text not null check (char_length(title) between 2 and 120),
  description text not null check (char_length(description) between 2 and 1000),
  classification text not null default 'RESTRICTED' check (classification in ('RESTRICTED','CONFIDENTIAL','TOP SECRET (FICTIONAL)')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 2 and 120),
  body text not null check (char_length(body) between 2 and 1200),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists applications_user_id_created_idx on public.applications(user_id, created_at desc);
create index if not exists applications_status_idx on public.applications(status);
create index if not exists missions_created_idx on public.missions(created_at desc);
create index if not exists case_files_created_idx on public.case_files(created_at desc);
create index if not exists announcements_created_idx on public.announcements(created_at desc);

-- Automatically create a member profile when a user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'member')
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- SECURITY DEFINER helper prevents role-policy recursion. Only trusted admins may manage records.
create or replace function public.has_role(required_roles public.app_role[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = any(required_roles)
  );
$$;
revoke all on function public.has_role(public.app_role[]) from public;
grant execute on function public.has_role(public.app_role[]) to authenticated;

alter table public.profiles enable row level security;
alter table public.applications enable row level security;
alter table public.missions enable row level security;
alter table public.case_files enable row level security;
alter table public.announcements enable row level security;

-- Profiles: users can read only their own profile; admins can read all. No client can change role.
drop policy if exists "profile_select_self_or_admin" on public.profiles;
create policy "profile_select_self_or_admin" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or public.has_role(array['admin']::public.app_role[]));

drop policy if exists "profile_update_self_email_only_not_role" on public.profiles;
-- Do not create a client UPDATE policy on profiles: role/email changes are handled by trusted server/admin SQL.

-- Applications: members create and read only their own. Admin/staff can review; only admin/staff may update status.
drop policy if exists "applications_insert_own_pending" on public.applications;
create policy "applications_insert_own_pending" on public.applications
for insert to authenticated
with check (user_id = (select auth.uid()) and status = 'pending');

drop policy if exists "applications_select_own_or_staff" on public.applications;
create policy "applications_select_own_or_staff" on public.applications
for select to authenticated
using (user_id = (select auth.uid()) or public.has_role(array['staff','admin']::public.app_role[]));

drop policy if exists "applications_update_staff_admin" on public.applications;
create policy "applications_update_staff_admin" on public.applications
for update to authenticated
using (public.has_role(array['staff','admin']::public.app_role[]))
with check (public.has_role(array['staff','admin']::public.app_role[]));

-- No delete policy for applications by default; delete through trusted SQL/admin process if required.

-- Roleplay content: signed-in members may read; only staff/admin can publish.
drop policy if exists "missions_select_authenticated" on public.missions;
create policy "missions_select_authenticated" on public.missions
for select to authenticated using (true);
drop policy if exists "missions_insert_staff_admin" on public.missions;
create policy "missions_insert_staff_admin" on public.missions
for insert to authenticated with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "missions_update_staff_admin" on public.missions;
create policy "missions_update_staff_admin" on public.missions
for update to authenticated using (public.has_role(array['staff','admin']::public.app_role[]))
with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "missions_delete_admin" on public.missions;
create policy "missions_delete_admin" on public.missions
for delete to authenticated using (public.has_role(array['admin']::public.app_role[]));

drop policy if exists "cases_select_authenticated" on public.case_files;
create policy "cases_select_authenticated" on public.case_files
for select to authenticated using (true);
drop policy if exists "cases_insert_staff_admin" on public.case_files;
create policy "cases_insert_staff_admin" on public.case_files
for insert to authenticated with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "cases_update_staff_admin" on public.case_files;
create policy "cases_update_staff_admin" on public.case_files
for update to authenticated using (public.has_role(array['staff','admin']::public.app_role[]))
with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "cases_delete_admin" on public.case_files;
create policy "cases_delete_admin" on public.case_files
for delete to authenticated using (public.has_role(array['admin']::public.app_role[]));

drop policy if exists "announcements_select_authenticated" on public.announcements;
create policy "announcements_select_authenticated" on public.announcements
for select to authenticated using (true);
drop policy if exists "announcements_insert_staff_admin" on public.announcements;
create policy "announcements_insert_staff_admin" on public.announcements
for insert to authenticated with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "announcements_update_staff_admin" on public.announcements;
create policy "announcements_update_staff_admin" on public.announcements
for update to authenticated using (public.has_role(array['staff','admin']::public.app_role[]))
with check (public.has_role(array['staff','admin']::public.app_role[]));
drop policy if exists "announcements_delete_admin" on public.announcements;
create policy "announcements_delete_admin" on public.announcements
for delete to authenticated using (public.has_role(array['admin']::public.app_role[]));

-- Grant API table access; RLS policies above restrict the actual rows/actions.
grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update on public.applications to authenticated;
grant select, insert, update, delete on public.missions to authenticated;
grant select, insert, update, delete on public.case_files to authenticated;
grant select, insert, update, delete on public.announcements to authenticated;

-- The profiles table intentionally has no client insert/update/delete grants.

-- CIA Roleplay V2.1: access-code portal and code-managed applications.
-- The frontend never receives privileged database keys. All management is performed by RPCs.
create table if not exists public.rp_access_codes (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  rank text not null default 'member' check (rank in ('member','recruit','analyst','operations','staff','admin')),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  check (char_length(code) between 4 and 32)
);
create table if not exists public.rp_applications (
  id uuid primary key default gen_random_uuid(),
  access_code_id uuid not null references public.rp_access_codes(id) on delete restrict,
  nickname text not null check (char_length(nickname) between 2 and 40),
  discord_username text check (discord_username is null or char_length(discord_username) <= 80),
  age_bracket text not null check (age_bracket in ('Under 16','16–17','18+','Prefer not to say')),
  preferred_role text not null check (preferred_role in ('Recruit','Analyst','Operations','Administration')),
  motivation text not null check (char_length(motivation) between 20 and 700),
  score integer not null check (score between 0 and 5),
  status text not null default 'pending' check (status in ('pending','accepted','rejected')),
  created_at timestamptz not null default now()
);
alter table public.rp_access_codes enable row level security;
alter table public.rp_applications enable row level security;
revoke all on public.rp_access_codes from anon, authenticated;
revoke all on public.rp_applications from anon, authenticated;
insert into public.rp_access_codes(code,rank,active) values ('1937','admin',true)
on conflict (code) do update set rank='admin', active=true;

create or replace function public.rp_enter(p_code text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare c public.rp_access_codes%rowtype;
begin
  select * into c from public.rp_access_codes where code = upper(trim(p_code)) and active = true;
  if not found then return jsonb_build_object('valid',false); end if;
  return jsonb_build_object('valid',true,'rank',c.rank);
end; $$;

create or replace function public.rp_submit_application(p_code text,p_nickname text,p_discord text,p_age_bracket text,p_preferred_role text,p_motivation text,p_score integer)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare c public.rp_access_codes%rowtype;
begin
  select * into c from public.rp_access_codes where code=upper(trim(p_code)) and active=true;
  if not found or c.rank in ('admin','staff') then return jsonb_build_object('ok',false,'message','كود العضو غير صالح.'); end if;
  if char_length(trim(p_nickname)) not between 2 and 40 or char_length(trim(p_motivation)) not between 20 and 700 or p_score not between 0 and 5 then
    return jsonb_build_object('ok',false,'message','تحقق من الاسم والأجوبة والنقطة.');
  end if;
  if p_age_bracket not in ('Under 16','16–17','18+','Prefer not to say') or p_preferred_role not in ('Recruit','Analyst','Operations','Administration') then
    return jsonb_build_object('ok',false,'message','اختيارات الاستمارة غير صالحة.');
  end if;
  insert into public.rp_applications(access_code_id,nickname,discord_username,age_bracket,preferred_role,motivation,score)
  values(c.id,trim(p_nickname),nullif(trim(coalesce(p_discord,'')),''),p_age_bracket,p_preferred_role,trim(p_motivation),p_score);
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.rp_my_application(p_code text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare c public.rp_access_codes%rowtype; a public.rp_applications%rowtype;
begin
  select * into c from public.rp_access_codes where code=upper(trim(p_code)) and active=true;
  if not found then return jsonb_build_object('found',false); end if;
  select * into a from public.rp_applications where access_code_id=c.id order by created_at desc limit 1;
  if not found then return jsonb_build_object('found',false); end if;
  return jsonb_build_object('found',true,'nickname',a.nickname,'preferred_role',a.preferred_role,'score',a.score,'status',a.status,'created_at',a.created_at);
end; $$;

create or replace function public.rp_assert_admin(p_admin_code text)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select exists(select 1 from public.rp_access_codes where code=upper(trim(p_admin_code)) and active=true and rank in ('admin','staff'));
$$;

create or replace function public.rp_admin_list_apps(p_admin_code text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',a.id,'nickname',a.nickname,'discord_username',a.discord_username,'preferred_role',a.preferred_role,'score',a.score,'status',a.status,'motivation',a.motivation,'created_at',a.created_at) order by a.created_at desc) from public.rp_applications a),'[]'::jsonb);
end; $$;

create or replace function public.rp_admin_set_status(p_admin_code text,p_application_id uuid,p_status text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  if p_status not in ('accepted','rejected','pending') then raise exception 'حالة غير صالحة.'; end if;
  update public.rp_applications set status=p_status where id=p_application_id;
  if not found then return jsonb_build_object('ok',false,'message','الطلب غير موجود.'); end if;
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.rp_admin_list_codes(p_admin_code text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',id,'code',code,'rank',rank,'active',active,'created_at',created_at) order by created_at desc) from public.rp_access_codes where code <> '1937'),'[]'::jsonb);
end; $$;

create or replace function public.rp_admin_create_code(p_admin_code text,p_new_code text,p_rank text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare clean_code text := upper(trim(p_new_code));
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  if char_length(clean_code) not between 4 and 32 or p_rank not in ('member','recruit','analyst','operations','staff','admin') then return jsonb_build_object('ok',false,'message','الكود أو الرتبة غير صالحة.'); end if;
  insert into public.rp_access_codes(code,rank) values(clean_code,p_rank);
  return jsonb_build_object('ok',true);
exception when unique_violation then return jsonb_build_object('ok',false,'message','هاد الكود موجود من قبل.');
end; $$;

create or replace function public.rp_admin_delete_code(p_admin_code text,p_code_id uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  if not exists(select 1 from public.rp_access_codes where id=p_code_id and code <> '1937') then return jsonb_build_object('ok',false,'message','مايمكنش تحذف الكود الرئيسي أو ما لقيناهش.'); end if;
  if exists(select 1 from public.rp_applications where access_code_id=p_code_id) then
    update public.rp_access_codes set active=false where id=p_code_id and code <> '1937';
  else
    delete from public.rp_access_codes where id=p_code_id and code <> '1937';
  end if;
  return jsonb_build_object('ok',true);
end; $$;

create or replace function public.rp_admin_update_rank(p_admin_code text,p_code_id uuid,p_rank text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.rp_assert_admin(p_admin_code) then raise exception 'صلاحية الإدارة غير صالحة.'; end if;
  if p_rank not in ('member','recruit','analyst','operations','staff','admin') then return jsonb_build_object('ok',false,'message','رتبة غير صالحة.'); end if;
  update public.rp_access_codes set rank=p_rank where id=p_code_id and code <> '1937';
  if not found then return jsonb_build_object('ok',false,'message','مايمكنش تبدل رتبة الكود الرئيسي.'); end if;
  return jsonb_build_object('ok',true);
end; $$;

grant execute on function public.rp_enter(text) to anon, authenticated;
grant execute on function public.rp_submit_application(text,text,text,text,text,text,integer) to anon, authenticated;
grant execute on function public.rp_my_application(text) to anon, authenticated;
grant execute on function public.rp_assert_admin(text) to anon, authenticated;
grant execute on function public.rp_admin_list_apps(text) to anon, authenticated;
grant execute on function public.rp_admin_set_status(text,uuid,text) to anon, authenticated;
grant execute on function public.rp_admin_list_codes(text) to anon, authenticated;
grant execute on function public.rp_admin_create_code(text,text,text) to anon, authenticated;
grant execute on function public.rp_admin_delete_code(text,uuid) to anon, authenticated;
grant execute on function public.rp_admin_update_rank(text,uuid,text) to anon, authenticated;

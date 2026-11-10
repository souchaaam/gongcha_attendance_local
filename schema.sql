-- Gong Cha attendance app: Supabase schema
-- Run this in Supabase SQL Editor. Then create an Auth user for the store administrator
-- and add that user's UUID to public.admin_users (instructions are in README.txt).

create extension if not exists pgcrypto;

create table if not exists public.employees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  active boolean not null default true,
  display_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.attendance_events (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id),
  event_type text not null check (event_type in ('clock_in','break_start','break_end','clock_out')),
  event_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  created_by uuid null references auth.users(id),
  note text not null default ''
);

create index if not exists attendance_events_event_at_idx on public.attendance_events(event_at desc);
create index if not exists attendance_events_employee_event_at_idx on public.attendance_events(employee_id, event_at desc);

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.attendance_audit_logs (
  id uuid primary key default gen_random_uuid(),
  event_id uuid,
  operation text not null check (operation in ('INSERT','UPDATE','DELETE')),
  old_data jsonb,
  new_data jsonb,
  changed_by uuid,
  changed_at timestamptz not null default now()
);

create or replace function public.is_attendance_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.admin_users where user_id = auth.uid()); $$;

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$ begin new.updated_at = now(); return new; end; $$;

drop trigger if exists employees_set_updated_at on public.employees;
create trigger employees_set_updated_at before update on public.employees
for each row execute function public.set_updated_at();

create or replace function public.log_attendance_change()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    insert into public.attendance_audit_logs(event_id, operation, new_data, changed_by)
    values (new.id, 'INSERT', to_jsonb(new), auth.uid());
    return new;
  elsif tg_op = 'UPDATE' then
    insert into public.attendance_audit_logs(event_id, operation, old_data, new_data, changed_by)
    values (new.id, 'UPDATE', to_jsonb(old), to_jsonb(new), auth.uid());
    return new;
  else
    insert into public.attendance_audit_logs(event_id, operation, old_data, changed_by)
    values (old.id, 'DELETE', to_jsonb(old), auth.uid());
    return old;
  end if;
end; $$;

drop trigger if exists attendance_events_audit on public.attendance_events;
create trigger attendance_events_audit after insert or update or delete on public.attendance_events
for each row execute function public.log_attendance_change();

alter table public.employees enable row level security;
alter table public.attendance_events enable row level security;
alter table public.admin_users enable row level security;
alter table public.attendance_audit_logs enable row level security;

drop policy if exists "active employees readable by kiosk" on public.employees;
create policy "active employees readable by kiosk" on public.employees
for select to anon, authenticated using (active = true or public.is_attendance_admin());

drop policy if exists "admins manage employees" on public.employees;
create policy "admins manage employees" on public.employees
for all to authenticated using (public.is_attendance_admin()) with check (public.is_attendance_admin());

drop policy if exists "today events readable by kiosk" on public.attendance_events;
create policy "today events readable by kiosk" on public.attendance_events
for select to anon, authenticated using (
  (event_at >= (date_trunc('day', now() at time zone 'Asia/Tokyo') at time zone 'Asia/Tokyo') and event_at < ((date_trunc('day', now() at time zone 'Asia/Tokyo') + interval '1 day') at time zone 'Asia/Tokyo'))
  or public.is_attendance_admin()
);

drop policy if exists "kiosk can add events" on public.attendance_events;
create policy "kiosk can add events" on public.attendance_events
for insert to anon, authenticated with check (true);

drop policy if exists "admins update events" on public.attendance_events;
create policy "admins update events" on public.attendance_events
for update to authenticated using (public.is_attendance_admin()) with check (public.is_attendance_admin());

drop policy if exists "admins delete events" on public.attendance_events;
create policy "admins delete events" on public.attendance_events
for delete to authenticated using (public.is_attendance_admin());

drop policy if exists "admins read own admin row" on public.admin_users;
create policy "admins read own admin row" on public.admin_users
for select to authenticated using (user_id = auth.uid());

drop policy if exists "admins read audit logs" on public.attendance_audit_logs;
create policy "admins read audit logs" on public.attendance_audit_logs
for select to authenticated using (public.is_attendance_admin());

-- Restrict table privileges; RLS policies further restrict row access.
grant usage on schema public to anon, authenticated;
grant select on public.employees to anon, authenticated;
grant insert, update, delete on public.employees to authenticated;
grant select, insert on public.attendance_events to anon, authenticated;
grant update, delete on public.attendance_events to authenticated;
grant select on public.admin_users to authenticated;
grant select on public.attendance_audit_logs to authenticated;

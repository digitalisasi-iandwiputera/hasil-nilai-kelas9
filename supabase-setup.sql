-- Run this script in the Supabase SQL Editor before deploying the portal HTML.
-- Create the listed admin email as a Supabase Auth user and disable public sign-ups.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.portal_admins (
    email text primary key check (email = lower(email))
);

insert into public.portal_admins (email)
values ('iandwi.putera@gmail.com')
on conflict (email) do nothing;

create table if not exists public.portal_settings (
    id boolean primary key default true check (id),
    school_name text not null default 'SMP Nusamandira',
    subject_name text not null default 'Informatika',
    academic_year text not null default '2026/2027',
    exam_title text not null default 'UTS Semester Ganjil'
);

insert into public.portal_settings (id) values (true) on conflict (id) do nothing;

create table if not exists public.classrooms (
    id uuid primary key default gen_random_uuid(),
    grade smallint not null check (grade between 7 and 9),
    name text not null check (length(trim(name)) between 1 and 50),
    access_code_hash text,
    unique (grade, name)
);

create unique index if not exists classrooms_grade_name_lower_idx
    on public.classrooms (grade, lower(name));

create table if not exists public.students (
    id uuid primary key default gen_random_uuid(),
    classroom_id uuid not null references public.classrooms(id) on delete restrict,
    name text not null check (length(trim(name)) between 1 and 150),
    score numeric(5, 2) not null check (score between 0 and 100),
    note text not null default '',
    unique (classroom_id, name)
);

create unique index if not exists students_classroom_name_lower_idx
    on public.students (classroom_id, lower(name));

alter table public.portal_admins enable row level security;
alter table public.portal_settings enable row level security;
alter table public.classrooms enable row level security;
alter table public.students enable row level security;

revoke all on public.portal_admins, public.portal_settings, public.classrooms, public.students from anon, authenticated;

create or replace function public.is_portal_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.portal_admins
        where email = lower(coalesce(auth.jwt() ->> 'email', ''))
    );
$$;

revoke all on function public.is_portal_admin() from public;
grant execute on function public.is_portal_admin() to authenticated;

drop policy if exists portal_admins_read_self on public.portal_admins;
drop policy if exists portal_settings_admin_only on public.portal_settings;
drop policy if exists classrooms_admin_only on public.classrooms;
drop policy if exists students_admin_only on public.students;

create policy portal_admins_read_self on public.portal_admins
    for select to authenticated using (email = lower(coalesce(auth.jwt() ->> 'email', '')));
create policy portal_settings_admin_only on public.portal_settings
    for all to authenticated using (public.is_portal_admin()) with check (public.is_portal_admin());
create policy classrooms_admin_only on public.classrooms
    for all to authenticated using (public.is_portal_admin()) with check (public.is_portal_admin());
create policy students_admin_only on public.students
    for all to authenticated using (public.is_portal_admin()) with check (public.is_portal_admin());

create or replace function public.get_public_portal_data()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
    with ranked as (
        select
            s.id,
            s.name,
            s.score,
            c.id as classroom_id,
            c.grade,
            c.name as classroom_name,
            rank() over (partition by c.grade order by s.score desc) as score_rank
        from public.students s
        join public.classrooms c on c.id = s.classroom_id
    )
    select jsonb_build_object(
        'settings', (
            select jsonb_build_object(
                'schoolName', school_name,
                'subjectName', subject_name,
                'academicYear', academic_year,
                'examTitle', exam_title
            )
            from public.portal_settings
            where id
        ),
        'classrooms', coalesce((
            select jsonb_agg(jsonb_build_object(
                'id', c.id,
                'grade', c.grade,
                'name', c.name,
                'accessCodeSet', c.access_code_hash is not null
            ) order by c.grade, c.name)
            from public.classrooms c
        ), '[]'::jsonb),
        'totalStudents', (select count(*) from public.students),
        'topStudents', coalesce((
            select jsonb_agg(jsonb_build_object(
                'name', ranked.name,
                'score', ranked.score,
                'classroomId', ranked.classroom_id,
                'grade', ranked.grade,
                'class', ranked.classroom_name,
                'rank', ranked.score_rank
            ) order by ranked.grade, ranked.score_rank, ranked.name)
            from ranked
            where ranked.score_rank <= 10
        ), '[]'::jsonb)
    );
$$;

create or replace function public.get_class_public_podium(p_classroom_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
    with ranked as (
        select
            s.id,
            s.name,
            s.score,
            c.id as classroom_id,
            c.grade,
            c.name as classroom_name,
            rank() over (order by s.score desc) as score_rank
        from public.students s
        join public.classrooms c on c.id = s.classroom_id
        where c.id = p_classroom_id
    )
    select coalesce(jsonb_agg(jsonb_build_object(
        'name', ranked.name,
        'score', ranked.score,
        'classroomId', ranked.classroom_id,
        'grade', ranked.grade,
        'class', ranked.classroom_name,
        'rank', ranked.score_rank
    ) order by ranked.score_rank, ranked.name), '[]'::jsonb)
    from ranked
    where ranked.score_rank <= 3;
$$;

create or replace function public.get_class_results(p_classroom_id uuid, p_access_code text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    stored_hash text;
    result jsonb;
begin
    select c.access_code_hash into stored_hash
    from public.classrooms c
    where c.id = p_classroom_id;

    if stored_hash is null
       or p_access_code is null
       or length(p_access_code) < 8
       or stored_hash <> extensions.crypt(p_access_code, stored_hash) then
        raise exception 'Kode akses kelas tidak sesuai.';
    end if;

    select coalesce(jsonb_agg(jsonb_build_object(
        'id', s.id,
        'name', s.name,
        'score', s.score,
        'note', s.note,
        'classroomId', c.id,
        'grade', c.grade,
        'class', c.name
    ) order by s.score desc, s.name), '[]'::jsonb)
    into result
    from public.students s
    join public.classrooms c on c.id = s.classroom_id
    where c.id = p_classroom_id;

    return result;
end;
$$;

create or replace function public.get_admin_portal_data()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    if not public.is_portal_admin() then
        raise exception 'Akun ini tidak memiliki akses admin.';
    end if;

    return jsonb_build_object(
        'settings', (
            select jsonb_build_object(
                'schoolName', school_name,
                'subjectName', subject_name,
                'academicYear', academic_year,
                'examTitle', exam_title
            )
            from public.portal_settings
            where id
        ),
        'classrooms', coalesce((
            select jsonb_agg(jsonb_build_object(
                'id', c.id,
                'grade', c.grade,
                'name', c.name,
                'accessCodeSet', c.access_code_hash is not null
            ) order by c.grade, c.name)
            from public.classrooms c
        ), '[]'::jsonb),
        'students', coalesce((
            select jsonb_agg(jsonb_build_object(
                'id', s.id,
                'name', s.name,
                'score', s.score,
                'note', s.note,
                'classroomId', s.classroom_id,
                'grade', c.grade,
                'class', c.name
            ) order by c.grade, c.name, s.name)
            from public.students s
            join public.classrooms c on c.id = s.classroom_id
        ), '[]'::jsonb)
    );
end;
$$;

create or replace function public.admin_save_portal_data(
    p_settings jsonb,
    p_classrooms jsonb,
    p_students jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not public.is_portal_admin() then
        raise exception 'Akun ini tidak memiliki akses admin.';
    end if;

    insert into public.portal_settings (id, school_name, subject_name, academic_year, exam_title)
    values (
        true,
        coalesce(nullif(trim(p_settings ->> 'schoolName'), ''), 'SMP Nusamandira'),
        coalesce(nullif(trim(p_settings ->> 'subjectName'), ''), 'Informatika'),
        coalesce(nullif(trim(p_settings ->> 'academicYear'), ''), '2026/2027'),
        coalesce(nullif(trim(p_settings ->> 'examTitle'), ''), 'UTS Semester Ganjil')
    )
    on conflict (id) do update set
        school_name = excluded.school_name,
        subject_name = excluded.subject_name,
        academic_year = excluded.academic_year,
        exam_title = excluded.exam_title;

    insert into public.classrooms (id, grade, name)
    select x.id, x.grade, trim(x.name)
    from jsonb_to_recordset(coalesce(p_classrooms, '[]'::jsonb)) as x(id uuid, grade smallint, name text)
    on conflict (id) do update set grade = excluded.grade, name = excluded.name;

    delete from public.students s
    where not exists (
        select 1
        from jsonb_to_recordset(coalesce(p_students, '[]'::jsonb)) as x(id uuid)
        where x.id = s.id
    );

    insert into public.students (id, classroom_id, name, score, note)
    select x.id, x.classroom_id, trim(x.name), x.score, coalesce(x.note, '')
    from jsonb_to_recordset(coalesce(p_students, '[]'::jsonb))
        as x(id uuid, classroom_id uuid, name text, score numeric, note text)
    on conflict (id) do update set
        classroom_id = excluded.classroom_id,
        name = excluded.name,
        score = excluded.score,
        note = excluded.note;

    delete from public.classrooms c
    where not exists (
        select 1
        from jsonb_to_recordset(coalesce(p_classrooms, '[]'::jsonb)) as x(id uuid)
        where x.id = c.id
    );
end;
$$;

create or replace function public.admin_set_class_access_code(p_classroom_id uuid, p_access_code text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not public.is_portal_admin() then
        raise exception 'Akun ini tidak memiliki akses admin.';
    end if;
    if p_access_code is null or length(trim(p_access_code)) < 8 or length(p_access_code) > 64 then
        raise exception 'Kode akses harus terdiri dari 8 sampai 64 karakter.';
    end if;

    update public.classrooms
    set access_code_hash = extensions.crypt(trim(p_access_code), extensions.gen_salt('bf', 10))
    where id = p_classroom_id;

    if not found then
        raise exception 'Kelas tidak ditemukan.';
    end if;
end;
$$;

create or replace function public.admin_clear_class_access_code(p_classroom_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not public.is_portal_admin() then
        raise exception 'Akun ini tidak memiliki akses admin.';
    end if;
    update public.classrooms set access_code_hash = null where id = p_classroom_id;
    if not found then
        raise exception 'Kelas tidak ditemukan.';
    end if;
end;
$$;

revoke all on function public.get_public_portal_data() from public;
revoke all on function public.get_class_public_podium(uuid) from public;
revoke all on function public.get_class_results(uuid, text) from public;
revoke all on function public.get_admin_portal_data() from public;
revoke all on function public.admin_save_portal_data(jsonb, jsonb, jsonb) from public;
revoke all on function public.admin_set_class_access_code(uuid, text) from public;
revoke all on function public.admin_clear_class_access_code(uuid) from public;

grant execute on function public.get_public_portal_data() to anon, authenticated;
grant execute on function public.get_class_public_podium(uuid) to anon, authenticated;
grant execute on function public.get_class_results(uuid, text) to anon, authenticated;
grant execute on function public.get_admin_portal_data() to authenticated;
grant execute on function public.admin_save_portal_data(jsonb, jsonb, jsonb) to authenticated;
grant execute on function public.admin_set_class_access_code(uuid, text) to authenticated;
grant execute on function public.admin_clear_class_access_code(uuid) to authenticated;

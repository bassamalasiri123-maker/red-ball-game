create table if not exists public.scores (
  user_id uuid references auth.users(id) on delete cascade,
  player_name text not null,
  score integer not null check (score between 0 and 52000),
  level integer not null check (level between 1 and 50),
  created_at timestamptz not null default now()
);

create table if not exists public.player_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null
    check (username ~ '^[a-z0-9_]{3,18}$')
);

create unique index if not exists player_profiles_username_lower_idx
  on public.player_profiles (lower(username));

alter table public.player_profiles enable row level security;
revoke all on public.player_profiles from public, anon, authenticated;

create or replace function public.create_player_profile()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  clean_username text := lower(btrim(new.raw_user_meta_data ->> 'username'));
  profile_user_id uuid;
begin
  if clean_username is null or clean_username !~ '^[a-z0-9_]{3,18}$' then
    raise exception 'Username must contain 3 to 18 letters, numbers, or underscores.';
  end if;

  if exists (
    select 1
      from public.scores
      where lower(btrim(player_name)) = clean_username
  ) then
    raise exception 'Username already taken.';
  end if;

  insert into public.player_profiles (user_id, username)
  values (new.id, clean_username)
  on conflict do nothing
  returning user_id into profile_user_id;

  if profile_user_id is null then
    select user_id
      into profile_user_id
      from public.player_profiles
      where lower(username) = clean_username;

    if profile_user_id is distinct from new.id then
      raise exception 'Username already taken.';
    end if;
  end if;

  return new;
end;
$$;

revoke all on function public.create_player_profile() from public, anon, authenticated;
drop trigger if exists create_player_profile on auth.users;
create trigger create_player_profile
  after insert on auth.users
  for each row execute function public.create_player_profile();

-- Migrate the earlier name-based scoreboard without discarding its history.
alter table public.scores
  add column if not exists user_id uuid references auth.users(id) on delete cascade;
alter table public.scores drop constraint if exists scores_pkey;
drop index if exists public.scores_player_name_lower_idx;
create unique index if not exists scores_user_id_idx
  on public.scores (user_id);

alter table public.scores drop constraint if exists scores_score_check;
alter table public.scores
  add constraint scores_score_check check (score between 0 and 52000);
alter table public.scores drop constraint if exists scores_level_check;
alter table public.scores
  add constraint scores_level_check check (level between 1 and 50);

alter table public.scores enable row level security;

drop policy if exists "Anyone can view scores" on public.scores;
create policy "Anyone can view scores"
  on public.scores
  for select
  to anon, authenticated
  using (true);

revoke insert, update, delete on public.scores from anon, authenticated;
grant select on public.scores to anon, authenticated;

drop function if exists public.submit_score(text, integer, integer);
create or replace function public.submit_score(
  p_player_name text,
  p_score integer,
  p_level integer
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  clean_name text := btrim(p_player_name);
  player_id uuid := auth.uid();
  registered_name text;
begin
  if player_id is null then
    raise exception 'Sign in before submitting a score.';
  end if;

  select username
    into registered_name
    from public.player_profiles
    where user_id = player_id;

  if registered_name is null or clean_name <> registered_name then
    raise exception 'Player name must match the signed-in account.';
  end if;

  if clean_name is null
    or char_length(clean_name) < 1
    or char_length(clean_name) > 18
    or clean_name ~ '[[:cntrl:]]' then
    raise exception 'Player name must contain 1 to 18 visible characters.';
  end if;

  if p_score is null or p_score < 0 or p_score > 52000 then
    raise exception 'Score is outside the allowed range.';
  end if;

  if p_level is null or p_level < 1 or p_level > 50 then
    raise exception 'Level must be between 1 and 50.';
  end if;

  insert into public.scores (user_id, player_name, score, level)
  values (player_id, clean_name, p_score, p_level)
  on conflict (user_id) do update
    set player_name = excluded.player_name,
        score = excluded.score,
        level = excluded.level,
        created_at = now()
    where excluded.score > public.scores.score;
end;
$$;

revoke all on function public.submit_score(text, integer, integer) from public, anon, authenticated;
grant execute on function public.submit_score(text, integer, integer) to authenticated;

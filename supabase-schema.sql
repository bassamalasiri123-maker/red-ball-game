create table if not exists public.scores (
  player_name text primary key,
  score integer not null check (score between 0 and 52000),
  level integer not null check (level between 1 and 10),
  created_at timestamptz not null default now()
);

alter table public.scores enable row level security;

create unique index if not exists scores_player_name_lower_idx
  on public.scores (lower(player_name));

drop policy if exists "Anyone can view scores" on public.scores;
create policy "Anyone can view scores"
  on public.scores
  for select
  to anon, authenticated
  using (true);

revoke insert, update, delete on public.scores from anon, authenticated;
grant select on public.scores to anon, authenticated;

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
begin
  if clean_name is null
    or char_length(clean_name) < 1
    or char_length(clean_name) > 18
    or clean_name ~ '[[:cntrl:]]' then
    raise exception 'Player name must contain 1 to 18 visible characters.';
  end if;

  if p_score is null or p_score < 0 or p_score > 52000 then
    raise exception 'Score is outside the allowed range.';
  end if;

  if p_level is null or p_level < 1 or p_level > 10 then
    raise exception 'Level must be between 1 and 10.';
  end if;

  insert into public.scores (player_name, score, level)
  values (clean_name, p_score, p_level)
  on conflict ((lower(player_name))) do update
    set score = excluded.score,
        level = excluded.level,
        created_at = now()
    where excluded.score > public.scores.score;
end;
$$;

revoke all on function public.submit_score(text, integer, integer) from public;
grant execute on function public.submit_score(text, integer, integer) to anon, authenticated;

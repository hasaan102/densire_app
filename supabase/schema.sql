create table if not exists public.orders (
  id text primary key,
  created_at timestamptz not null,
  status text not null check (status in ('New', 'Preparing', 'Ready', 'Completed', 'Cancelled')),
  order_data jsonb not null
);

alter table public.orders enable row level security;

revoke all on table public.orders from anon, authenticated;
grant select, insert, update on table public.orders to service_role;

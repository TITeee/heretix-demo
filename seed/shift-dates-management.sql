-- Runs once, right after the seed is loaded into an empty database: moves every
-- date forward by the time since the seed was made, so the demo looks the same
-- on whatever day it starts (findings detected weeks ago, due dates ahead or
-- passed, triage a few days old).
DO $$
DECLARE
  shift interval;
  col record;
BEGIN
  SELECT (now() AT TIME ZONE 'UTC') - built_at INTO shift FROM public.demo_seed;
  IF shift > interval '0' THEN
    FOR col IN
      SELECT c.table_name, c.column_name FROM information_schema.columns c
      JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
      WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
        AND c.data_type LIKE 'timestamp%' AND c.is_generated = 'NEVER'
        AND c.table_name NOT IN ('_prisma_migrations', 'demo_seed')
    LOOP
      EXECUTE format('UPDATE %I SET %I = %I + $1 WHERE %I IS NOT NULL',
                     col.table_name, col.column_name, col.column_name, col.column_name) USING shift;
    END LOOP;
  END IF;
  RAISE NOTICE 'demo dates moved forward by %', shift;
  DROP TABLE public.demo_seed;
END $$;

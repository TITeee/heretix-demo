-- Runs once, right after the seed is loaded: moves the collection jobs forward
-- by the time since the seed was made, so the data reads as loaded recently.
-- The vulnerabilities keep their own dates (published, modified): those are
-- facts about the vulnerability, not about the demo.
DO $$
DECLARE
  shift interval;
BEGIN
  SELECT (now() AT TIME ZONE 'UTC') - built_at INTO shift FROM public.demo_seed;
  IF shift > interval '0' THEN
    UPDATE "CollectionJob" SET "createdAt" = "createdAt" + shift, "updatedAt" = "updatedAt" + shift,
      "startedAt" = "startedAt" + shift, "completedAt" = "completedAt" + shift;
  END IF;
  RAISE NOTICE 'demo collection jobs moved forward by %', shift;
  DROP TABLE public.demo_seed;
END $$;

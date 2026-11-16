# A PostgreSQL that loads one of the demo's seeds on its first start, then moves
# the seed's dates up to that day. Built by build/publish-seed.sh for each seed.
FROM postgres:15-alpine
ARG SEED
COPY seed/heretix-${SEED}.sql.gz /docker-entrypoint-initdb.d/10-seed.sql.gz
COPY seed/shift-dates-${SEED}.sql /docker-entrypoint-initdb.d/20-shift-dates.sql

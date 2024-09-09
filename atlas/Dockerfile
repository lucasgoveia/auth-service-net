FROM arigaio/atlas:latest

ENV DATABASE_URL=""

COPY atlas/migrations /migrations 

CMD ["migrate", "apply", "--dir", "file://migrations", "--url", "${DATABASE_URL}"]
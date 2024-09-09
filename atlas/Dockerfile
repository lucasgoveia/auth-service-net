FROM arigaio/atlas:latest

ARG  DATABASE_URL

COPY atlas/migrations /migrations 

CMD ["migrate", "apply", "--dir", "file://migrations", "--url", "$DATABASE_URL"]
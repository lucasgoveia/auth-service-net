FROM arigaio/atlas:latest

ENV DATABASE_URL=""

COPY migrations /migrations

ENTRYPOINT ["atlas"]
CMD ["migrate", "apply", "--dir", "file://migrations", "--url", "${DATABASE_URL}"]
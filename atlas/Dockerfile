FROM alpine:latest

RUN apk add --no-cache curl

RUN curl -sSf https://atlasgo.sh | sh
    
ENV DATABASE_URL="your_database_url"

COPY atlas/migrations /migrations 

CMD exec atlas migrate apply --dir file:///migrations --url $DATABASE_URL
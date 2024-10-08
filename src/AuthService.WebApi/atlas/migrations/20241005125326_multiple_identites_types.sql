-- Create enum type "credential_type"
CREATE TYPE "iam"."credential_type" AS ENUM ('email', 'username', 'phone', 'social', 'b2b', 'passkey');

-- Create "credentials" table
CREATE TABLE "iam"."credentials"
(
    "id"         bigint                  NOT NULL,
    "user_id"    bigint                  NOT NULL,
    "type"       "iam"."credential_type" NOT NULL DEFAULT 'email',
    "identifier" character varying(256)  NULL,
    "secret"     character varying(512)  NULL,
    "provider"   character varying(100)  NULL,
    "verified"   boolean                 NOT NULL DEFAULT false,
    "created_at" timestamp               NOT NULL,
    "updated_at" timestamp               NOT NULL,
    "deleted_at" timestamp               NULL,
    PRIMARY KEY ("id"),
    CONSTRAINT "unique_credential_per_type" UNIQUE ("type", "identifier"),
    CONSTRAINT "identities_users_fk" FOREIGN KEY ("user_id") REFERENCES "iam"."users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);

-- Create "user_emails" table
CREATE TABLE "iam"."user_emails"
(
    "user_id"    bigint                 NOT NULL,
    "email"      character varying(256) NOT NULL,
    "verified"   boolean                NOT NULL DEFAULT false,
    "created_at" timestamp              NOT NULL,
    "updated_at" timestamp              NOT NULL,
    "deleted_at" timestamp              NULL,
    PRIMARY KEY ("user_id", "email"),
    CONSTRAINT "unique_user_email" UNIQUE ("email"),
    CONSTRAINT "user_emails_users_fk" FOREIGN KEY ("user_id") REFERENCES "iam"."users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "user_emails_user_id_idx" to table: "user_emails"
CREATE INDEX "user_emails_user_id_idx" ON "iam"."user_emails" ("user_id");

-- Get all identities from "identities" table and insert them into "credentials" table
INSERT INTO "iam"."credentials" ("id", "user_id", "type", "identifier", "secret", "provider", "verified", "created_at",
                                 "updated_at", "deleted_at")
SELECT i.id,
       i.user_id,
       'email',
       i.username,
       i.password_hash,
       NULL,
       U.email_verified,
       i.created_at,
       i.updated_at,
       i.deleted_at
FROM "iam"."identities" i
         JOIN iam.users u on u.id = i.user_id;

-- Get emails from "users" table and insert them into "user_emails" table
INSERT INTO "iam"."user_emails" ("user_id", "email", "verified", "created_at", "updated_at", "deleted_at")
SELECT id,
       email,
       email_verified,
       created_at,
       updated_at,
       deleted_at
FROM "iam"."users";

-- Create index "credentials_user_credential_type_idx" to table: "credentials"
CREATE INDEX "credentials_user_credential_type_idx" ON "iam"."credentials" ("user_id", "type");
-- Create index "user_identities_credential_type_idx" to table: "credentials"
CREATE INDEX "user_identities_credential_type_idx" ON "iam"."credentials" ("type");

-- Drop index "user_sessions_session_id_ended_at_idx" from table: "user_sessions"
DROP INDEX "iam"."user_sessions_session_id_ended_at_idx";
-- Drop index "user_sessions_user_id_session_id_ended_at_idx" from table: "user_sessions"
DROP INDEX "iam"."user_sessions_user_id_session_id_ended_at_idx";

-- Rename a column from "identity_id" to "credential_id"
ALTER TABLE "iam"."user_sessions"
    RENAME COLUMN "identity_id" TO "credential_id";
-- Rename a column from "ended_at" to "expires_at"
ALTER TABLE "iam"."user_sessions"
    RENAME COLUMN "ended_at" TO "expires_at";

-- Modify "user_sessions" table
ALTER TABLE "iam"."user_sessions"
    ALTER COLUMN "user_agent" TYPE character varying(256),
    ADD PRIMARY KEY ("id"),
    ADD CONSTRAINT "user_sessions_session_id_unique" UNIQUE ("session_id"),
    ADD CONSTRAINT "user_sessions_credentials_fk" FOREIGN KEY ("credential_id") REFERENCES "iam"."credentials" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
    ADD CONSTRAINT "user_sessions_users_fk" FOREIGN KEY ("user_id") REFERENCES "iam"."users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;

-- Create index "column.user_id" to table: "user_sessions"
CREATE INDEX "column.user_id" ON "iam"."user_sessions" ("user_id");
-- Create index "user_sessions_session_id_expires_at_idx" to table: "user_sessions"
CREATE INDEX "user_sessions_session_id_expires_at_idx" ON "iam"."user_sessions" ("session_id", "expires_at");
-- Create index "user_sessions_user_id_session_id_expires_at_idx" to table: "user_sessions"
CREATE INDEX "user_sessions_user_id_session_id_expires_at_idx" ON "iam"."user_sessions" ("user_id", "session_id", "expires_at");

-- Modify "users" table
ALTER TABLE "iam"."users"
    DROP COLUMN "email",
    DROP COLUMN "email_verified",
    DROP COLUMN "phone_number",
    DROP COLUMN "phone_number_verified";

-- Drop "identities" table
DROP TABLE "iam"."identities";

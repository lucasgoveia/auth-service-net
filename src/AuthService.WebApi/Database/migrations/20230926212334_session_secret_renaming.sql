-- Modify "user_sessions" table
ALTER TABLE "iam"."user_sessions" DROP COLUMN "session_secret", ADD COLUMN "session_secret" character varying(256) NOT NULL;

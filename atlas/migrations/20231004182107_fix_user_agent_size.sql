-- Modify "user_sessions" table
ALTER TABLE "iam"."user_sessions" ALTER COLUMN "user_agent" TYPE character varying(200);

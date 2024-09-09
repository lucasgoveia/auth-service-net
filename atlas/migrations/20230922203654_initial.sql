-- Drop schema named "public"
DROP SCHEMA "public" CASCADE;
-- Add new schema named "iam"
CREATE SCHEMA "iam";
-- Create "user_sessions" table
CREATE TABLE "iam"."user_sessions" ("id" integer NOT NULL GENERATED ALWAYS AS IDENTITY, "session_id" character varying(32) NOT NULL, "user_id" bigint NOT NULL, "identity_id" bigint NOT NULL, "ip_address" character varying(15) NOT NULL, "user_agent" character varying(50) NOT NULL, "device_fingerprint" character varying(128) NOT NULL, "created_at" timestamp NOT NULL, "ended_at" timestamp NULL, "session_secret" character varying(256) NOT NULL);
-- Create index "user_sessions_session_id_ended_at_idx" to table: "user_sessions"
CREATE INDEX "user_sessions_session_id_ended_at_idx" ON "iam"."user_sessions" ("session_id", "ended_at");
-- Create index "user_sessions_user_id_session_id_ended_at_idx" to table: "user_sessions"
CREATE INDEX "user_sessions_user_id_session_id_ended_at_idx" ON "iam"."user_sessions" ("user_id", "session_id", "ended_at");
-- Create "users" table
CREATE TABLE "iam"."users" ("id" bigint NOT NULL, "name" character varying(256) NOT NULL, "avatar_link" character varying(1000) NULL, "created_at" timestamp NOT NULL, "updated_at" timestamp NOT NULL, "deleted_at" timestamp NULL, PRIMARY KEY ("id"));
-- Create "identities" table
CREATE TABLE "iam"."identities" ("id" bigint NOT NULL, "user_id" bigint NOT NULL, "username" character varying(100) NOT NULL, "password_hash" character varying(256) NOT NULL, "email" character varying(256) NULL, "email_verified" boolean NOT NULL DEFAULT false, "phone_number" character varying(40) NULL, "phone_number_verified" boolean NOT NULL DEFAULT false, "two_factor_enabled" boolean NOT NULL DEFAULT false, "created_at" timestamp NOT NULL, "updated_at" timestamp NOT NULL, "deleted_at" timestamp NULL, "lockout_enabled" boolean NOT NULL DEFAULT true, "lockout_end_date" timestamp NULL, "access_failed_count" integer NOT NULL DEFAULT 0, PRIMARY KEY ("id"), CONSTRAINT "identities_users_fk" FOREIGN KEY ("user_id") REFERENCES "iam"."users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "identities_username_idx" to table: "identities"
CREATE INDEX "identities_username_idx" ON "iam"."identities" ("username");

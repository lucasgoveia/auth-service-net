-- Modify "identities" table
ALTER TABLE "iam"."identities" DROP COLUMN "email", DROP COLUMN "email_verified", DROP COLUMN "phone_number", DROP COLUMN "phone_number_verified", DROP COLUMN "two_factor_enabled", DROP COLUMN "lockout_enabled", DROP COLUMN "lockout_end_date", DROP COLUMN "access_failed_count";
-- Create index "identities_username_deleted_at_idx" to table: "identities"
CREATE INDEX "identities_username_deleted_at_idx" ON "iam"."identities" ("username", "deleted_at");
-- Modify "users" table
ALTER TABLE "iam"."users" ADD COLUMN "email" character varying(256) NULL, ADD COLUMN "email_verified" boolean NOT NULL DEFAULT false, ADD COLUMN "phone_number" character varying(20) NULL, ADD COLUMN "phone_number_verified" boolean NOT NULL DEFAULT false, ADD COLUMN "lockout_enabled" boolean NOT NULL DEFAULT true, ADD COLUMN "lockout_end_date" timestamp NULL, ADD COLUMN "access_failed_count" integer NOT NULL DEFAULT 0, ADD COLUMN "two_factor_enabled" boolean NOT NULL DEFAULT false;

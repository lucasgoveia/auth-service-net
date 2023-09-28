-- Create index "users_email_email_verified_idx" to table: "users"
CREATE INDEX "users_email_email_verified_idx" ON "iam"."users" ("email", "email_verified");
-- Create index "users_email_idx" to table: "users"
CREATE INDEX "users_email_idx" ON "iam"."users" ("email");
-- Create index "users_id_access_failed_count_idx" to table: "users"
CREATE INDEX "users_id_access_failed_count_idx" ON "iam"."users" ("id", "access_failed_count");

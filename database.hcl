schema "iam" {}

table "users" {
  schema = schema.iam
  column "id" {
    null = false
    type = bigint
  }
  column "name" {
    null = false
    type = varchar(256)
  }
  column "avatar_link" {
    null = false
    type = varchar(1000)
  }
  column "created_at" {
    null = false
    type = timestamp
  }
  column "updated_at" {
    null = false
    type = timestamp
  }
  column "deleted_at" {
    null = true
    type = timestamp
  }
  primary_key {
    columns = [column.id]
  }
}

table "identity" {
  schema = schema.iam
  column "id" {
    null = false
    type = bigint
  }
  column "user_id" {
    null = true
    type = bigint
  }
  column "username" {
    null = false
    type = varchar(100)
  }
  column "password_hash" {
    null = false
    type = varchar(256)
  }
  column "email" {
    null = true
    type = varchar(256)
  }
  column "email_verified" {
    null = false
    type = boolean
    default = false
  }
  column "phone_number" {
    null = true
    type = varchar(40)
  }
  column "phone_number_verified" {
    null = false
    type = boolean
    default = false
  }
  column "two_factor_enabled" {
    null = false
    type = boolean
    default = false
  }
  column "created_at" {
    null = false
    type = timestamp
  }
  column "updated_at" {
    null = false
    type = timestamp
  }
  column "deleted_at" {
    null = true
    type = timestamp
  }
  column "lockout_enabled" {
    null = false
    type = boolean
    default = true
  }
  column "lockout_end_date" {
    null = true
    type = timestamp
  }
  column "access_failed_count" {
    null = false
    type = int
    default = 0
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "user_fk" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
  }
  index "identity_username_idx" {
    columns = [column.username]
  }
}

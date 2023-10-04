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
  column "email" {
    null = true
    type = varchar(256)
  }
  column "email_verified" {
    null    = false
    type    = boolean
    default = false
  }
  column "phone_number" {
    null = true
    type = varchar(20)
  }
  column "phone_number_verified" {
    null    = false
    type    = boolean
    default = false
  }
  column "avatar_link" {
    null = true
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
  column "lockout_enabled" {
    null    = false
    type    = boolean
    default = true
  }
  column "lockout_end_date" {
    null = true
    type = timestamp
  }
  column "access_failed_count" {
    null    = false
    type    = int
    default = 0
  }
  column "two_factor_enabled" {
    null    = false
    type    = boolean
    default = false
  }
  primary_key {
    columns = [column.id]
  }
  
  index "users_email_idx" {
    columns = [column.email]
  }
  
  index "users_email_email_verified_idx" {
    columns = [column.email, column.email_verified]
  }
  
  index "users_id_access_failed_count_idx" {
    columns = [column.id, column.access_failed_count]
  }
}

table "identities" {
  schema = schema.iam
  column "id" {
    null = false
    type = bigint
  }
  column "user_id" {
    null = false
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
  foreign_key "identities_users_fk" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
  }
  index "identities_username_idx" {
    columns = [column.username]
  }
  index "identities_username_deleted_at_idx" {
    columns = [column.username, column.deleted_at]
  }
}

table "user_sessions" {
  schema = schema.iam
  column "id" {
    null = false
    type = int
    identity {
      generated = ALWAYS
      start     = 0
      increment = 1
    }
  }
  column "session_id" {
    null = false
    type = varchar(32)
  }
  column "user_id" {
    null = false
    type = bigint
  }
  column "identity_id" {
    null = false
    type = bigint
  }
  column "ip_address" {
    null = false
    type = varchar(15)
  }
  column "user_agent" {
    null = false
    type = varchar(200)
  }
  column "device_fingerprint" {
    null = false
    type = varchar(128)
  }
  column "created_at" {
    null = false
    type = timestamp
  }
  column "ended_at" {
    null = true
    type = timestamp
  }
  column "session_secret" {
    null = false
    type = varchar(256)
  }

  index "user_sessions_session_id_ended_at_idx" {
    columns = [column.session_id, column.ended_at]
  }
  index "user_sessions_user_id_session_id_ended_at_idx" {
    columns = [column.user_id, column.session_id, column.ended_at]
  }
}

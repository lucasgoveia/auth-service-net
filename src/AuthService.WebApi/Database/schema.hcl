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

table "identities" {
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
    null    = false
    type    = boolean
    default = false
  }
  column "phone_number" {
    null = true
    type = varchar(40)
  }
  column "phone_number_verified" {
    null    = false
    type    = boolean
    default = false
  }
  column "two_factor_enabled" {
    null    = false
    type    = boolean
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
}

table "identity_devices" {
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
  column "device_fingerprint" {
    null = false
    type = varchar(128)
  }
  column "identity_id" {
    null = false
    type = bigint
  }
  column "name" {
    null = false
    type = varchar(50)
  }
  column "ip_address" {
    null = false
    type = varchar(15)
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "identity_devices_identities_fk" {
    columns     = [column.identity_id]
    ref_columns = [table.identities.column.id]
  }
  index "identity_devices_identity_id_device_id_idx" {
    columns = [column.identity_id, column.device_fingerprint]
  }
}

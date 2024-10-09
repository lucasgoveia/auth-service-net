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
  
  index "users_id_access_failed_count_idx" {
    columns = [column.id, column.access_failed_count]
  }
}

table "user_emails" {
  schema = schema.iam
  column "user_id" {
    null = false
    type = bigint
  }
  column "email" {
    null = false
    type = varchar(256)
  }
  column "verified" {
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
  primary_key {
    columns = [column.user_id, column.email]
  }
  
  foreign_key "user_emails_users_fk" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
  }
  
  index "user_emails_user_id_idx" {
    columns = [column.user_id]
  }
  
  unique "unique_user_email" {
    columns = [column.email]
  }
}


enum "credential_type" {
  schema = schema.iam
  values = ["email", "username", "phone", "social", "b2b", "passkey"]
}

table "credentials" {
  schema = schema.iam
  column "id" {
    null = false
    type = bigint
  }
  column "user_id" {
    null = false
    type = bigint
  }
  column "type" {
    null = false
    type = enum.credential_type // e.g., email, phone, social, sso, passkey
    default = "email"
  }
  column "identifier" {
    null = true
    type = varchar(256) // For email, phone number, provider ID, etc.
  }
  column "secret" {
    null = true
    type = varchar(512) // Could be password hash, public key for passkeys, or null for SSO/social
  }
  column "provider" {
    null = true
    type = varchar(100) // Used for social and SSO (e.g., google, facebook, azure_ad), nullable for email/phone
  }
  column "verified" {
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
  primary_key {
    columns = [column.id]
  }
  foreign_key "identities_users_fk" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
  }
  
  index "user_identities_credential_type_idx" {
    columns = [column.type]
  }
  
  index "credentials_user_credential_type_idx" {
    columns = [column.user_id, column.type]
  }
  
  unique "unique_credential_per_type" {
    columns = [column.type, column.identifier]
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
  column "credential_id" {
    null = false
    type = bigint
  }
  column "ip_address" {
    null = false
    type = varchar(50)
  }
  column "user_agent" {
    null = false
    type = varchar(256)
  }
  column "device_fingerprint" {
    null = false
    type = varchar(128)
  }
  column "created_at" {
    null = false
    type = timestamp
  }
  column "expires_at" {
    null = true
    type = timestamp
  }
  column "session_secret" {
    null = false
    type = varchar(256)
  }
  primary_key {
    columns = [column.id]
  }

  foreign_key "user_sessions_users_fk" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
  }
  
  foreign_key "user_sessions_credentials_fk" {
    columns     = [column.credential_id]
    ref_columns = [table.credentials.column.id]
  }
  
  unique "user_sessions_session_id_unique" {
    columns = [column.session_id]
  }
  
  index "column.user_id" {
    columns = [ column.user_id ]
  }
  index "user_sessions_session_id_expires_at_idx" {
    columns = [column.session_id, column.expires_at]
  }
  index "user_sessions_user_id_session_id_expires_at_idx" {
    columns = [column.user_id, column.session_id, column.expires_at]
  }
}

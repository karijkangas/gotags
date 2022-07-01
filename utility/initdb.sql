CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS pending CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;

DROP TYPE IF EXISTS pending_category CASCADE;

DROP TRIGGER IF EXISTS set_pending_timestamp ON pending;
DROP TRIGGER IF EXISTS set_users_timestamp ON users;
DROP TRIGGER IF EXISTS set_profiles_timestamp ON profiles;

CREATE TYPE pending_category AS ENUM ('join', 'reset_password', 'change_email');

CREATE TABLE IF NOT EXISTS pending (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  category pending_category,
  data JSONB,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  user_id INTEGER,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER REFERENCES users PRIMARY KEY,
  data JSONB,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE OR REPLACE FUNCTION trigger_update_modified_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.modified_at = current_timestamp;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER set_pending_timestamp
BEFORE UPDATE ON pending
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

CREATE TRIGGER set_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

CREATE TRIGGER set_profiles_timestamp
BEFORE UPDATE ON profiles
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

CREATE UNIQUE INDEX IF NOT EXISTS users_idx ON users (email) INCLUDE (password_hash);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS pending CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS limits CASCADE;

DROP TYPE IF EXISTS pending_category CASCADE;

DROP TRIGGER IF EXISTS set_pending_timestamp ON pending;
DROP TRIGGER IF EXISTS set_users_timestamp ON users;
DROP TRIGGER IF EXISTS set_profiles_timestamp ON profiles;
DROP TRIGGER IF EXISTS check_pending_capacity ON pending;
DROP TRIGGER IF EXISTS check_sessions_capacity ON sessions;
-- DROP TRIGGER IF EXISTS set_sessions_timestamp ON sessions;

CREATE TYPE pending_category AS ENUM ('join', 'reset_password', 'change_email');

CREATE TABLE IF NOT EXISTS pending (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  category pending_category,
  data JSONB not null default '{}'::jsonb,
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

ALTER SEQUENCE users_id_seq RESTART;

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  user_id INTEGER,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY REFERENCES users ON DELETE CASCADE,
  data JSONB not null default '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS limits (
  id INT NOT NULL PRIMARY KEY DEFAULT 1,
  pending INT NOT NULL DEFAULT 10,
  max_pending INT NOT NULL DEFAULT 10,
  sessions INT NOT NULL DEFAULT 10,
  max_sessions INT NOT NULL DEFAULT 10,
  CHECK (id = 1)
);
INSERT INTO limits VALUES (1) ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION trigger_update_modified_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.modified_at = current_timestamp;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS set_pending_timestamp ON pending;

CREATE TRIGGER set_pending_timestamp
BEFORE UPDATE ON pending
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- DROP TRIGGER IF EXISTS set_users_timestamp ON users;

CREATE TRIGGER set_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- DROP TRIGGER IF EXISTS set_profiles_timestamp ON profiles;

CREATE TRIGGER set_profiles_timestamp
BEFORE UPDATE ON profiles
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- DROP TRIGGER IF EXISTS set_sessions_timestamp ON sessions;

-- CREATE TRIGGER set_sessions_timestamp
-- BEFORE UPDATE ON sessions
-- FOR EACH ROW
-- EXECUTE FUNCTION trigger_update_modified_at();

CREATE OR REPLACE FUNCTION check_pending_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM pending as p1 WHERE p1.email = NEW.email) >= (SELECT pending FROM limits WHERE id=1)
  THEN
    RAISE EXCEPTION 'No more for you';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS verify_pending_capacity ON pending;

CREATE TRIGGER check_pending_capacity 
BEFORE INSERT ON pending
FOR EACH ROW EXECUTE PROCEDURE check_pending_capacity();

CREATE OR REPLACE FUNCTION check_sessions_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM sessions as s1 WHERE s1.user_id = NEW.user_id) >= (SELECT sessions FROM limits WHERE id=1)
  THEN
    RAISE EXCEPTION 'No more for you';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS verify_sessions_capacity ON sessions;

CREATE TRIGGER check_sessions_capacity 
BEFORE INSERT ON sessions
FOR EACH ROW EXECUTE PROCEDURE check_sessions_capacity();

CREATE UNIQUE INDEX IF NOT EXISTS users_idx ON users (email) INCLUDE (password_hash);

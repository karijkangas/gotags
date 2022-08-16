SET TIME ZONE 'UTC';

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ********** common **********

CREATE OR REPLACE FUNCTION now_utc()
RETURNS TIMESTAMP WITH TIME ZONE AS $$
  SELECT now() AT TIME ZONE 'utc'
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION trigger_update_modified_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.modified_at = now_utc();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ********** limits **********
DROP TABLE IF EXISTS limits CASCADE;

CREATE TABLE IF NOT EXISTS limits (
  id INT NOT NULL PRIMARY KEY DEFAULT 1,
  pending INT NOT NULL DEFAULT 10,            -- active pending items per email
  max_pending INT NOT NULL DEFAULT 10,        -- to reset pending
  sessions INT NOT NULL DEFAULT 10,           -- active sessions per email
  max_sessions INT NOT NULL DEFAULT 10,       -- to reset sessions
  emails INT NOT NULL DEFAULT 10,             -- emails send per email within limiter TTL window
  max_emails INT NOT NULL DEFAULT 10,         -- to reset emails
  CHECK (id = 1)
);
INSERT INTO limits VALUES (1) ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION get_pending_limit()
RETURNS INT AS $$
    SELECT pending
    FROM limits WHERE id = 1
$$ language sql;

CREATE OR REPLACE FUNCTION get_sessions_limit()
RETURNS INT AS $$
    SELECT sessions
    FROM limits WHERE id = 1
$$ language sql;

CREATE OR REPLACE FUNCTION get_emails_limit()
RETURNS INT AS $$
    SELECT emails
    FROM limits WHERE id = 1
$$ language sql;

-- ********** pending **********
DROP TABLE IF EXISTS pending CASCADE;

CREATE TABLE IF NOT EXISTS pending (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  category TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

CREATE OR REPLACE FUNCTION check_pending_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM pending AS p1
      WHERE p1.email = NEW.email) >= get_pending_limit()
  THEN
    RAISE EXCEPTION 'pending: no capacity';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_pending_capacity 
BEFORE INSERT ON pending
FOR EACH ROW EXECUTE PROCEDURE check_pending_capacity();

-- ********** limiter **********
DROP TABLE IF EXISTS limiter CASCADE;

CREATE TABLE IF NOT EXISTS limiter (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  counter INT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  CONSTRAINT max_email_limit CHECK (counter BETWEEN 1 AND get_emails_limit())
);

ALTER SEQUENCE limiter_id_seq RESTART;
CREATE UNIQUE INDEX IF NOT EXISTS limiter_idx ON limiter(email, counter);

-- ********** users **********
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_idx ON users (email) INCLUDE (id, email);
ALTER SEQUENCE users_id_seq RESTART;

DROP TRIGGER IF EXISTS set_users_timestamp ON users;

CREATE TRIGGER set_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- ********** profiles **********
DROP TABLE IF EXISTS profiles CASCADE;

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

DROP TRIGGER IF EXISTS set_profiles_timestamp ON profiles;

CREATE TRIGGER set_profiles_timestamp
BEFORE UPDATE ON profiles
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

CREATE OR REPLACE FUNCTION create_user_profile() RETURNS TRIGGER AS
$BODY$
BEGIN
    INSERT INTO profiles(id) VALUES(NEW.id);
    RETURN new;
END;
$BODY$
language plpgsql;

DROP TRIGGER IF EXISTS create_user_profile ON users;

CREATE TRIGGER create_user_profile
     AFTER INSERT ON users
     FOR EACH ROW
     EXECUTE PROCEDURE create_user_profile();

-- ********** sessions **********
DROP TABLE IF EXISTS sessions CASCADE;

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

CREATE OR REPLACE FUNCTION check_sessions_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM sessions AS s1 WHERE s1.user_id = NEW.user_id) >= get_sessions_limit()
  THEN
    RAISE EXCEPTION 'sessions: no capacity';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS check_sessions_capacity ON sessions;

CREATE TRIGGER check_sessions_capacity 
BEFORE INSERT ON sessions
FOR EACH ROW EXECUTE PROCEDURE check_sessions_capacity();

-- ********** tag_catalog **********
DROP TABLE IF EXISTS tag_catalog CASCADE;

CREATE TABLE IF NOT EXISTS tag_catalog (
  id SERIAL PRIMARY KEY,
  category TEXT NOT NULL UNIQUE,
  default_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

INSERT INTO tag_catalog (category, default_data) VALUES ('nop', '{}');
INSERT INTO tag_catalog (category, default_data) VALUES ('counter', '{"counter": 0}');
INSERT INTO tag_catalog (category, default_data) VALUES ('anticounter', '{}');

-- ********** tags **********
DROP TABLE IF EXISTS tags CASCADE;

CREATE TABLE IF NOT EXISTS tags (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc()
);

DROP TRIGGER IF EXISTS set_tags_timestamp ON tags;

CREATE TRIGGER set_tags_timestamp
BEFORE UPDATE ON tags
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- ********** tag_events **********
DROP TABLE IF EXISTS tag_events CASCADE;

CREATE TABLE IF NOT EXISTS tag_events (
  user_id INTEGER,
  tag_id UUID NOT NULL,
  category TEXT NOT NULL,   -- 'added', 'accessed', 'acted_on'
  event_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_tag FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS tag_events_idx ON tag_events (user_id, tag_id, category);

-- ********** admins **********
DROP TABLE IF EXISTS admins CASCADE;

CREATE TABLE IF NOT EXISTS admins (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS admins_idx ON admins (user_id);

-- ********** admin_sessions **********
DROP TABLE IF EXISTS admin_sessions CASCADE;

CREATE TABLE IF NOT EXISTS admin_sessions (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now_utc(),
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS limits CASCADE;
DROP TABLE IF EXISTS pending CASCADE;
DROP TABLE IF EXISTS limiter CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;


-- DROP TRIGGER IF EXISTS set_users_timestamp ON users;
-- DROP TRIGGER IF EXISTS set_profiles_timestamp ON profiles;
-- DROP TRIGGER IF EXISTS check_pending_capacity ON pending;
-- DROP TRIGGER IF EXISTS check_sessions_capacity ON sessions;
-- DROP TRIGGER IF EXISTS set_sessions_timestamp ON sessions;

-- ********** common **********

CREATE OR REPLACE FUNCTION trigger_update_modified_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.modified_at = current_timestamp;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ********** limits **********

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
RETURNS int AS $$
    SELECT pending
    FROM limits WHERE id = 1
$$ language sql;

CREATE OR REPLACE FUNCTION get_sessions_limit()
RETURNS int AS $$
    SELECT sessions
    FROM limits WHERE id = 1
$$ language sql;

CREATE OR REPLACE FUNCTION get_emails_limit()
RETURNS int AS $$
    SELECT emails
    FROM limits WHERE id = 1
$$ language sql;

-- ********** pending **********

-- DROP TYPE IF EXISTS pending_category CASCADE;
-- CREATE TYPE pending_category AS ENUM ('join', 'reset_password', 'change_email');

CREATE TABLE IF NOT EXISTS pending (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  category TEXT NOT NULL,
  -- category pending_category,
  data JSONB not null default '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp
  -- modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

-- DROP TRIGGER IF EXISTS set_pending_timestamp ON pending;

-- CREATE TRIGGER set_pending_timestamp
-- BEFORE UPDATE ON pending
-- FOR EACH ROW
-- EXECUTE FUNCTION trigger_update_modified_at();

CREATE OR REPLACE FUNCTION check_pending_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM pending as p1 WHERE p1.email = NEW.email) >= get_pending_limit()
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
CREATE TABLE IF NOT EXISTS limiter (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  counter INT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  CONSTRAINT max_email_limit CHECK (counter BETWEEN 1 AND get_emails_limit())
);

ALTER SEQUENCE limiter_id_seq RESTART;
CREATE UNIQUE INDEX IF NOT EXISTS limiter_idx ON limiter(email, counter);

-- CREATE OR REPLACE FUNCTION pending_limiter_set_counter() RETURNS TRIGGER AS
-- $BODY$
--     DECLARE
--         row_count integer;
--     BEGIN
--         SELECT count(*) INTO row_count FROM pending_limiter WHERE email = NEW.email;
--         IF row_count = 0 THEN
--             NEW.counter = 1;
--             RETURN NEW;
--         ELSE
--             NEW.counter = row_count + 1;
--             RETURN NEW;
--         END IF;
--     END;
-- $BODY$ LANGUAGE plpgsql;

-- CREATE TRIGGER pending_limiter_set_counter
--   BEFORE INSERT ON pending_limiter
--   FOR EACH
--   ROW EXECUTE PROCEDURE pending_limiter_set_counter();

-- CREATE OR REPLACE FUNCTION copy_email_to_email_counter() RETURNS TRIGGER AS
-- $BODY$
-- BEGIN
--     INSERT INTO email_counter(email) VALUES(NEW.email);
--     RETURN new;
-- END;
-- $BODY$
-- language plpgsql;

-- DROP TRIGGER IF EXISTS copy_email_to_email_counter ON pending;

-- CREATE TRIGGER copy_email_to_email_counter
--      AFTER INSERT ON pending
--      FOR EACH ROW
--      EXECUTE PROCEDURE copy_email_to_email_counter()();

-- ********** users **********

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX IF NOT EXISTS users_idx ON users (email) INCLUDE (id, email);
ALTER SEQUENCE users_id_seq RESTART;

DROP TRIGGER IF EXISTS set_users_timestamp ON users;

CREATE TRIGGER set_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_update_modified_at();

-- ********** profiles **********

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data JSONB not null default '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
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

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
  -- CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION check_sessions_capacity()
  RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT count(*) FROM sessions as s1 WHERE s1.user_id = NEW.user_id) >= get_sessions_limit()
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

-- ********** tags **********

DROP TABLE IF EXISTS tag_catalog CASCADE;
DROP TABLE IF EXISTS tags CASCADE;
DROP TABLE IF EXISTS tag_events CASCADE;

CREATE TABLE IF NOT EXISTS tag_catalog (
  id SERIAL PRIMARY KEY,
  category TEXT NOT NULL,
  default_data JSONB not null default '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS tags (
  id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  data JSONB not null default '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS tag_events (
  user_id INTEGER,
  tag_id UUID,
  category TEXT NOT NULL,   -- 'connected', 'accessed', 'acted_on'
  event_at TIMESTAMP WITH TIME ZONE default current_timestamp,
  CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_tag FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- -- ********** profile keys **********
-- CREATE TABLE IF NOT EXISTS profile_keys (
--   key TEXT UNIQUE NOT NULL PRIMARY KEY
-- );


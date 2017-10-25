CREATE TYPE account_status AS ENUM ('close', 'enable', 'disable', 'block');
CREATE TYPE status AS ENUM ('enable', 'disable', 'pending', 'close', 'remove', 'lock');
CREATE TYPE transaction_status AS ENUM ('new', 'process', 'onhold', 'cancel', 'complete');
CREATE TYPE gizacoin_status AS ENUM ('valid', 'invalid');

CREATE TABLE users (
     uid uuid NOT NULL,
     login text NOT NULL,
     name text NOT NULL,
     email text NOT NULL,
     reference json NOT NULL,
     register TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     status status DEFAULT 'enable',
     PRIMARY KEY(uid),
     UNIQUE (email),
     UNIQUE (login)
);

CREATE TABLE balance (
  account_id uuid NOT NULL,
  amount numeric NOT NULL DEFAULT 0,
  gizacoin_hash uuid,
  last_update timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id)
);

CREATE TABLE gizacoin (
  gizacoin_id uuid NOT NULL,
  account_id uuid NOT NULL,
  status gizacoin_status NOT NULL DEFAULT 'valid',
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_update timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (gizacoin_id)
);

CREATE TABLE gizacoin_hash_map (
  gizacoin_hash_id uuid NOT NULL,
  account_id uuid NOT NULL,
  amount numeric NOT NULL DEFAULT 0,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (gizacoin_hash_id)
);

CREATE TABLE transaction_lock (
  account_id uuid NOT NULL,
  transaction_id uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id)
);

CREATE TABLE transaction (
  transaction_id uuid NOT NULL,
  from_id uuid NOT NULL,
  to_id uuid NOT NULL,
  amount numeric NOT NULL,
  deduce numeric NOT NULL,
  gizacoin_data json NOT NULL,
  reference json,
  status transaction_status NOT NULL DEFAULT 'new',
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  execute_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (transaction_id)
);

CREATE TABLE account_token (
  account_id uuid NOT NULL,
  token uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id)
);

CREATE TABLE account_token_revoke (
  account_id uuid NOT NULL,
  token uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id)
);

CREATE TABLE portal (
  portal_id uuid,
  name text NOT NULL,
  status account_status NOT NULL DEFAULT 'close',
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (portal_id)
);

CREATE TABLE portal_token (
  portal_id uuid NOT NULL,
  token uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (portal_id)
);

CREATE TABLE portal_token_revoke (
  portal_id uuid NOT NULL, 
  token uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (portal_id)
);

CREATE TABLE activate_code (
  login text NOT NULL,
  code text NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (login)
);

CREATE TABLE genes (
  account_id uuid NOT NULL,
  bigchat_id text NOT NULL,
  app_id text NOT NULL DEFAULT 'bigchat',
  amount numeric NOT NULL DEFAULT 0,
  daily_amount numeric NOT NULL DEFAULT 0,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_update timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id, bigchat_id, app_id),
  UNIQUE (bigchat_id, app_id)
);

CREATE TABLE app_activate_code (
  account_id uuid NOT NULL,
  login text NOT NULL,
  code text NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id),
  UNIQUE (login)
);

CREATE TABLE app_auth (
  account_id uuid NOT NULL,
  app_id text NOT NULL,
  token uuid NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiry_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id, app_id)
);

CREATE TABLE apps (
  app_id text NOT NULL,
  name text NOT NULL,
  icon_url text NOT NULL,
  info text NOT NULL,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_id)
);

CREATE TABLE new_genes (
  account_id uuid NOT NULL,
  amount numeric NOT NULL DEFAULT 0,
  daily_amount numeric NOT NULL DEFAULT 0,
  create_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_update timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id)
);

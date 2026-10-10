CREATE TABLE IF NOT EXISTS auth_flows (
  state_hash TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_flows_expiry ON auth_flows(expires_at);
CREATE TABLE IF NOT EXISTS proofs (
  code_hash TEXT PRIMARY KEY,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS proofs_expiry ON proofs(expires_at);

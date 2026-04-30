-- tools/aggregator/schema.sql
-- Postgres tables for the tools aggregator.
-- This is a CACHE, not truth. Rebuilt from log scan at any time.

CREATE TABLE IF NOT EXISTS cases (
    id              SERIAL PRIMARY KEY,
    docket_number   TEXT UNIQUE NOT NULL,
    case_type       TEXT NOT NULL,
    division        TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    filed_date      DATE,
    court_did       TEXT NOT NULL,
    log_did         TEXT NOT NULL,
    log_position    BIGINT NOT NULL,
    signer_did      TEXT NOT NULL,
    schema_ref_pos  BIGINT,
    sealed          BOOLEAN DEFAULT FALSE,
    expunged        BOOLEAN DEFAULT FALSE,
    assigned_judge  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_events (
    id              SERIAL PRIMARY KEY,
    case_id         INTEGER REFERENCES cases(id),
    event_type      TEXT NOT NULL,
    log_position    BIGINT NOT NULL,
    signer_did      TEXT NOT NULL,
    authority_path  TEXT,
    payload_summary JSONB,
    log_time        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id);
CREATE INDEX IF NOT EXISTS idx_case_events_signer ON case_events(signer_did);
CREATE INDEX IF NOT EXISTS idx_case_events_pos ON case_events(log_position);

CREATE TABLE IF NOT EXISTS officers (
    id              SERIAL PRIMARY KEY,
    delegate_did    TEXT NOT NULL,
    signer_did      TEXT NOT NULL,
    role            TEXT,
    division        TEXT,
    scope_limit     TEXT[],
    log_position    BIGINT NOT NULL,
    is_live         BOOLEAN DEFAULT TRUE,
    revoked_at_pos  BIGINT,
    depth           INTEGER NOT NULL DEFAULT 1,
    court_did       TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_officers_did ON officers(delegate_did);
CREATE INDEX IF NOT EXISTS idx_officers_live ON officers(is_live) WHERE is_live = TRUE;

CREATE TABLE IF NOT EXISTS artifacts (
    id              SERIAL PRIMARY KEY,
    cid             TEXT UNIQUE NOT NULL,
    content_digest  TEXT,
    case_id         INTEGER REFERENCES cases(id),
    filing_position BIGINT NOT NULL,
    signer_did      TEXT NOT NULL,
    sealed          BOOLEAN DEFAULT FALSE,
    expunged        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);

CREATE TABLE IF NOT EXISTS sealing_orders (
    id              SERIAL PRIMARY KEY,
    case_id         INTEGER REFERENCES cases(id),
    order_type      TEXT NOT NULL,
    log_position    BIGINT NOT NULL,
    signer_did      TEXT NOT NULL,
    authority       TEXT,
    affected_cids   TEXT[],
    is_active       BOOLEAN DEFAULT TRUE,
    superseded_by   BIGINT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sealing_case ON sealing_orders(case_id);

CREATE TABLE IF NOT EXISTS assignments (
    id              SERIAL PRIMARY KEY,
    assignment_date DATE NOT NULL,
    division        TEXT NOT NULL,
    judge_did       TEXT NOT NULL,
    courtrooms      TEXT[],
    case_types      TEXT[],
    log_position    BIGINT NOT NULL,
    superseded_by   BIGINT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assignments_date ON assignments(assignment_date);

CREATE TABLE IF NOT EXISTS scan_watermarks (
    log_did         TEXT PRIMARY KEY,
    last_position   BIGINT NOT NULL DEFAULT 0,
    last_scan_at    TIMESTAMPTZ DEFAULT NOW()
);

-- 3E.5 — Capacity-aware filings index. One row per (entry, capacity).
-- The aggregator walks the log, deserializes filed_by_capacity and
-- signed_by_capacities (defined in schemas/capacity.go), and writes
-- one row per role appearance so read-side queries can answer:
--
--   "Which entries did Filer X file?"  (filed_by_capacity rows)
--   "Which entries did Signer Y cosign?" (signed_by_capacities rows)
--
-- This is a CACHE built from the log; truth lives on-log. Rebuilds
-- are idempotent: PRIMARY KEY (case_id, log_position, capacity_did,
-- capacity_kind) prevents duplicates on rescan.
CREATE TABLE IF NOT EXISTS parties_filings (
    id              SERIAL PRIMARY KEY,
    case_id         INTEGER REFERENCES cases(id),
    log_position    BIGINT NOT NULL,
    log_did         TEXT NOT NULL,

    -- "filed_by" or "signed_by" — distinguishes the Filer-side
    -- single capacity block from the Signer-side cosigners list.
    capacity_kind   TEXT NOT NULL CHECK (capacity_kind IN ('filed_by','signed_by')),

    -- The actor's network DID (attorney_did for Filers; signer DID
    -- for Signers). For Parties (no DID), the binding_id is stored
    -- in capacity_binding_id and capacity_did is the empty string.
    capacity_did    TEXT NOT NULL DEFAULT '',

    -- Closed-set role string from schemas.FilerRole / role_catalog.
    capacity_role   TEXT NOT NULL,

    -- Optional binding_id reference (Pro Se filings, Party-side
    -- references). Empty when capacity_did is populated.
    capacity_binding_id TEXT,

    -- Free-form credentials map (bpr_number, jurisdiction, firm,
    -- letters_of_administration_ref, appointment_order_ref, etc.).
    -- Stored as JSONB so the aggregator can index on credential
    -- values without a separate table.
    credentials     JSONB,

    -- Event type + case_ref for query convenience. Both copied from
    -- the parent entry's payload at scan time.
    event_type      TEXT NOT NULL,
    case_ref        TEXT,

    sworn_at        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (log_did, log_position, capacity_did, capacity_binding_id, capacity_kind)
);

CREATE INDEX IF NOT EXISTS idx_parties_filings_case ON parties_filings(case_id);
CREATE INDEX IF NOT EXISTS idx_parties_filings_did ON parties_filings(capacity_did)
    WHERE capacity_did <> '';
CREATE INDEX IF NOT EXISTS idx_parties_filings_role ON parties_filings(capacity_role);
CREATE INDEX IF NOT EXISTS idx_parties_filings_event ON parties_filings(event_type);
CREATE INDEX IF NOT EXISTS idx_parties_filings_binding
    ON parties_filings(capacity_binding_id)
    WHERE capacity_binding_id IS NOT NULL;

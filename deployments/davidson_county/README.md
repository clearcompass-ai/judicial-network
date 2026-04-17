# Davidson County Court — Deployment

Davidson County (Nashville), Tennessee. The first production deployment
of the judicial network.

## Court Identity

- **Court DID:** `did:web:courts.nashville.gov`
- **Jurisdiction:** Tennessee
- **County:** Davidson
- **Case volume:** ~50,000 cases/year

## Log DIDs

- Officers: `did:web:courts.nashville.gov:officers`
- Cases: `did:web:courts.nashville.gov:cases`
- Parties: `did:web:courts.nashville.gov:parties`

## Infrastructure

- **Operator:** TN AOC shared infrastructure (Model 2/3)
- **Storage:** GCS (`davidson-court-artifacts` bucket)
- **Anchor:** TN state anchor (`did:web:courts.tn.gov:anchor`)
- **Witnesses:** 3-of-4 quorum (AOC-managed)
- **Escrow:** 3-of-5 threshold

## Divisions

- Criminal Division
- Civil Division
- Chancery Division
- Circuit Division
- General Sessions Division
- Juvenile Division

## Deployment Steps

```bash
# 1. Bootstrap the court
./bootstrap.sh

# 2. Verify deployment
./verify.sh

# 3. Bootstrap initial officers
judicial-network officer-bootstrap \
    --court-config config/court.yaml \
    --logs-config config/logs.yaml
```

## Daily Operations

- `daily_docket.go` — generates daily docket assignment commentary entries
- `court_ops.go` — operational helpers (division management, schema updates)

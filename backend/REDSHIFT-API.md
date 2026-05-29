# Redshift Data API — Frontend Integration Guide

## Overview

The Loyalty Dashboard backend provides a query endpoint that lets the frontend execute read-only SQL against the Redshift `loyalty` schema in the Data Integrations account. Authentication, cross-account role assumption, and credential management all happen server-side — the frontend just sends SQL and gets results.

## Endpoint

```
POST https://7ghddg7uji.execute-api.eu-west-1.amazonaws.com/data/query
```

Requires a valid session JWT (same auth as all other protected endpoints).

## Request

```json
{
  "sql": "SELECT * FROM loyalty.customers LIMIT 10"
}
```

## Response

```json
{
  "columns": ["id", "name", "email", "created_at"],
  "rows": [
    ["1", "John Doe", "john@example.com", "2025-03-01"],
    ["2", "Jane Smith", "jane@example.com", "2025-03-02"]
  ]
}
```

## Frontend Usage

Use the existing `YoyoAuth.authFetch()` helper from `assets/auth.js`:

```javascript
async function queryRedshift(sql) {
  const res = await YoyoAuth.authFetch('/data/query', {
    method: 'POST',
    body: JSON.stringify({ sql }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Query failed');
  }

  return res.json(); // { columns: [...], rows: [...] }
}

// Example:
const { columns, rows } = await queryRedshift(
  "SELECT * FROM loyalty.reward_issued_airtime LIMIT 20"
);
```

## Constraints

| Constraint | Value |
|------------|-------|
| Access level | Read-only (SELECT only) |
| Max SQL length | 4,000 characters |
| Query timeout | 25 seconds |
| Schema | `loyalty` (always prefix tables with `loyalty.`) |

Write statements (INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE, GRANT, REVOKE, COPY) are rejected server-side with a 400 response.

## Available Tables

Run this query to get the full list:

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema = 'loyalty'
```

Known tables (as of initial deployment):

- `loyalty.earn_type_campaign_type`
- `loyalty.reward_issued_airtime`
- `loyalty.transactional_request`
- `loyalty.user_sku`
- `loyalty.reward_value_type`

## Error Responses

| Status | Body | Meaning |
|--------|------|---------|
| 401 | `{"error": "unauthorized"}` | Missing or expired JWT — user needs to log in again |
| 400 | `{"error": "bad-json"}` | Request body is not valid JSON |
| 400 | `{"error": "missing-sql"}` | No `sql` field in the request body |
| 400 | `{"error": "sql-too-long"}` | SQL exceeds 4,000 characters |
| 400 | `{"error": "write-not-allowed"}` | Detected a write/DDL statement |
| 502 | `{"error": "query-failed", "message": "..."}` | Redshift error or query timed out |

## Architecture

```
Browser → API Gateway → QueryRedshiftFn (Lambda)
                              │
                              ├─ Verify JWT (Secrets Manager)
                              ├─ STS AssumeRole → Data Integrations account
                              └─ Redshift Data API → loyalty schema
```

- **Sandbox account (058264502468)**: Amplify app, API Gateway, Lambda
- **Data Integrations account (603938032842)**: Redshift cluster `yoyo-datawarehouse-integrations`, database `cvs_loyalty_int`
- **Cross-account role**: `SandboxLoyaltyDashboardRedshiftRead` (assumed by the Lambda)
- **Redshift DB user**: `dashboard_loyalty_readonly` (read-only access to `loyalty` schema)

## Testing with curl

```bash
# Get a valid JWT by logging in through the portal, then:
curl -X POST "https://7ghddg7uji.execute-api.eu-west-1.amazonaws.com/data/query" \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT table_name FROM information_schema.tables WHERE table_schema = '\''loyalty'\'' LIMIT 5"}'
```

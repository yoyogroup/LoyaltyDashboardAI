/**
 * Cross-account Redshift Data API helper.
 *
 * Assumes the SandboxLoyaltyDashboardRedshiftRead role in the Data Integrations
 * account, then executes read-only queries against the loyalty schema via the
 * Redshift Data API.
 *
 * Usage:
 *   import { queryRedshift } from './lib/redshift.mjs';
 *   const result = await queryRedshift('SELECT * FROM loyalty.customers LIMIT 10');
 */

import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import {
  RedshiftDataClient,
  ExecuteStatementCommand,
  DescribeStatementCommand,
  GetStatementResultCommand,
} from '@aws-sdk/client-redshift-data';

// ─── Configuration ──────────────────────────────────────────────────────────
const DATA_INTEGRATIONS_ROLE_ARN =
  'arn:aws:iam::603938032842:role/SandboxLoyaltyDashboardRedshiftRead';
const EXTERNAL_ID = 'yoyo-loyalty-redshift-access';
const CLUSTER_IDENTIFIER = 'yoyo-datawarehouse-integrations';
const DATABASE = 'cvs_loyalty_int';
const DB_USER = 'dashboard_loyalty_readonly'; // Redshift DB user for GetClusterCredentials

// ─── STS: Assume cross-account role ─────────────────────────────────────────
const stsClient = new STSClient({});

async function getCrossAccountCredentials() {
  const { Credentials } = await stsClient.send(
    new AssumeRoleCommand({
      RoleArn: DATA_INTEGRATIONS_ROLE_ARN,
      RoleSessionName: 'loyalty-dashboard-redshift',
      ExternalId: EXTERNAL_ID,
      DurationSeconds: 900, // 15 min — minimum for Data API queries
    })
  );

  return {
    accessKeyId: Credentials.AccessKeyId,
    secretAccessKey: Credentials.SecretAccessKey,
    sessionToken: Credentials.SessionToken,
  };
}

// ─── Redshift Data API query ────────────────────────────────────────────────

/**
 * Execute a SQL query against the Redshift cluster in the Data Integrations
 * account and return the result rows.
 *
 * @param {string} sql - The SQL statement to execute (read-only).
 * @param {object} [options]
 * @param {number} [options.pollIntervalMs=500] - How often to poll for completion.
 * @param {number} [options.timeoutMs=30000] - Max wait time before throwing.
 * @returns {Promise<{columns: string[], rows: any[][]}>}
 */
export async function queryRedshift(sql, { pollIntervalMs = 500, timeoutMs = 30000 } = {}) {
  const credentials = await getCrossAccountCredentials();

  const redshiftData = new RedshiftDataClient({
    region: 'eu-west-1', // Region where the Redshift cluster lives
    credentials,
  });

  // Submit the statement
  const { Id: statementId } = await redshiftData.send(
    new ExecuteStatementCommand({
      ClusterIdentifier: CLUSTER_IDENTIFIER,
      Database: DATABASE,
      DbUser: DB_USER,
      Sql: sql,
      WithEvent: false,
    })
  );

  // Poll until complete
  const deadline = Date.now() + timeoutMs;
  let status;
  while (Date.now() < deadline) {
    const desc = await redshiftData.send(
      new DescribeStatementCommand({ Id: statementId })
    );
    status = desc.Status;

    if (status === 'FINISHED') break;
    if (status === 'FAILED') {
      throw new Error(`Redshift query failed: ${desc.Error}`);
    }
    if (status === 'ABORTED') {
      throw new Error('Redshift query was aborted.');
    }

    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }

  if (status !== 'FINISHED') {
    throw new Error(`Redshift query timed out after ${timeoutMs}ms (status: ${status})`);
  }

  // Fetch results
  const result = await redshiftData.send(
    new GetStatementResultCommand({ Id: statementId })
  );

  const columns = result.ColumnMetadata.map((col) => col.name);
  const rows = result.Records.map((row) =>
    row.map((field) => {
      // Each field is an object like { stringValue: '...' } or { longValue: 123 }
      const key = Object.keys(field).find((k) => field[k] !== undefined && k !== 'isNull');
      return field.isNull ? null : field[key];
    })
  );

  return { columns, rows };
}

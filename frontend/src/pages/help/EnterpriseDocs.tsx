import React from 'react'

export interface SocDetailDoc {
  id: string
  name: string
  route: string
  category: string
  icon: string
  tagline: string
  keywords: string[]
  details: React.ReactNode
}

export const ENTERPRISE_DOCS: SocDetailDoc[] = [
  {
    id: 'detection-rules',
    name: 'Detection Rules',
    route: '/detection-rules',
    category: 'Enterprise',
    icon: 'ShieldCheck',
    tagline: 'Sigma and custom detection rules with full lifecycle — versioning, peer approval, testing, and rollback.',
    keywords: [
      'detection', 'rules', 'sigma', 'custom', 'yaml', 'lifecycle', 'approval',
      'peer review', 'versioning', 'rollback', 'testing', 'dry-run', 'history',
      'change request', 'false positive', 'condition', 'logsource', 'severity',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">What Are Detection Rules?</h3>
        <p className="text-muted-foreground mb-2">
          Detection rules are the core logic that the SOC platform evaluates against every piece of incoming
          alert telemetry. When a rule's conditions match an event, the platform generates a detection — a
          structured alert that analysts can triage, escalate, or suppress. Rules are the bridge between raw
          log data and actionable security findings, and their quality directly determines how useful your
          alert queue is.
        </p>
        <p className="text-muted-foreground mb-2">
          Without well-crafted rules, you are flying blind: either generating so many false positives that
          analysts become desensitised, or missing genuine threats because conditions are too narrow. The
          detection rules module gives you a structured environment to write, test, review, and deploy rules
          safely — with a full audit trail of every change ever made.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rule Types: Sigma vs Custom</h3>
        <p className="text-muted-foreground mb-2">
          The platform supports two rule formats, each suited to different use cases:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>
            <strong>Sigma rules</strong> use the industry-standard YAML format originally developed by the
            Sigma project. They are portable, community-shareable, and can be imported directly from public
            rule repositories. A Sigma rule specifies a <code>title</code>, a <code>logsource</code> block
            (which identifies the log category and product), a <code>detection</code> block with keywords
            or field matchers, and a <code>condition</code> expression that ties them together. Example
            fields: <code>detection.keywords</code> for free-text matching,
            <code>detection.condition: keywords</code> to activate the keyword set.
          </li>
          <li>
            <strong>Custom rules</strong> use a JSON condition builder that is friendlier for analysts who
            are not comfortable with YAML. You define field-level matchers (field name, operator, value),
            combine them with AND/OR logic, and the platform compiles them into an internal evaluation
            engine at save time. Custom rules are faster to write for simple use cases but are not portable
            to other platforms.
          </li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rule Severity Levels</h3>
        <p className="text-muted-foreground mb-2">
          Every rule carries a severity level — <strong>Low, Medium, High,</strong> or <strong>Critical</strong> —
          which is automatically inherited by any detection the rule fires. This means your rule severity
          directly influences analyst prioritisation. A Critical rule firing on a production auth server will
          surface immediately at the top of the alert queue; a Low rule on a dev workstation will sit lower.
          Think carefully about severity at rule creation time: over-assigning Critical severity causes alert
          fatigue, while under-assigning Low severity causes important detections to be deprioritised.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rule Lifecycle: Create → Approve → Active</h3>
        <p className="text-muted-foreground mb-2">
          Rules follow a structured lifecycle to prevent accidental deployment of broken or noisy logic into
          the live detection pipeline:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Create</strong> — Write the rule (Sigma YAML or Custom JSON) and save it as a draft.</li>
          <li><strong>Submit Change Request</strong> — When you are ready to deploy, submit a change request. This locks the rule content and notifies peer reviewers.</li>
          <li><strong>Peer Approval</strong> — A second admin reviews the rule logic, test results, and potential impact. They can approve or reject with a comment.</li>
          <li><strong>Approved</strong> — Once approved, the rule is promoted to Active status and begins evaluating incoming telemetry.</li>
          <li><strong>Active</strong> — The rule is live. It can be edited, which re-enters the lifecycle at "Submit Change Request" for the new version.</li>
        </ul>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Peer approval is intentional:</strong> You cannot approve your own change request. This dual-control
          requirement exists to catch logic errors, overly broad conditions, and misconfigured severity levels before
          they flood the alert queue with noise — or, worse, miss real threats. If you are the only admin, a second
          admin account must be created before rules can be promoted to Active.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rule Testing (Dry-Run Evaluation)</h3>
        <p className="text-muted-foreground mb-2">
          Before submitting a change request, use the <strong>Test Rule</strong> panel on the rule detail page.
          Paste a sample event as a JSON object into the input area and click "Run Test." The platform evaluates
          the rule's conditions against your sample event and reports whether the rule would have matched — along
          with which specific conditions triggered. This is a dry-run: no alert is created, no analyst is notified,
          and nothing is written to the database.
        </p>
        <p className="text-muted-foreground mb-2">
          Testing is available to all roles, including Viewers. You do not need admin privileges to test a rule
          against a sample event. This allows junior analysts to validate their understanding of a rule without
          risk. Testing with a real event sample (copied from a recent alert) is far more reliable than testing
          with a synthetic sample you constructed manually — real events contain all the edge-case fields that
          synthetic samples often omit.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rule History and Versioning</h3>
        <p className="text-muted-foreground mb-2">
          Every time a rule is saved, the previous version is archived. The <strong>Rule History</strong> tab
          on the rule detail page lists every version with its timestamp, the user who made the change, and the
          approval status. You can diff any two versions side by side to see exactly what changed in the YAML
          or JSON — useful when investigating why a rule's false positive rate changed after an update.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Rollback</h3>
        <p className="text-muted-foreground mb-2">
          If a rule update causes problems — spiking false positives, or a regression that stops matching real
          threats — you can roll back to any previous approved version in a single click. A mandatory reason
          field is provided when initiating a rollback, which is written to the audit log. The rollback itself
          counts as a new version in the history, so the audit trail is never broken. Rollbacks bypass the
          change request flow and take effect immediately, because speed matters when a noisy rule is flooding
          the queue.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Rollbacks are logged with the acting user, rollback reason, target version, and timestamp. This log
          entry is visible in both the rule history tab and the platform audit log under Settings → Audit Log.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Sigma Format Quick Reference</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><code>title</code>: Human-readable name for the rule. Use descriptive names — "Mimikatz LSASS Access" not "Rule 47."</li>
          <li><code>logsource.category</code>: The type of log this rule targets (e.g., <code>process_creation</code>, <code>network_connection</code>).</li>
          <li><code>logsource.product</code>: The source product (e.g., <code>windows</code>, <code>linux</code>).</li>
          <li><code>detection.keywords</code>: A list of strings; any match triggers the keyword set.</li>
          <li><code>detection.condition</code>: The boolean expression combining detection sets (e.g., <code>keywords</code>, <code>selection and not filter</code>).</li>
          <li><code>falsepositives</code>: Document known FP scenarios — peer reviewers will check this field.</li>
          <li><code>level</code>: Maps to rule severity: <code>low / medium / high / critical</code>.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Deploy a New Sigma Rule Safely</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Write the Sigma YAML in a text editor using the format above. Include <code>falsepositives</code>.</li>
          <li>Find or generate a real event JSON sample that should trigger the rule.</li>
          <li>Open Detection Rules → New Rule, paste the YAML, and use "Test Rule" with your sample event.</li>
          <li>Confirm the test shows a match. Adjust conditions if it does not.</li>
          <li>Also test with a known-benign event to verify you are not generating false positives.</li>
          <li>Save the rule and submit a change request with a description of what the rule detects and why.</li>
          <li>Notify a peer admin to review and approve the change request.</li>
          <li>After approval and activation, monitor the alert queue for 48 hours and check the false positive rate in rule stats.</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Roll Back a Noisy Rule</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Open the rule causing noise from the Detection Rules list.</li>
          <li>Go to Rule History and identify the last stable approved version (before the problematic update).</li>
          <li>Click "Rollback to this version" and enter a reason (e.g., "FP rate exceeded 40% after last update").</li>
          <li>Verify the alert queue normalises within the next polling cycle (typically 1–5 minutes).</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Admin:</strong> Create, edit, submit change requests, approve/reject change requests (not their own), delete, and rollback rules.</li>
          <li><strong>Senior Analyst / Analyst / Viewer:</strong> View all rules, view rule history, and test rules against sample events in dry-run mode.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Always test with a real event sample before creating a change request — synthetic samples miss edge-case fields.</li>
          <li>Set a calendar reminder to review the false positive rate 48 hours after any rule goes Active.</li>
          <li>Use descriptive rule names that convey the threat technique (e.g., "PowerShell Encoded Command Execution") rather than generic labels.</li>
          <li>Document known false positive scenarios in the <code>falsepositives</code> field — peer reviewers expect it.</li>
          <li>For Sigma rules sourced from public repositories, still test them against your environment before deploying; community rules are written for generic telemetry and may need tuning for your log schema.</li>
        </ul>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Approving your own change request (the UI prevents this, but never create a workaround);
          deploying without a dry-run test; using overly broad conditions like matching a single common keyword across all event
          types (generates enormous false positive volume); setting Critical severity on informational detections.
        </div>
      </div>
    ),
  },

  {
    id: 'resilience',
    name: 'Resilience',
    route: '/resilience',
    category: 'Enterprise',
    icon: 'ActivitySquare',
    tagline: 'Control plane for operational resilience — detection QA, secret rotation, tenant isolation, DR drills, and AI governance.',
    keywords: [
      'resilience', 'DR drill', 'disaster recovery', 'RPO', 'RTO', 'secret rotation',
      'API key', 'tenant isolation', 'detection QA', 'precision', 'recall', 'runbook',
      'dual control', 'approval', 'AI governance', 'hallucination', 'source quality',
      'tactic coverage', 'blind spot', 'monthly review',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Overview: Seven Control Areas</h3>
        <p className="text-muted-foreground mb-2">
          The Resilience page is the control plane for proving that your SOC infrastructure works correctly
          before an incident forces you to find out otherwise. It consolidates seven distinct operational
          health checks into a single dashboard, each targeting a different failure mode that can silently
          degrade your security posture. The philosophy here is simple: validate continuously, fix proactively,
          and document that you did — so when an auditor or incident responder asks "how do you know your
          detection pipeline was working before the breach?", you have evidence.
        </p>
        <p className="text-muted-foreground mb-2">
          The seven control areas are: Detection QA, Secret Rotation, Tenant Boundaries, Runbook Approvals,
          DR Drills, AI Governance, and Source Quality. Each is described in detail below.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">1. Detection QA</h3>
        <p className="text-muted-foreground mb-2">
          Detection QA replays a curated set of historical telemetry events against your active detection rules
          to measure how well the rules are performing in terms of precision and recall. <strong>Precision</strong>
          measures how often a rule fires on a real threat vs. a false positive — a precision of 80% means 80%
          of detections are genuine. <strong>Recall</strong> measures how many known-malicious events the rule
          catches — a recall of 70% means the rule detected 70% of the threat events in the test corpus.
        </p>
        <p className="text-muted-foreground mb-2">
          The QA gate passes when precision is at or above 70% AND recall is at or above 60%. Rules that fail
          the gate are flagged for review before the next promotion cycle. This prevents the common pattern of
          deploying a rule, forgetting about it, and then discovering months later that it has been generating
          mostly false positives or silently missing real attacks because the log schema changed.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Detection QA runs against historical telemetry, not live traffic. It is safe to run at any time and
          does not create alerts or notifications. Schedule it to run before any batch rule promotion.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">2. Secret Rotation</h3>
        <p className="text-muted-foreground mb-2">
          The Secret Rotation panel tracks every API key and credential configured in the platform and measures
          how long it has been since each was last rotated. Each credential is governed by a rotation policy
          with a configurable interval (default 90 days). When a credential exceeds its interval without
          rotation, it is marked as <strong>overdue</strong>. The overdue count is shown prominently at the
          top of the panel so it cannot be ignored.
        </p>
        <p className="text-muted-foreground mb-2">
          Stale API keys are one of the most common breach vectors in enterprise environments. A key that has
          not been rotated in 18 months may have been silently exfiltrated, shared across systems beyond its
          intended scope, or logged in a place it should not have been. Regular rotation limits the blast
          radius of any single credential compromise. The platform does not rotate credentials automatically —
          you must retrieve a new key from the upstream provider and paste it into Settings — but it tracks
          the rotation date and alerts you when you are overdue.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">3. Tenant Boundaries</h3>
        <p className="text-muted-foreground mb-2">
          If your deployment serves multiple tenants (e.g., an MSSP managing multiple client environments),
          the Tenant Boundaries panel runs a workspace isolation check to verify that no cross-tenant data
          collision has occurred. Each active workspace is listed with an isolation status badge:
          <strong>Isolated</strong> (green) or <strong>Collision Detected</strong> (red). A collision means
          that alert or asset data belonging to one tenant has appeared in another tenant's workspace — a
          serious data leakage condition that must be resolved before that tenant's data is considered
          trustworthy.
        </p>
        <p className="text-muted-foreground mb-2">
          Single-tenant deployments will show one workspace entry and can treat this panel as a sanity check.
          The isolation check runs a set of database-level queries that validate foreign key relationships,
          tenant_id field consistency, and API response scoping.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">4. Runbook Approvals</h3>
        <p className="text-muted-foreground mb-2">
          High-risk automated response actions — such as blocking an IP address, disabling a user account, or
          isolating an endpoint — queue here for dual-control approval before execution. Each pending action
          shows a risk level badge (<strong>High / Medium / Low</strong>), the requesting analyst, the
          requested action details, and the timestamp. An admin can approve or reject the action with a
          comment that is recorded in the audit log.
        </p>
        <p className="text-muted-foreground mb-2">
          Dual-control approval prevents a single analyst from unilaterally taking an action that could
          disrupt business operations (e.g., blocking a legitimate executive's IP address) or cause legal
          exposure (e.g., preserving evidence incorrectly). The risk classification of each action type is
          configurable in Settings → Runbook Configuration.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">5. DR Drills</h3>
        <p className="text-muted-foreground mb-2">
          Disaster Recovery drills are scheduled restore exercises that verify your backup and recovery
          procedures actually work. Each drill specifies a target system (e.g., "Alert Database," "Detection
          Rules Store"), an RPO target (Recovery Point Objective — maximum acceptable data loss, expressed in
          hours), and an RTO target (Recovery Time Objective — maximum acceptable downtime, expressed in hours).
        </p>
        <p className="text-muted-foreground mb-2">
          After a drill runs, the platform records the actual RPO achieved (how old was the most recent
          recoverable backup?) and the actual RTO achieved (how long did the restore take?). A Pass/Fail
          badge is shown based on whether actuals met targets. Failed drills must be investigated and
          remediated before the next scheduled drill cycle.
        </p>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Do not skip DR drills.</strong> "We haven't had an incident" is not evidence that your
          recovery process works — it is evidence that you haven't tested it. Quarterly drills at minimum
          are recommended; monthly drills for Tier 1 systems (auth, detection pipeline, evidence store).
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">6. AI Governance</h3>
        <p className="text-muted-foreground mb-2">
          AI Governance tracks analyst feedback on AI-generated analysis: alert summaries, threat actor
          attributions, and key fact extractions. Analysts submit feedback from the Alert Detail page →
          AI Analysis tab, rating each output on a scale of 1–5 and optionally flagging it as a
          <strong>hallucination</strong> (factually incorrect or invented content).
        </p>
        <p className="text-muted-foreground mb-2">
          The panel aggregates this feedback into three metrics: <strong>average rating</strong> (target ≥ 4.0),
          <strong>hallucination rate</strong> (percentage of AI outputs flagged as hallucinations — target &lt; 5%),
          and <strong>guardrail health status</strong> (whether the platform's AI safety filters are
          functioning correctly). If the hallucination rate exceeds threshold, the AI provider configuration
          should be reviewed — the model, temperature settings, or prompt templates may need adjustment.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">7. Source Quality</h3>
        <p className="text-muted-foreground mb-2">
          Source Quality measures how well each configured data source covers the MITRE ATT&CK framework.
          The quality score for each source is computed as: <strong>65% tactic coverage</strong> (how many
          ATT&CK tactics does this source have detections for?) plus <strong>35% source health</strong>
          (is the source actively ingesting and is its error rate low?). Sources with low scores are listed
          with their specific <strong>blind spots</strong> — tactic categories where no detections exist —
          so you can prioritise which new rules or additional data sources to add.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Monthly Resilience Review</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Open Resilience → Detection QA. Trigger a replay and review precision/recall for all active rules. Flag any below threshold.</li>
          <li>Check Secret Rotation. Rotate any overdue credentials immediately — do not defer.</li>
          <li>Verify Tenant Boundaries. Confirm all workspaces show "Isolated" status. Investigate any collision immediately.</li>
          <li>Review Runbook Approvals. Clear any pending approvals or rejections with documented reasoning.</li>
          <li>Run the scheduled DR drill for at least one Tier 1 system. Record actual RPO and RTO.</li>
          <li>Review AI Governance metrics. If hallucination rate has increased, audit recent AI outputs and adjust model settings.</li>
          <li>Document the review in your team's runbook log, including any findings and remediation actions taken.</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Admin:</strong> Full access to all resilience controls — can trigger QA replays, initiate DR drills, approve runbooks, and manage rotation policies.</li>
          <li><strong>SOC Lead / Senior Analyst:</strong> Can approve runbooks and submit AI feedback; view-only access to QA, rotation, and DR results.</li>
          <li><strong>Analyst / Viewer:</strong> Can submit AI feedback from the Alert Detail page; read-only access to Resilience panel.</li>
        </ul>

        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Tip:</strong> Export the Resilience summary as a PDF from the Reports page (Report type: Resilience Summary)
          to attach evidence of your monthly review to your security programme documentation or audit pack.
        </div>
      </div>
    ),
  },

  {
    id: 'assets',
    name: 'Assets',
    route: '/assets',
    category: 'Enterprise',
    icon: 'Server',
    tagline: 'Asset inventory with ownership, criticality scoring, enrichment from telemetry, and business-impact context.',
    keywords: [
      'assets', 'CMDB', 'inventory', 'hostname', 'IP', 'criticality', 'owner',
      'department', 'enrichment', 'confidence', 'crown jewel', 'entity pivot',
      'workstation', 'server', 'cloud', 'network', 'alert count', 'incident count',
      'business impact', 'triage', 'risk',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">What Is the Asset Register?</h3>
        <p className="text-muted-foreground mb-2">
          The Asset register is the SOC platform's built-in CMDB (Configuration Management Database). It maps
          technical systems — servers, workstations, network devices, cloud instances — to the business context
          that makes them meaningful during an incident: who owns them, what department they belong to, how
          critical they are to business operations, and what their current security posture looks like. Without
          this context, analysts triaging an alert on an IP address must hunt through Slack, wikis, and email
          to find out whether the affected system is a test box or a payment processing server. The asset
          register puts that context one click away.
        </p>
        <p className="text-muted-foreground mb-2">
          The register also acts as the backbone for risk prioritisation across the entire platform. When an
          alert fires on a host, the platform looks up the host's asset record and uses the criticality score
          to inform how urgently the alert should be reviewed. A High severity alert on a criticality-5 asset
          escalates automatically; the same alert on a criticality-1 dev box can wait.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Asset Fields</h3>
        <p className="text-muted-foreground mb-2">
          Each asset record stores the following information:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Hostname / IP address:</strong> The primary identifier. Can be a DNS hostname, static IP, or cloud instance ID.</li>
          <li><strong>Asset type:</strong> One of Server, Workstation, Network Device, or Cloud Instance. Used for filtering and reporting.</li>
          <li><strong>Owner:</strong> The person or team responsible for this asset. This is who gets contacted during an incident involving this host.</li>
          <li><strong>Department:</strong> The business unit the asset belongs to (e.g., Engineering, Finance, HR).</li>
          <li><strong>Criticality:</strong> A score from 1 to 5 indicating business impact (see scale below).</li>
          <li><strong>Open alerts count:</strong> The number of currently unresolved alerts linked to this asset, updated on each enrichment pass.</li>
          <li><strong>Open incidents count:</strong> The number of currently open incidents that include this asset.</li>
          <li><strong>Confidence score:</strong> Automatically computed from telemetry richness (0–100%). See below.</li>
          <li><strong>Last enriched:</strong> Timestamp of the most recent enrichment run for this asset.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Criticality Scale</h3>
        <p className="text-muted-foreground mb-2">
          The criticality scale is the most important field in the asset register. Set it accurately before
          alerts start arriving — recalibrating criticality during an active incident is stressful and error-prone.
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>1 — Test / Development:</strong> Non-production systems with no sensitive data. A compromise has minimal business impact.</li>
          <li><strong>2 — Internal Tools:</strong> Internal-facing systems (wikis, ticketing, internal dashboards). Compromise affects productivity but not customer data.</li>
          <li><strong>3 — Business Systems:</strong> Core business applications used daily (ERP, CRM, HR systems). Compromise disrupts business operations.</li>
          <li><strong>4 — Customer-Facing:</strong> Systems that directly serve customers (web app, API gateways). Compromise affects customer experience and may expose customer data.</li>
          <li><strong>5 — Crown Jewel:</strong> The most critical systems: payment processing, authentication infrastructure, data warehouses, secrets management. A compromise at this level is a major incident by definition.</li>
        </ul>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Review your criticality-5 assets monthly. Changes in the business (new products, infrastructure migrations,
          acquisitions) can mean previously lower-criticality assets now deserve a 5 rating. An outdated asset
          register can cause analysts to under-prioritise alerts on what are now crown jewel systems.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Confidence Score</h3>
        <p className="text-muted-foreground mb-2">
          The confidence score (0–100%) measures how much telemetry enrichment data exists for an asset. An
          asset created 10 minutes ago with no linked alerts has a confidence score near zero — the platform
          knows it exists but has little evidence about its behaviour or security posture. An asset that has
          been actively generating telemetry for months, has multiple linked alerts that were investigated and
          resolved, and has had several enrichment passes will have a high confidence score. High-confidence
          assets give analysts more context to work with during triage.
        </p>
        <p className="text-muted-foreground mb-2">
          The confidence score is computed automatically during enrichment runs. You cannot manually set it,
          but you can trigger an enrichment pass at any time to ensure it reflects the current state of
          telemetry.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Enrichment</h3>
        <p className="text-muted-foreground mb-2">
          Click the <strong>Enrich</strong> button on any asset record to trigger a telemetry reconciliation pass.
          During enrichment, the platform:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Queries all alerts in the system for any that reference this asset's hostname or IP.</li>
          <li>Updates the open alerts count and open incidents count fields.</li>
          <li>Recalculates the confidence score based on the volume and recency of linked telemetry.</li>
          <li>Records the "last enriched" timestamp.</li>
        </ul>
        <p className="text-muted-foreground mb-2">
          Enrichment is not automatic on a schedule by default — trigger it manually when you need current data,
          or set up a scheduled enrichment job via the API for high-criticality assets. Always enrich an asset
          before using its data to make incident response decisions if the last enriched timestamp is more than
          24 hours old.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Entity Pivot: Context Without Leaving the Page</h3>
        <p className="text-muted-foreground mb-2">
          One of the most workflow-accelerating features of the asset register is the <strong>entity pivot panel</strong>.
          On the Alerts page or the Incidents page, click any IP address or hostname in a table row and a
          slide-out panel appears immediately on the right side of the screen. This panel shows the full asset
          record for that entity — criticality, owner, department, open alert count, open incident count, and
          confidence score — along with a list of the most recent alerts linked to that asset.
        </p>
        <p className="text-muted-foreground mb-2">
          The pivot panel means you never have to open a new tab, navigate away from your triage queue, or
          copy-paste a hostname into a search box. Asset context is always one click away from any alert or
          incident. During high-tempo incident response, this reduces cognitive load significantly.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Asset Search and Filtering</h3>
        <p className="text-muted-foreground mb-2">
          The asset list page supports filtering by asset type, department, criticality level, and free-text
          search across hostname, IP, and owner fields. Use criticality filters to quickly identify all
          crown-jewel assets, or department filters to scope your view during a business-unit-specific
          investigation.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Register a New Critical Server</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Open Assets → New Asset. Enter the hostname and IP address.</li>
          <li>Set Asset Type to "Server" and Criticality to 4 or 5 depending on business function.</li>
          <li>Assign an Owner (the team or individual responsible) and the correct Department.</li>
          <li>Save the asset, then click "Enrich" immediately to pull in any existing telemetry.</li>
          <li>Navigate to the Alerts page and filter by this host's IP to confirm that new alerts are correctly linking to the asset record.</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Use Asset Context During Alert Triage</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>On the Alerts page, identify an alert on an unfamiliar host.</li>
          <li>Click the host's IP or hostname to open the entity pivot panel.</li>
          <li>Review criticality, owner, and open incident count without leaving the alerts view.</li>
          <li>Adjust your response priority based on criticality — a High alert on a criticality-5 host warrants immediate escalation.</li>
          <li>If criticality is 5 and there are multiple open incidents, page the asset owner immediately.</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Admin:</strong> Full CRUD access — create, view, update, delete assets, and trigger enrichment.</li>
          <li><strong>Analyst / Senior Analyst:</strong> Can create, view, update assets, and trigger enrichment. Cannot delete.</li>
          <li><strong>Viewer:</strong> Read-only access to asset records and the entity pivot panel.</li>
        </ul>

        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Tip:</strong> Do not leave the Owner field blank. During an active incident at 2am, you need to
          know who to call in 30 seconds — not spend 20 minutes hunting through org charts. Every asset should
          have a named owner or team before it reaches production status.
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Leaving criticality at the default value of 1 (every asset looks
          equally unimportant); not assigning an owner (no accountability during incidents); failing to enrich
          assets with active incidents (stale alert counts lead to incorrect risk assessment).
        </div>
      </div>
    ),
  },

  {
    id: 'settings',
    name: 'Settings',
    route: '/settings',
    category: 'Enterprise',
    icon: 'Settings2',
    tagline: 'Platform configuration — integrations, AI provider, user management, security settings, and audit governance.',
    keywords: [
      'settings', 'configuration', 'API key', 'integration', 'connector', 'AI provider',
      'OpenAI', 'Claude', 'Gemini', 'Bedrock', 'Groq', 'Mistral', 'Ollama', 'users',
      'roles', 'RBAC', 'SSO', 'SAML', 'OIDC', 'LDAP', 'MFA', 'session timeout',
      'audit log', 'scheduled reports', 'secret rotation', 'admin',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Settings Overview</h3>
        <p className="text-muted-foreground mb-2">
          The Settings page is the administrative control centre for the SOC platform. It is divided into six
          sections, each governing a different aspect of platform configuration: Source Integrations, AI
          Configuration, Users &amp; Roles, Security, Scheduled Reports, and Audit Log. Access to the Settings
          page is restricted to Admins — no other role can view or modify these configurations.
        </p>
        <p className="text-muted-foreground mb-2">
          Every change made in Settings is automatically recorded in the Audit Log with the old value, new
          value, the user who made the change, and the timestamp. Sensitive values such as API keys and
          passwords are redacted in log entries — you will see <code>[REDACTED]</code> rather than the actual
          secret, which means the audit log is safe to export and share with auditors without exposing
          credentials.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Source Integrations</h3>
        <p className="text-muted-foreground mb-2">
          Source integrations configure the data connectors that pull telemetry into the platform. Each
          configured source has its own settings section where you enter API keys or credentials, the base
          endpoint URL, and the polling interval (how frequently the connector fetches new data — default
          typically 60 seconds for most sources).
        </p>
        <p className="text-muted-foreground mb-2">
          Before saving any integration configuration, click <strong>Test Connection</strong>. This sends an
          authenticated request to the upstream API and reports success or failure immediately. Saving without
          testing can result in silent ingestion failure — the platform will show the source as configured,
          but no data will flow in. This is one of the most common causes of "why aren't we seeing alerts from
          [Source X]?" questions.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Source health metrics (connection status, last successful ingest timestamp, error rate) are visible
          on the Sources page. After saving a new integration, navigate to Sources to confirm the health
          indicator turns green within the first polling cycle.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">AI Configuration</h3>
        <p className="text-muted-foreground mb-2">
          The AI Configuration section controls which AI provider powers the platform's analysis features:
          alert summarisation, threat actor attribution, key fact extraction, and the AI assistant. The
          platform supports the following providers: <strong>OpenAI, Anthropic Claude, Google Gemini,
          Azure OpenAI, Amazon Bedrock, Groq, Mistral,</strong> and <strong>Ollama</strong> (for
          on-premises/air-gapped deployments). Only one provider is active at a time.
        </p>
        <p className="text-muted-foreground mb-2">
          To configure an AI provider, select it from the dropdown, paste the API key (or endpoint URL for
          Azure/Bedrock/Ollama), specify the model name (e.g., <code>gpt-4o</code>, <code>claude-3-5-sonnet-20241022</code>,
          <code>gemini-1.5-pro</code>), and click <strong>Test Connection</strong>. The platform sends a
          minimal test prompt to verify the key is valid and the model is accessible. Save only after a
          successful test.
        </p>
        <p className="text-muted-foreground mb-2">
          For Ollama (local model hosting), the endpoint is typically <code>http://localhost:11434</code>.
          Ollama is the recommended choice for environments where data cannot leave the network for compliance
          or classification reasons.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Users &amp; Roles</h3>
        <p className="text-muted-foreground mb-2">
          User management is handled in Settings → Users &amp; Roles. Admins can create new user accounts,
          assign or change roles, reset passwords, view the per-user activity log, and revoke active sessions.
          The platform uses role-based access control (RBAC) with the following roles, in ascending order of
          privilege:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Viewer:</strong> Read-only access to alerts, incidents, assets, and reports.</li>
          <li><strong>Analyst:</strong> Can triage alerts, create and update incidents, manage assets.</li>
          <li><strong>Senior Analyst:</strong> All Analyst permissions plus runbook approvals, detection rule testing, and scheduled reports access.</li>
          <li><strong>Admin:</strong> Full platform access including Settings, user management, rule lifecycle approval, and deletion operations.</li>
        </ul>
        <p className="text-muted-foreground mb-2">
          Session revocation is available on a per-user basis. If an account is compromised or a user leaves
          the organisation, immediately revoke all their active sessions from the user detail page — this
          invalidates all existing tokens without requiring a password reset first.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">SSO and LDAP</h3>
        <p className="text-muted-foreground mb-2">
          For enterprise environments, Settings → SSO/LDAP enables Single Sign-On and directory-based user
          provisioning. The platform supports:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>SAML 2.0:</strong> Configure an Identity Provider (IdP) metadata URL and the platform's Service Provider (SP) entity ID and ACS URL. Compatible with Okta, Azure AD, Google Workspace, Ping Identity, and others.</li>
          <li><strong>OIDC (OpenID Connect):</strong> Configure the issuer URL, client ID, and client secret. Compatible with Auth0, Keycloak, Azure AD, and others.</li>
          <li><strong>LDAP / Active Directory:</strong> Configure server URL, bind DN, bind password, user search base, and attribute mappings. Sync runs on a configurable schedule to provision and deprovision users automatically.</li>
          <li><strong>Group-to-role mapping:</strong> Map directory groups (e.g., <code>CN=SOC-Analysts</code>) to platform roles so that new analysts automatically receive the Analyst role when their account is provisioned.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Security Settings</h3>
        <p className="text-muted-foreground mb-2">
          The Security section controls session and authentication policies:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Session timeout:</strong> Idle session expiration in minutes. Default 30 minutes. Users are warned 5 minutes before expiration and can extend.</li>
          <li><strong>Maximum concurrent sessions:</strong> Limit how many simultaneous sessions a single user account can maintain. Default 3. Set to 1 for admin accounts for maximum security.</li>
          <li><strong>MFA settings:</strong> Enable or disable multi-factor authentication platform-wide. When enabled, all users must enroll a TOTP authenticator at next login.</li>
          <li><strong>Blocked token management:</strong> View and manage the list of invalidated JWTs (e.g., from compromised sessions or forced logouts). Entries expire automatically after the original token TTL.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Scheduled Reports</h3>
        <p className="text-muted-foreground mb-2">
          Create automated report delivery jobs in Settings → Scheduled Reports. Each report job specifies:
          the report type (Executive Summary, Alert Volume, Incident Timeline, Resilience Summary, MITRE
          Coverage), the frequency (daily / weekly / monthly), the delivery time, and the recipient email
          addresses. Reports are rendered as PDFs and emailed at the scheduled time.
        </p>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Use a shared team mailbox (e.g., <code>soc-reports@company.com</code>) as the recipient rather
          than personal email addresses. When an individual leaves the organisation, personal email recipients
          silently bounce — a shared mailbox ensures continuity and is easier to audit.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Audit Log</h3>
        <p className="text-muted-foreground mb-2">
          The Audit Log in Settings is a tamper-evident, append-only record of all administrative actions
          across the platform. Every settings change, user creation, role assignment, rule approval, and
          playbook execution is logged with: the action type, the entity affected, the old value, the new
          value (API keys and passwords redacted), the user who performed the action, and the timestamp.
          The log can be filtered by date range, action type, and user, and can be exported as CSV for
          integration with SIEM or compliance tools.
        </p>
        <p className="text-muted-foreground mb-2">
          Review the audit log monthly to check for unexpected changes — particularly unexpected role
          escalations, new admin account creations, or API key updates outside of your standard rotation
          schedule. Anomalies in the audit log are often early indicators of insider threat or compromised
          admin credentials.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Rotate an AI Provider API Key</h3>
        <ol className="list-decimal pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Generate a new API key from the AI provider's dashboard (OpenAI, Anthropic, etc.). Do not revoke the old key yet.</li>
          <li>Navigate to Settings → AI Configuration. Paste the new key into the API Key field (the old key is not shown, only a masked placeholder).</li>
          <li>Click "Test Connection." Confirm the test succeeds with the new key.</li>
          <li>Click "Save." The platform begins using the new key immediately for all AI requests.</li>
          <li>Navigate to an alert and open the AI Analysis tab. Trigger a new summary to verify end-to-end functionality with the new key.</li>
          <li>Revoke the old key from the provider's dashboard. Record the rotation date in your secret inventory.</li>
        </ol>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Admin:</strong> Full access to all Settings sections.</li>
          <li><strong>Senior Analyst:</strong> Read-only access to Scheduled Reports (can view but not create or modify report jobs).</li>
          <li><strong>Analyst / Viewer:</strong> No access to Settings. Attempting to navigate to /settings redirects to the dashboard with a permission error.</li>
        </ul>

        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Best practices:</strong> Always click "Test Connection" before saving any integration or AI key.
          Rotate API keys every 90 days — use the Resilience → Secret Rotation panel to track overdue keys.
          Review the Audit Log monthly for unexpected changes. Never share admin credentials — each administrator
          should have their own named account so that audit log entries are attributable to an individual.
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Saving integration API keys without running "Test Connection" first
          (causes silent ingest failure that may go undetected for hours); using personal email addresses for
          scheduled report recipients (breaks when the person leaves); sharing a single admin account across
          multiple people (makes audit log attribution impossible and violates least-privilege principles).
        </div>
      </div>
    ),
  },
]

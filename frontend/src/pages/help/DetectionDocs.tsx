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

export const DETECTION_DOCS: SocDetailDoc[] = [
  {
    id: 'incidents',
    name: 'Incidents',
    route: '/incidents',
    category: 'Detection & Response',
    icon: 'shield-alert',
    tagline: 'Correlated attack threads — multiple related alerts grouped into a single coordinated response unit.',
    keywords: [
      'incident', 'response', 'escalate', 'triage', 'timeline', 'containment',
      'analyst', 'severity', 'lifecycle', 'evidence', 'notes', 'assets', 'attack campaign',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Incidents vs Alerts</h3>
        <p className="text-muted-foreground mb-2">
          An <strong>alert</strong> is a single detection event — one rule fired against one data point. An{' '}
          <strong>incident</strong> is a correlated group of alerts that together tell the story of a coordinated
          attack or security breach. Where an alert answers "what happened right now?", an incident answers "what
          is the attacker trying to accomplish, and how far have they gotten?" Multiple alerts across different
          sources, hosts, or time windows are stitched together into one incident so your team can manage the
          response as a unified campaign rather than chasing dozens of individual detections in parallel.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Example: A phishing email alert, a credential stuffing alert 30 minutes later, and a lateral movement
          alert an hour after that are all part of the same attacker chain. Grouping them into one incident lets
          a single analyst own the full response narrative instead of three analysts working in isolation.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Incident Lifecycle</h3>
        <p className="text-muted-foreground mb-2">
          Every incident moves through a defined lifecycle. Understanding each stage helps your team communicate
          status clearly and ensures no incident is left in an ambiguous state.
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Open</strong> — newly created, not yet assigned or investigated. Requires immediate triage to determine scope and urgency.</li>
          <li><strong>In Progress</strong> — an analyst has taken ownership and active investigation or containment is underway.</li>
          <li><strong>Contained</strong> — the threat has been isolated (e.g., host quarantined, account disabled) but the incident is not yet fully resolved or documented.</li>
          <li><strong>Closed</strong> — remediation is complete, a closure reason is documented, and any post-mortem notes have been added. Closed incidents are read-only for non-admins.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Incident Card — Key Fields</h3>
        <p className="text-muted-foreground mb-2">
          Each incident card in the list view surfaces the most critical contextual fields at a glance so analysts
          can prioritize without opening every incident:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Severity</strong> — aggregated from the highest-severity linked alert (Critical, High, Medium, Low).</li>
          <li><strong>Open alert count</strong> — number of linked alerts that are still in an unresolved state.</li>
          <li><strong>Affected assets</strong> — unique hostnames and usernames observed across all linked alerts.</li>
          <li><strong>MITRE tactic chain</strong> — the ordered sequence of ATT&CK tactics detected across the linked alerts, showing attacker progression.</li>
          <li><strong>Assigned analyst</strong> — the team member currently owning the incident response.</li>
          <li><strong>Timeline last updated</strong> — timestamp of the most recent action or note, indicating whether the incident is actively worked.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Incident Detail Page — Tabs</h3>
        <p className="text-muted-foreground mb-2">
          Clicking an incident opens the Incident Detail page, organised into six tabs:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Overview</strong> — incident summary card, severity, status, assigned analyst, and the AI-generated narrative connecting the alert chain. This is the first tab to check when picking up an incident from a colleague.</li>
          <li><strong>Alerts</strong> — the full table of linked alerts. Each row is clickable and opens the Alert Detail view without losing incident context. From here you can also link additional alerts or unlink incorrectly grouped ones.</li>
          <li><strong>Assets</strong> — deduplicated list of all affected hosts and accounts with pivot links to their full alert history. Use this tab to understand blast radius.</li>
          <li><strong>Timeline</strong> — immutable, chronological audit trail of every status change, analyst action, comment, and evidence attachment. Cannot be edited or deleted.</li>
          <li><strong>Notes</strong> — freeform analyst working notes. Unlike timeline entries (which are automatic), notes must be added manually. Notes support markdown for structured runbook output.</li>
          <li><strong>Evidence</strong> — file attachments such as packet captures, memory dumps, screenshots, and exported logs. Each attachment records the uploader and timestamp.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">AI Summary</h3>
        <p className="text-muted-foreground mb-2">
          When an incident is created or new alerts are linked, the platform automatically generates an AI narrative
          on the Overview tab. The summary reads across all linked alert data — source IPs, usernames, MITRE
          techniques, timing, and affected assets — and produces a plain-English attack story. It highlights the
          probable initial access vector, progression through kill-chain stages, and the likely attacker objective.
          The AI summary is a starting point for investigation; it does not replace analyst judgment, and you should
          always validate its conclusions against raw alert data.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Creating an Incident</h3>
        <p className="text-muted-foreground mb-2">
          Incidents can be created two ways. From the Incidents page, click <strong>New Incident</strong> in the
          top-right corner, fill in the title, severity, and description, then save. Alternatively, from any Alert
          Detail page, open the action menu and choose <strong>Escalate to Incident</strong> — this creates a new
          incident pre-linked to that alert. You can also link additional alerts from the Alerts tab using the
          <strong>Link to Incident</strong> action in the alert row action menu, or by dragging alert rows into
          the incident from the Alerts page.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Respond to a Ransomware Incident</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Step 1 — Identify the incident in the Open queue and assign it to yourself to prevent duplicate work.</li>
          <li>Step 2 — Set status to <strong>In Progress</strong> and add a timeline note with your initial assessment.</li>
          <li>Step 3 — Review the Alerts tab; link any additional related alerts you find via threat hunting or correlation.</li>
          <li>Step 4 — Review the Assets tab; identify the primary infected host and any accounts with suspicious activity.</li>
          <li>Step 5 — Trigger the ransomware containment playbook (or manually isolate the host and disable affected accounts).</li>
          <li>Step 6 — Set status to <strong>Contained</strong> and attach evidence (quarantine confirmation, IOC list) to the Evidence tab.</li>
          <li>Step 7 — Add a detailed note documenting root cause, attacker actions, and remediation steps taken.</li>
          <li>Step 8 — Set status to <strong>Closed</strong> with a closure reason and post-mortem note. Notify stakeholders.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Viewer</strong> — read-only access to all incident tabs; cannot update status, add notes, or link alerts.</li>
          <li><strong>Analyst</strong> — can update incident status, add notes, link/unlink alerts, and upload evidence.</li>
          <li><strong>Senior Analyst</strong> — coordinates multi-analyst response, can reassign ownership, and approve playbook executions tied to the incident.</li>
          <li><strong>Admin</strong> — full access including deletion, bulk operations, and overriding closure states.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Create <strong>one incident per attack campaign</strong>, not one per alert. Fragmenting a campaign across multiple incidents makes it impossible to see the full picture.</li>
          <li>Update the incident status promptly at each transition — stale "Open" incidents mislead dashboard metrics and SLA tracking.</li>
          <li>Add timeline notes even for small actions (e.g., "Checked firewall logs — no outbound connections found"). Future analysts and auditors need the full record.</li>
        </ul>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Creating duplicate incidents for the same attacker campaign is the most
          frequent error — always search existing incidents before creating a new one. Closing an incident without a
          closure reason and post-mortem note leaves the team without lessons learned and breaks compliance audit trails.
        </div>
      </div>
    ),
  },

  {
    id: 'mitre',
    name: 'MITRE Coverage',
    route: '/mitre',
    category: 'Detection & Response',
    icon: 'grid-3x3',
    tagline: 'ATT&CK heatmap showing technique detection coverage — identify blind spots before attackers exploit them.',
    keywords: [
      'mitre', 'att&ck', 'heatmap', 'technique', 'tactic', 'coverage', 'gap', 'detection engineering',
      'blind spot', 'purple team', 'adversary', 'kill chain', 'prevalence', 'source quality',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">What is MITRE ATT&CK?</h3>
        <p className="text-muted-foreground mb-2">
          MITRE ATT&CK is a globally accessible, curated knowledge base of adversary tactics and techniques based
          on real-world observations. It organises attacker behaviour into <strong>14 tactics</strong> — high-level
          goals an attacker pursues — and over <strong>200 techniques</strong> — the specific methods used to achieve
          those goals. ATT&CK is the industry-standard language for describing how attacks work, and mapping your
          detections to it tells you exactly where your security controls are strong and where attackers could
          operate undetected.
        </p>
        <p className="text-muted-foreground mb-2">
          The 14 tactics in order of the attack lifecycle are: Reconnaissance, Resource Development, Initial Access,
          Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral
          Movement, Collection, Command &amp; Control, Exfiltration, and Impact. Each tactic column in the heatmap
          represents one of these goals, and each cell within a column represents a specific technique an attacker
          might use to achieve it.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Reading the Heatmap</h3>
        <p className="text-muted-foreground mb-2">
          The MITRE Coverage heatmap renders every ATT&CK technique as a coloured cell. The colour encodes how
          strongly your environment detects activity matching that technique:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Grey</strong> — no detections for this technique in the selected time window. A blind spot.</li>
          <li><strong>Blue</strong> — some detections; the technique is partially covered but the signal volume is low.</li>
          <li><strong>Green</strong> — strong detection signal; multiple detections from one or more sources in the window.</li>
        </ul>
        <p className="text-muted-foreground mb-2">
          Coverage is <strong>live</strong> — cells update as new alerts arrive. When an alert is tagged with a MITRE
          technique (either by a detection rule or by the AI tagger), that cell increments its count and may change
          colour. This means the heatmap is always a reflection of what your active detection stack is actually seeing,
          not a theoretical assessment.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Hovering over any cell shows the technique name, MITRE ID (e.g., T1059), detection count in the current
          window, and the list of alert sources contributing to that coverage. Click the cell to drill into the
          matching alerts.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Coverage Score</h3>
        <p className="text-muted-foreground mb-2">
          The coverage score shown at the top of the page is the percentage of ATT&CK techniques for which you have
          at least one detection in the last 30 days (configurable via the time-window filter). It is a high-level
          KPI — useful for tracking progress quarter over quarter — but should always be interpreted alongside
          detection quality, not just quantity. A technique covered by a single low-confidence rule is technically
          "covered" but offers weak protection. Track coverage score alongside alert-to-incident conversion rates
          for a fuller picture.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Source Quality View</h3>
        <p className="text-muted-foreground mb-2">
          From the heatmap, you can pivot to the Source Quality view, which breaks down which of your connected
          data sources contribute detections for each tactic. This helps identify source gaps — for example, if
          Lateral Movement techniques are entirely covered by a single EDR source and you have no network-layer
          source, your coverage is brittle. Diversifying sources across tactics is as important as raw technique
          coverage numbers.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Gap Analysis</h3>
        <p className="text-muted-foreground mb-2">
          The <strong>Uncovered Techniques</strong> panel lists all grey (zero-detection) techniques sorted
          descending by MITRE prevalence score — a measure of how frequently the technique is observed in real-world
          attacks. Techniques at the top of this list represent the highest-priority gaps: they are both common in
          attacker toolkits and completely undetected in your environment. Use this list as your detection
          engineering backlog.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Using MITRE for Detection Engineering</h3>
        <p className="text-muted-foreground mb-2">
          The heatmap is most powerful as a feedback loop for your detection engineering process. Identify a grey
          high-prevalence cell, research the technique in the MITRE ATT&CK knowledge base to understand its data
          sources and detection logic, write or import a detection rule targeting that technique, onboard the
          required log source if missing, and then watch the cell turn blue or green as alerts flow in. Each
          iteration measurably improves your coverage score and reduces attacker dwell time.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Conduct a Quarterly Coverage Review</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Step 1 — Set the time window to 90 days to get a quarterly view of detection activity.</li>
          <li>Step 2 — Note the overall coverage score and compare to last quarter's baseline.</li>
          <li>Step 3 — Sort the Uncovered Techniques list by prevalence score; prioritise the top 10 gaps.</li>
          <li>Step 4 — For each gap, check the Source Quality view — is the log source missing or is the rule missing?</li>
          <li>Step 5 — File detection engineering tickets for rule gaps; file source onboarding tickets for data gaps.</li>
          <li>Step 6 — Export the heatmap (PDF) for the monthly security report and stakeholder briefing.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Detection Engineer</strong> — primary user; drives gap analysis and translates gaps into detection rules.</li>
          <li><strong>SOC Architect</strong> — uses coverage data for strategic source onboarding decisions and control investment planning.</li>
          <li><strong>Purple Team</strong> — maps adversary simulation exercises to ATT&CK IDs and validates that simulated techniques light up correctly in the heatmap after exercises.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Review the heatmap immediately after onboarding a new data source to verify it contributes new technique coverage.</li>
          <li>Track coverage percentage as a formal KPI in monthly security reports — it creates accountability for the detection engineering programme.</li>
          <li>When consuming threat intelligence reports (CTI), map the mentioned TTPs to ATT&CK IDs before writing detection rules. This ensures the resulting rules improve targeted coverage.</li>
        </ul>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Assuming a high coverage percentage means strong security. Noisy detection
          rules that fire frequently on benign activity inflate technique counts and make cells green — but they are
          generating false positives, not real detections. Always validate coverage quality alongside quantity. Also
          avoid leaving the time window at a very short range (e.g., 1 day) and drawing conclusions about overall
          coverage from a period with low alert volume.
        </div>
      </div>
    ),
  },

  {
    id: 'hunting',
    name: 'Threat Hunting',
    route: '/hunting',
    category: 'Detection & Response',
    icon: 'search-code',
    tagline: 'Hypothesis-driven workspace for proactive threat hunting — saved queries, run history, and pivot-to-alert.',
    keywords: [
      'threat hunting', 'hunt', 'query', 'hypothesis', 'proactive', 'detection', 'saved hunts',
      'lateral movement', 'anomaly', 'pivot', 'results', 'rule', 'create rule', 'history', 'analyst',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">What is Threat Hunting?</h3>
        <p className="text-muted-foreground mb-2">
          Threat hunting is the proactive, human-driven search for threats that have evaded your automated detection
          rules. Where detection rules catch known-bad patterns, threat hunting starts with a <strong>hypothesis</strong>
          — an educated guess about attacker behaviour based on threat intelligence, anomalies in data, or security
          intuition — and then searches the alert and event database to confirm or refute it. Good hunters find
          intrusions that have been sitting undetected in environments for weeks or months, well before any automated
          alert would have fired.
        </p>
        <p className="text-muted-foreground mb-2">
          Hunting is not alert triage. It does not start with an alert; it starts with a question. The discipline
          requires experience, curiosity, and structured thinking. Results that confirm a hypothesis should be
          escalated to incidents and used to build new detection rules so the next instance is caught automatically.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Hunt Workspace Layout</h3>
        <p className="text-muted-foreground mb-2">
          The Threat Hunting page is divided into four panels:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Query editor</strong> — the main input area where you write and refine hunt queries. Supports field-based filtering with boolean logic.</li>
          <li><strong>Saved hunts list</strong> — left sidebar showing all previously saved hunt queries, each with its name, last run date, and result count from the last run.</li>
          <li><strong>Run history</strong> — a tab within the results area showing previous executions of the current query, with timestamps and result counts. Enables you to see whether a pattern is growing or shrinking over time.</li>
          <li><strong>Results panel</strong> — the main output area showing matching events in a tabular format. Supports sorting, column customisation, and row-level pivots.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Writing Hunt Queries</h3>
        <p className="text-muted-foreground mb-2">
          Hunt queries use a structured field-filter syntax. The following fields are available across all alert data:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>source_ip</strong> — originating IP address of the event.</li>
          <li><strong>dest_ip</strong> — destination IP address.</li>
          <li><strong>category</strong> — alert category (e.g., "lateral_movement", "credential_access").</li>
          <li><strong>severity</strong> — critical, high, medium, or low.</li>
          <li><strong>risk_score</strong> — numeric risk score 0–100 assigned by the detection engine.</li>
          <li><strong>mitre_technique</strong> — ATT&CK technique ID (e.g., "T1078") or name.</li>
          <li><strong>hostname</strong> — affected host name.</li>
          <li><strong>username</strong> — associated user account.</li>
          <li><strong>raw</strong> — full-text search across the raw event payload (slower; use sparingly on large datasets).</li>
        </ul>
        <p className="text-muted-foreground mb-2">
          Combine filters with AND, OR, and NOT operators and use parentheses for grouping. For example:
          <code className="ml-1 rounded bg-muted px-1 py-0.5 text-xs">category:lateral_movement AND severity:high AND NOT hostname:dc01</code>
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Saved Hunts</h3>
        <p className="text-muted-foreground mb-2">
          Any query can be saved as a named hunt. Saved hunts store the query text, a human-readable description,
          and optionally a hypothesis statement. They are persisted server-side and visible to all analysts with
          Analyst role or above. When you load a saved hunt, the last run results are displayed immediately so you
          can compare against a fresh run without waiting. Over time, your saved hunts library becomes a valuable
          institutional knowledge base of investigative techniques.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Running a Hunt and Pivoting</h3>
        <p className="text-muted-foreground mb-2">
          Click <strong>Run</strong> to execute the current query against the full alert database. Results appear
          in the panel below. Every result row is clickable — clicking opens the full Alert Detail page for that
          event in a side panel so you can inspect raw data, linked incidents, and analyst notes without losing
          your hunt context. If a result looks suspicious enough to warrant investigation, use the <strong>Escalate
          to Incident</strong> action directly from the hunt result row.
        </p>
        <p className="text-muted-foreground mb-2">
          When a hunt query proves to be a reliable detector of malicious behaviour, click <strong>Create Rule from
          Hunt</strong> to convert the query into a custom detection rule. This closes the loop from reactive
          hunting to proactive automated detection.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Hypothesis Examples</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>"Are there successful logins from countries where we have no employees?" — hunt for geographic anomalies in authentication events.</li>
          <li>"Which hosts had both a failed login alert and a lateral movement alert within the same hour?" — detect post-compromise pivoting.</li>
          <li>"Are any service accounts authenticating interactively?" — service accounts should never have interactive sessions.</li>
          <li>"Is there any outbound traffic to known TOR exit nodes?" — detect data exfiltration or C2 via anonymisation networks.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Run a Lateral Movement Hunt</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Step 1 — Form your hypothesis: "Attackers with initial access to workstations are pivoting to servers using compromised credentials."</li>
          <li>Step 2 — Write a query targeting lateral movement category alerts on server hostnames in the past 7 days.</li>
          <li>Step 3 — Run the query and review the result set. Look for patterns in usernames and source hosts.</li>
          <li>Step 4 — Refine the query to exclude known-good automation accounts (use NOT username:svc_deploy).</li>
          <li>Step 5 — For any suspicious rows, pivot to Alert Detail and check for correlated events on the same source host.</li>
          <li>Step 6 — If confirmed malicious, escalate to an incident and link all related alerts.</li>
          <li>Step 7 — Save the refined query as a saved hunt named "Lateral Movement — Server Targets" and use Create Rule from Hunt to automate future detection.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Senior Analyst and above</strong> — primary hunters. Hunting requires experience to form meaningful hypotheses and interpret ambiguous results. Running poorly formed queries wastes resources and produces misleading conclusions.</li>
          <li><strong>Junior Analysts</strong> — can view saved hunts and run existing named hunts to get familiar with the tooling, but should not create or modify hunt queries without supervision.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Always write your hypothesis down in the hunt description field before running — it keeps your investigation focused and is valuable context for colleagues reviewing your saved hunts later.</li>
          <li>Save negative results too. A hunt that found nothing proves coverage for that hypothesis, which is itself evidence of a healthy detection programme.</li>
          <li>Time-box hunts to 2 hours maximum per session. Open-ended hunting without constraints is inefficient; if you haven't found meaningful signal in 2 hours, reformulate the hypothesis.</li>
        </ul>

        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Tip:</strong> The most productive hunts start from threat intelligence. When you receive a CTI report
          mentioning specific techniques or IOCs, immediately translate them into hunt queries. This directly validates
          whether you would have detected the described attack in your environment.
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Hunting without a hypothesis — sometimes called a "fishing expedition" —
          produces overwhelming, unstructured data that is difficult to interpret. Always start with a specific
          question. Equally, failing to save successful hunt queries as detection rules means the next analyst
          has to rediscover the same technique manually.
        </div>
      </div>
    ),
  },

  {
    id: 'playbooks',
    name: 'Playbooks',
    route: '/playbooks',
    category: 'Detection & Response',
    icon: 'book-open-check',
    tagline: 'Automated response logic — standardize triage actions, enforce approval gates, and maintain full execution audit.',
    keywords: [
      'playbook', 'automation', 'response', 'action', 'trigger', 'approval', 'block', 'isolate',
      'dry-run', 'audit', 'library', 'phishing', 'ransomware', 'brute force', 'ioc', 'risk',
    ],
    details: (
      <div>
        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">What is a Playbook?</h3>
        <p className="text-muted-foreground mb-2">
          A playbook is a pre-defined, automated sequence of response actions that executes when an alert matches
          specific trigger conditions. Playbooks codify your SOC's institutional knowledge — the steps an experienced
          analyst would take for a given alert type — into a repeatable, audited process. They reduce mean time to
          respond (MTTR) by eliminating manual steps, ensure consistency across analysts and shifts, and create a
          complete forensic record of every automated action taken.
        </p>
        <p className="text-muted-foreground mb-2">
          Playbooks are not meant to replace analyst judgment on complex incidents. They are most effective for
          well-understood, high-volume alert types where the response is deterministic — phishing triage, brute-force
          lockdown, known-IOC blocking. For novel or complex incidents, use playbooks to handle the first-response
          steps (contain, notify, create incident) while analysts conduct deeper investigation.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Playbook Components</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Trigger conditions</strong> — field-based alert filters that determine when the playbook fires. Examples: severity equals Critical, category equals phishing, source equals Office365.</li>
          <li><strong>Action list</strong> — ordered sequence of response steps executed when the trigger matches. Each action has a type, parameters, and a configured failure behaviour (stop or continue).</li>
          <li><strong>Approval requirements</strong> — flag for whether high-risk actions require a senior analyst or admin to approve before execution proceeds.</li>
          <li><strong>Enabled / Disabled state</strong> — playbooks can be toggled off without deleting them, useful for temporarily disabling during maintenance windows or staging new playbooks before go-live.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Action Types</h3>
        <p className="text-muted-foreground mb-2">
          The platform supports eight built-in action types covering the full spectrum from informational to
          high-impact containment:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>update_alert_status</strong> — change the alert status (e.g., auto-close low-confidence alerts, set to In Progress for high-severity).</li>
          <li><strong>assign_alert</strong> — assign the alert to a specific analyst or analyst group based on category or severity.</li>
          <li><strong>send_notification</strong> — push a notification to a Slack channel, Teams webhook, email, or PagerDuty, including alert context in the message body.</li>
          <li><strong>block_ip</strong> — submit the alert's source IP to the firewall integration for a time-limited or permanent block. <strong>High risk.</strong></li>
          <li><strong>isolate_host</strong> — send an isolation command to the EDR integration to quarantine the affected host from the network. <strong>High risk.</strong></li>
          <li><strong>disable_user</strong> — disable the associated user account in Active Directory or the identity provider. <strong>High risk.</strong></li>
          <li><strong>create_incident</strong> — automatically create a new incident and link the triggering alert to it, with a pre-populated title and severity.</li>
          <li><strong>enrich_ioc</strong> — submit IOCs (IPs, domains, file hashes) from the alert to threat intelligence feeds and attach the results to the alert as enrichment data.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Risk Levels and Approval Workflow</h3>
        <p className="text-muted-foreground mb-2">
          Actions are classified into three risk levels that determine whether human approval is required before
          execution:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Low risk</strong> — update_alert_status, send_notification. Execute immediately without approval. Reversible with no operational impact.</li>
          <li><strong>Medium risk</strong> — assign_alert, enrich_ioc, create_incident. Execute immediately. Low likelihood of negative side effects.</li>
          <li><strong>High risk</strong> — block_ip, isolate_host, disable_user. These actions disrupt network connectivity or user access and can cause operational outages if triggered incorrectly. When a playbook containing a high-risk action fires, execution pauses after medium-risk actions complete and waits for a Senior Analyst or Admin to approve continuation.</li>
        </ul>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          A playbook that isolates a production server or disables a privileged account incorrectly can cause a
          business outage. Always configure high-risk actions with approval requirements enabled, even on playbooks
          you trust. The approval gate adds less than 5 minutes of response latency while preventing potentially
          hours of recovery work.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Dry-Run Mode</h3>
        <p className="text-muted-foreground mb-2">
          Before enabling any new playbook, use <strong>Dry-Run</strong> to simulate its execution against a live
          or historical alert without taking any real actions. The dry-run output shows each action that would be
          executed, its parameters, its risk level, and whether it would succeed or fail based on current integration
          connectivity. This lets you validate trigger logic, verify action parameters, and review risk exposure
          before any automated action touches your environment.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Execution Forensics and Audit Trail</h3>
        <p className="text-muted-foreground mb-2">
          Every playbook execution — whether triggered automatically or run manually — writes an immutable audit
          record. The record captures the actor (the platform user or the automation trigger), the timestamp, the
          alert that triggered execution, each action taken with its input parameters and result (success or failure),
          and for approved executions, the identity of the approver. These records are available from the Execution
          Log tab on each playbook detail page and cannot be modified or deleted. They are critical for regulatory
          compliance and post-incident forensics.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Playbook Library</h3>
        <p className="text-muted-foreground mb-2">
          The platform ships with a pre-built library of playbooks covering the most common SOC response scenarios.
          Available library templates include phishing response, ransomware containment, brute-force account lockdown,
          and IOC blocking. Installing from the library creates a copy of the template in your environment pre-configured
          with sensible defaults. Customise trigger conditions, notification targets, and approval settings to match
          your environment before enabling.
        </p>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          To install a library playbook: navigate to Playbooks → Playbook Library tab → find the template →
          click Install → review and customise → Dry-Run → Enable.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Create a Phishing Response Playbook</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Step 1 — Navigate to Playbooks → New Playbook. Name it "Phishing — Automated Triage".</li>
          <li>Step 2 — Set trigger conditions: category equals phishing AND severity in [high, critical].</li>
          <li>Step 3 — Add action: send_notification to the #soc-alerts Slack channel with alert context.</li>
          <li>Step 4 — Add action: create_incident with title template "Phishing: {'{'}alert.hostname{'}'}" and severity matching alert severity.</li>
          <li>Step 5 — Add action: enrich_ioc to submit sender domain and link IPs to threat intel feeds.</li>
          <li>Step 6 — Add action: disable_user for the targeted account. Enable approval requirement.</li>
          <li>Step 7 — Add action: block_ip for the sending IP. Enable approval requirement.</li>
          <li>Step 8 — Save, run a Dry-Run against a recent phishing alert, review output, then Enable.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Review and Approve a High-Risk Playbook Execution</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Step 1 — Receive a notification (Slack / email) that a playbook execution is awaiting approval.</li>
          <li>Step 2 — Navigate to Playbooks → Pending Approvals tab and locate the execution.</li>
          <li>Step 3 — Review the execution context: which alert triggered it, which actions already ran, and the proposed high-risk action (e.g., isolate_host for hostname "ws-045").</li>
          <li>Step 4 — Verify the host is not a critical production system by checking the Assets page in a separate tab.</li>
          <li>Step 5 — Click Approve to allow the isolation action to proceed, or Reject to halt the playbook and add a rejection note explaining why.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li><strong>Senior Analyst / Admin</strong> — can create, edit, and delete playbooks. Responsible for validating trigger logic and action parameters.</li>
          <li><strong>Senior Analyst</strong> — can manually trigger playbooks that do not contain high-risk actions.</li>
          <li><strong>Admin</strong> — the only role that can approve high-risk playbook execution steps.</li>
          <li><strong>Analyst</strong> — can view playbooks and execution logs but cannot create, modify, or trigger them.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground mb-3">
          <li>Always dry-run before enabling a new playbook, even if you installed it from the library. Environmental differences (integration endpoints, account names) can cause unexpected failures.</li>
          <li>Start new playbooks with notification-only actions in the first week of production use. Monitor the notifications to validate trigger accuracy before adding automated containment actions.</li>
          <li>Review execution logs weekly. Failed actions that are silently ignored can give a false sense of automated protection that isn't actually executing.</li>
        </ul>

        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Tip:</strong> Build a staging environment duplicate of your highest-risk playbooks. Run new
          versions in staging against replayed historical alerts before promoting to production. This eliminates
          the risk of an untested playbook isolating a critical host during business hours.
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          <strong>Common mistakes:</strong> Enabling high-risk block or isolate actions without testing in a staging
          environment, and not setting approval requirements on those actions, are the two most frequent causes of
          playbook-induced outages. Also, leaving playbooks enabled but disabled integrations — a block_ip action
          with a disconnected firewall integration will silently fail, giving you no actual protection.
        </div>
      </div>
    ),
  },
]

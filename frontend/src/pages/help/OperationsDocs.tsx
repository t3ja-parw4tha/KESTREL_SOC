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

export const OPERATIONS_DOCS: SocDetailDoc[] = [
  // ─────────────────────────────────────────────────────────────────────────────
  // Dashboard
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'dashboard',
    name: 'Dashboard',
    route: '/app',
    category: 'Operations',
    icon: '📊',
    tagline: 'Real-time SOC command view — live KPIs, alert volume trends, active incidents, and source health.',
    keywords: ['kpi', 'overview', 'triage', 'queue', 'trend', 'operations', 'dashboard', 'incident', 'volume', 'health'],
    details: (
      <div className="space-y-6 text-sm">

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Overview</h3>
        <p className="text-muted-foreground mb-2">
          The Dashboard is your real-time command view of the security operations centre. It aggregates
          data from every connected log source into a single, scannable page so that an analyst arriving
          at their workstation — or a CISO opening the platform on a mobile device — can immediately
          understand the current threat posture without navigating to individual queue pages. Every widget
          on the Dashboard is designed to answer a specific operational question: How busy is the queue?
          Are any critical threats being actively worked? Is every data source reporting in?
        </p>
        <p className="text-muted-foreground mb-2">
          Data on the Dashboard refreshes automatically every 30 seconds via WebSocket. You do not need
          to manually reload the page. A subtle pulse indicator in the top-right of each widget confirms
          that live data is flowing. If the WebSocket connection drops, widgets switch to a polling fallback
          and a banner appears at the top of the page.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">KPI Cards</h3>
        <p className="text-muted-foreground mb-2">
          The top row of the Dashboard displays four key performance indicator cards. These are your
          highest-level operational metrics and should be checked first at the start of every shift.
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Total Alerts</strong> — the count of all open alerts
            across every severity level in the current 24-hour window. A sudden spike compared to the
            previous day is the first signal that something abnormal is occurring.
          </li>
          <li>
            <strong className="text-foreground">Open Incidents</strong> — the number of correlated
            incident records that have not yet been resolved or closed. Incidents represent grouped,
            escalated threats and carry higher urgency than raw alerts.
          </li>
          <li>
            <strong className="text-foreground">Critical / High Count</strong> — alerts at the two
            highest severity levels. These are the alerts most likely to represent real threats and
            carry the tightest SLA targets. This count should ideally trend downward through a shift
            as analysts triage and close items.
          </li>
          <li>
            <strong className="text-foreground">Mean Time to Triage (MTTT)</strong> — the average
            elapsed time between an alert being created and an analyst first touching it (changing
            status or adding a comment). This metric directly reflects analyst capacity and queue
            discipline. A rising MTTT means the queue is growing faster than analysts can process it.
          </li>
        </ul>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          KPI cards compare the current window against the previous equivalent period. A green arrow
          indicates improvement; a red arrow indicates regression. For Total Alerts and Critical/High,
          a lower number is better. For MTTT, a lower time is better. For Open Incidents, context
          matters — a rising count early in an incident campaign is expected, but a sustained rise
          with no closures is a capacity signal.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Volume Trend Chart</h3>
        <p className="text-muted-foreground mb-2">
          The alert volume chart plots alert counts over time, broken down by severity band. By default
          it shows the last 24 hours in 1-hour buckets; you can switch to 7-day view (1-day buckets)
          using the selector above the chart.
        </p>
        <p className="text-muted-foreground mb-2">
          Reading the chart effectively requires understanding what both spikes and drops mean:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">A sharp upward spike</strong> typically indicates a
            detection rule firing on an attack campaign, a scanning event, or a misconfigured service
            generating noise. Cross-reference with the Source Health row to see which connector produced
            the volume.
          </li>
          <li>
            <strong className="text-foreground">A gradual rise</strong> over several hours often
            indicates a slow-burn campaign or an increasing number of misconfiguration alerts from
            a newly onboarded source.
          </li>
          <li>
            <strong className="text-foreground">A sudden drop to zero</strong> is almost always a
            data problem, not a quiet environment. It means a source has stopped reporting. Check
            the Source Health row immediately when you see a volume drop that coincides with a
            source going amber or red.
          </li>
          <li>
            <strong className="text-foreground">A gradual decline</strong> through a shift is the
            expected pattern as analysts triage and close alerts, reducing the open count.
          </li>
        </ul>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Warning: Do not interpret a volume drop as a "quiet day" without first verifying source
          health. Silent sources produce no alerts and therefore no spikes — but the absence of
          data means your detection coverage has gaps you cannot see.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Source Health Row</h3>
        <p className="text-muted-foreground mb-2">
          Below the volume chart is a horizontal row of source health indicators — one tile per
          configured connector. Each tile shows the source name, its category badge, and a coloured
          status dot:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Green</strong> — the source is actively sending or
            responding to polls and has not exceeded its error budget. No action required.
          </li>
          <li>
            <strong className="text-foreground">Amber</strong> — the source is degraded. It is still
            within its 99.5% uptime SLO but is experiencing elevated errors or intermittent connectivity.
            Investigate at your earliest convenience during the shift.
          </li>
          <li>
            <strong className="text-foreground">Red</strong> — the source has gone stale. No data has
            been received for more than 15 minutes. The SLO is breached. This requires immediate
            investigation because your detection coverage for this source's asset category is now blind.
          </li>
        </ul>
        <p className="text-muted-foreground mb-2">
          Clicking a source tile opens a flyout panel with the last-seen timestamp, recent error log
          entries, and a link to the full Sources page for remediation steps.
        </p>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Warning: Never ignore amber source dots. An amber state means you are consuming error budget.
          If left unresolved, amber turns red and you lose coverage. Treat amber as a P3 task that must
          be resolved before end of shift.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Recent Alerts Widget</h3>
        <p className="text-muted-foreground mb-2">
          The Recent Alerts widget shows the 10 most recently created alerts, sorted by creation time
          descending. It acts as a fast-triage preview queue. Each row displays the severity dot, alert
          title, source name, MITRE tactic tag, and elapsed time since creation. Clicking any row opens
          the full Alert Detail page. This widget is intentionally compact — it is not a replacement for
          the Alerts page, which provides full filtering, bulk operations, and SLA timer visibility. Use
          the Recent Alerts widget to spot the newest arrivals; use the Alerts page to work the full queue.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Active Incidents Panel</h3>
        <p className="text-muted-foreground mb-2">
          The Active Incidents panel lists open incident records — these are correlated groups of alerts
          that the platform has determined are related (by shared IOCs, asset, or MITRE tactic chain).
          Each entry shows the incident title, the number of constituent alerts, the highest severity
          present, and the assigned analyst (if any). Active incidents represent escalated threats that
          require incident response attention, not just routine alert triage. An incident appearing here
          means the platform has detected a multi-step attack pattern or a cluster of related suspicious
          events that should be investigated as a unit.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Start-of-Shift Checklist</h3>
        <p className="text-muted-foreground mb-2">
          Follow these five steps every time you begin a shift to establish situational awareness before
          diving into individual alerts:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Step 1 — Check KPI cards.</strong> Note the Critical/High
            count and MTTT. If MTTT has risen significantly since the last shift, the queue may be backed up
            and you should request additional analysts or prioritise hard.
          </li>
          <li>
            <strong className="text-foreground">Step 2 — Scan Source Health.</strong> Any red or amber
            tiles? Resolve red sources before working alert queue — a blind source creates false confidence.
          </li>
          <li>
            <strong className="text-foreground">Step 3 — Review the volume chart.</strong> Look for overnight
            spikes you were not briefed on in shift handover. Correlate spikes with the source responsible.
          </li>
          <li>
            <strong className="text-foreground">Step 4 — Check Active Incidents.</strong> Are there open
            incidents from the previous shift that need a status update or handover note? Add a comment to
            any incident you are taking ownership of.
          </li>
          <li>
            <strong className="text-foreground">Step 5 — Navigate to Alerts.</strong> Use the Dashboard
            only as a situational summary. The full triage workflow happens in the Alerts page, where you
            have filters, SLA timers, and bulk operations.
          </li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Role</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Primary focus on Dashboard</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">SOC Manager</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Trend analysis — are KPIs improving week-over-week? Is MTTT within SLA? Are any sources chronically degraded?</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Tier-1 Analyst</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Queue depth check — how many Critical/High alerts need immediate attention? Which sources are feeding today?</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">CISO</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">KPI summary for situational awareness. Active Incidents panel for any ongoing material threats to report to leadership.</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            Do not rely solely on the Dashboard for your triage workflow. It is a summary view. The
            Alerts page provides the full queue with SLA timers, assignment filters, and bulk operations
            that the Dashboard does not expose.
          </li>
          <li>
            Set up source health alerts in <strong className="text-foreground">Settings → Notifications</strong>
            so that on-call analysts are paged when a source goes red, even when they are not actively
            watching the Dashboard.
          </li>
          <li>
            Use the 7-day volume view at the start of each week to identify recurring noise patterns
            that should be suppressed or tuned.
          </li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Common Mistakes</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Ignoring amber source dots.</strong> Amber means you
            are losing error budget silently. Two hours of amber on a primary EDR source is a material
            detection gap, even if no red state is reached.
          </li>
          <li>
            <strong className="text-foreground">Misreading a volume drop as a quiet day.</strong>
            Always check source health before concluding that low alert volume means low threat activity.
            A dead source produces no alerts.
          </li>
          <li>
            <strong className="text-foreground">Using the Dashboard as the primary triage tool.</strong>
            The Recent Alerts widget only shows 10 items. If your queue has 200 open Critical alerts,
            you cannot triage them from the Dashboard. Always move to the Alerts page for queue work.
          </li>
        </ul>

      </div>
    ),
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // Alerts
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'alerts',
    name: 'Alerts',
    route: '/app/alerts',
    category: 'Operations',
    icon: '🚨',
    tagline: 'Full alert queue with severity filtering, assignment, bulk operations, and SLA tracking.',
    keywords: ['alert', 'triage', 'sla', 'filter', 'severity', 'assign', 'bulk', 'false-positive', 'suppress', 'queue', 'keyboard'],
    details: (
      <div className="space-y-6 text-sm">

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Overview</h3>
        <p className="text-muted-foreground mb-2">
          The Alerts page is the primary triage workstation for tier-1 and tier-2 analysts. Every alert
          ingested by KESTREL — regardless of source — appears here. The page provides a paginated,
          filterable, and sortable table of all alerts in the system, with real-time SLA timer overlays
          that make it immediately visible which alerts are approaching or have breached their response
          time targets.
        </p>
        <p className="text-muted-foreground mb-2">
          Unlike the Dashboard's summary view, the Alerts page is designed for sustained queue work.
          It supports keyboard-driven navigation, bulk operations for shift handovers, and inline status
          transitions that do not require opening the full Alert Detail page. An experienced analyst
          can triage dozens of low-complexity alerts per hour directly from this view.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Filter Bar</h3>
        <p className="text-muted-foreground mb-2">
          The filter bar runs across the top of the alert table and provides the following controls:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Severity</strong> — multi-select chips: Critical, High,
            Medium, Low. Selecting multiple severities returns alerts matching any selected level. Most
            analysts start a shift with Critical and High selected.
          </li>
          <li>
            <strong className="text-foreground">Status</strong> — Open, In Progress, Resolved, False
            Positive. Defaults to Open + In Progress. Filter to Resolved to review closed items during
            a retrospective.
          </li>
          <li>
            <strong className="text-foreground">Source</strong> — dropdown listing every configured
            connector. Use this to isolate alerts from a specific tool (e.g., show only CrowdStrike
            alerts) during source-specific investigations.
          </li>
          <li>
            <strong className="text-foreground">Owner</strong> — filter by assigned analyst. Useful
            for a team lead reviewing their analysts' workloads, or for an analyst viewing only their
            own assigned queue.
          </li>
          <li>
            <strong className="text-foreground">Date Range</strong> — defaults to last 24 hours.
            Supports preset ranges (4h, 24h, 7d) and a custom date-time picker for historical review.
          </li>
          <li>
            <strong className="text-foreground">Free-text search</strong> — searches alert title,
            description, source host, and any enriched IOC fields simultaneously.
          </li>
        </ul>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          Active filters are persisted in the URL query string. You can bookmark or share a filtered
          view with colleagues by copying the browser URL. Filter state is also preserved when you
          navigate to an Alert Detail page and return.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Alert Table Columns</h3>
        <p className="text-muted-foreground mb-2">
          Each row in the alert table represents a single alert. The columns from left to right are:
        </p>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Column</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Severity dot</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Coloured indicator: red (Critical), orange (High), yellow (Medium), blue (Low).</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Title</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Alert name as generated by the detection rule or source. Click to open Alert Detail.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Source</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">The connector that generated this alert (e.g., CrowdStrike, Splunk).</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">MITRE Tactic</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">The ATT&amp;CK tactic tag mapped by the rule engine (e.g., Execution, Persistence).</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Risk Score</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">0–100 composite score combining rule confidence, asset criticality, and enrichment signals.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">SLA Timer</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Countdown to SLA breach. Colour-coded: green (OK), amber (50%+ elapsed), red (breached).</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Owner</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Assigned analyst avatar and username. Empty if unassigned.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Status</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Current state badge: Open, In Progress, Resolved, False Positive.</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">SLA Timers and Targets</h3>
        <p className="text-muted-foreground mb-2">
          Every alert is subject to a triage SLA — the maximum elapsed time from alert creation to
          an analyst first actioning it. SLA targets are defined by severity:
        </p>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Severity</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">SLA Target</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Amber Threshold</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Critical</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">15 minutes</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">7 minutes (50%)</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">High</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">1 hour</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">30 minutes</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Medium</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">4 hours</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">2 hours</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Low</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">24 hours</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">12 hours</td>
            </tr>
          </tbody>
        </table>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          SLA breach data is included in the Analyst Activity report. Persistent SLA breaches on
          Critical alerts are a leading indicator of analyst under-staffing and should be escalated
          to the SOC Manager immediately rather than silently accepted.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Bulk Operations</h3>
        <p className="text-muted-foreground mb-2">
          Select multiple alerts using the checkbox column (or Shift+click to range-select) to reveal
          the bulk action toolbar above the table. Available bulk operations:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Bulk Assign</strong> — assign all selected alerts to a specific analyst. Useful for shift handovers where a departing analyst reassigns their in-progress queue.</li>
          <li><strong className="text-foreground">Bulk Status Update</strong> — transition all selected alerts to a new status simultaneously. Most commonly used to mark a batch of confirmed false positives.</li>
          <li><strong className="text-foreground">Bulk Suppress</strong> — create a suppression rule covering the selected alert pattern (prompts for suppression parameters).</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Keyboard Triage Mode</h3>
        <p className="text-muted-foreground mb-2">
          For high-speed queue work, KESTREL supports keyboard-driven triage directly in the Alerts
          table. Click any row to focus it, then use:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">J / K</strong> — move focus down / up one row</li>
          <li><strong className="text-foreground">A</strong> — assign focused alert to yourself</li>
          <li><strong className="text-foreground">R</strong> — mark focused alert as Resolved</li>
          <li><strong className="text-foreground">F</strong> — mark focused alert as False Positive</li>
          <li><strong className="text-foreground">Enter</strong> — open Alert Detail for focused alert</li>
          <li><strong className="text-foreground">Escape</strong> — return to table from detail panel</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Alert Deduplication</h3>
        <p className="text-muted-foreground mb-2">
          When the same alert fires multiple times in rapid succession (same rule, same asset, same
          signature), KESTREL groups them into a single deduplicated row showing a count badge (e.g.,
          "×12"). Click the badge to expand the group and see individual event timestamps. The SLA timer
          for a grouped alert starts from the first event in the group, not the most recent. Deduplication
          reduces queue noise but does not suppress investigation — a rule firing 50 times may indicate
          a brute-force attempt where the volume itself is significant.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Creating Suppression Rules</h3>
        <p className="text-muted-foreground mb-2">
          To suppress future alerts matching a known-benign pattern, right-click any alert row (or open
          its action menu via the three-dot icon) and select <strong className="text-foreground">Create
          Suppression Rule</strong>. A drawer opens pre-populated with the alert's rule ID, source, and
          key field values. You can tighten or broaden the match criteria before saving. Suppression rules
          are audited — every rule shows who created it, when, and against which alert it was first applied.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Triage a New Critical Alert</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Step 1.</strong> Filter Alerts to Critical + Open. Identify the alert with the highest risk score and shortest remaining SLA time.</li>
          <li><strong className="text-foreground">Step 2.</strong> Press A to assign it to yourself, or click the Owner column and select your name. This stops the MTTT clock and signals ownership.</li>
          <li><strong className="text-foreground">Step 3.</strong> Press Enter (or click the title) to open Alert Detail. Review the Overview tab: risk score, affected asset, rule description.</li>
          <li><strong className="text-foreground">Step 4.</strong> Run AI Analysis to get a plain-English explanation and recommended actions. Check the Enrichment tab for VT/AbuseIPDB hits on any IOCs.</li>
          <li><strong className="text-foreground">Step 5.</strong> Check the MITRE tab to understand where this technique falls in a potential kill chain. Is there a matching incident that should be updated?</li>
          <li><strong className="text-foreground">Step 6.</strong> Add a comment documenting your findings: what you checked, what you found, and your decision rationale. This is mandatory before any status change.</li>
          <li><strong className="text-foreground">Step 7.</strong> Change status: Resolved (confirmed false positive or benign), or escalate to an Incident if a real threat is confirmed. Never leave Critical alerts in Open state after investigation.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Role Guidance</h3>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Role</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Alert permissions</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Viewer</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Read-only. Can view alert details and AI analysis. Cannot change status or assign.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Analyst</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Full triage. Can assign to self, change status, add comments, create suppression rules.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Senior Analyst</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">All Analyst permissions plus: can assign alerts to other analysts, approve suppression rules.</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Admin</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">All permissions including hard-delete of alerts and management of suppression rule library.</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>Always work highest severity first. Sort by severity descending, then by SLA timer ascending to find the most urgent item.</li>
          <li>Always add a comment before changing status. Comments create an audit trail that compliance and IR teams depend on.</li>
          <li>Use bulk assign for shift handovers — select all in-progress alerts, bulk assign to the incoming analyst, and add a handover note in the incident or alert comment.</li>
          <li>Review the full Enrichment tab before marking an alert as False Positive. An IP that looks clean to you may have a recent VT hit that changes the picture.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Common Mistakes</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Marking alerts as False Positive without investigating context.</strong>
            FP marking without a comment and investigation creates false confidence and corrupts the analyst
            activity metrics used for performance reviews.
          </li>
          <li>
            <strong className="text-foreground">Letting SLA timers breach without escalating.</strong>
            If you cannot reach a Critical alert within 7 minutes (amber threshold), immediately flag to
            the shift lead so they can redistribute load or escalate.
          </li>
          <li>
            <strong className="text-foreground">Working from the Dashboard's Recent Alerts widget instead of the full Alerts page.</strong>
            The widget only shows the 10 most recent alerts. A high-risk alert from 2 hours ago that is
            approaching SLA breach will not appear there.
          </li>
        </ul>

      </div>
    ),
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // Reports
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'reports',
    name: 'Reports',
    route: '/app/reports',
    category: 'Operations',
    icon: '📈',
    tagline: 'Executive summaries, detection coverage, analyst activity metrics, and compliance evidence exports.',
    keywords: ['report', 'executive', 'compliance', 'soc2', 'pci', 'coverage', 'mitre', 'analyst', 'activity', 'export', 'schedule', 'audit'],
    details: (
      <div className="space-y-6 text-sm">

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Overview</h3>
        <p className="text-muted-foreground mb-2">
          The Reports page is designed for SOC managers, CISOs, and compliance stakeholders who need
          structured, time-bounded summaries of the platform's detection and response activity. Unlike
          the live Dashboard, Reports are generated over a defined historical window and represent a
          fixed snapshot of metrics at the time of generation. Each report type answers a distinct
          business question — whether that is "how busy was the SOC last month?", "which attack
          techniques are we not detecting?", or "can we prove to auditors that we reviewed every
          Critical alert within SLA?"
        </p>
        <p className="text-muted-foreground mb-2">
          Reports can be generated on demand or scheduled for automatic delivery. All report types
          support export as PDF (for board briefings) or JSON (for integration with GRC platforms).
          Compliance Evidence Bundles additionally include a SHA-256 checksum and digital signature
          to satisfy chain-of-custody requirements for formal audits.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Report Types</h3>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Report</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Primary audience</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Key questions answered</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Executive Summary</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">CISO, Board</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Alert volumes, open/closed ratio, MTTR trend, top attack categories</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Detection Coverage</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">SOC Manager, Detection Engineer</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">MITRE tactic coverage %, active vs total rules, top detected techniques</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Analyst Activity</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">SOC Manager, HR</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Alerts handled per analyst, average triage time, escalation rate, SLA breach rate</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Compliance Evidence Bundle</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Compliance Officer, External Auditor</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Signed, verifiable evidence package for SOC 2 / PCI-DSS / ISO 27001 assessments</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Time Range Selector</h3>
        <p className="text-muted-foreground mb-2">
          All reports require a time range before generation. Preset options are Last 7 Days, Last 30
          Days, and Last 90 Days. A custom date-time picker is available for precise control (e.g., the
          exact calendar quarter for a quarterly board pack). The selected range is embedded in the
          report header and the compliance bundle metadata so that auditors can verify the scope without
          ambiguity.
        </p>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Warning: Always confirm your time range before generating. A report generated with the
          wrong date range may appear identical in structure but contain entirely different data.
          This is the most common error when preparing compliance evidence packages.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Executive Summary Report</h3>
        <p className="text-muted-foreground mb-2">
          The Executive Summary is a management-level narrative report combining charts and tabular
          data. It contains:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Alert volume by severity</strong> — stacked bar chart comparing the selected period against the previous equivalent period, making trends immediately readable without SOC domain knowledge.</li>
          <li><strong className="text-foreground">Closed/Open ratio</strong> — the percentage of alerts that were resolved within the period versus those that remained open at the period end. A ratio below 80% indicates queue backlog.</li>
          <li><strong className="text-foreground">MTTR trend</strong> — Mean Time to Resolve, charted day-by-day across the period. Rising MTTR is a staffing or tooling signal.</li>
          <li><strong className="text-foreground">Top attack categories</strong> — the five most-detected MITRE ATT&amp;CK tactics in the period, with alert count and severity breakdown. Useful for communicating to non-technical stakeholders which threat types the SOC is observing most frequently.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Detection Coverage Report</h3>
        <p className="text-muted-foreground mb-2">
          The Detection Coverage report is a technical report for detection engineers and SOC managers
          responsible for the rule set. It contains:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">MITRE tactic coverage percentage</strong> — for each of the 14 ATT&amp;CK tactics, the fraction of sub-techniques that have at least one active detection rule. A tactic at 0% means no rules cover any technique within it.</li>
          <li><strong className="text-foreground">Rules active vs total</strong> — how many detection rules are currently enabled out of the total defined. Disabled rules are listed with the reason for disabling.</li>
          <li><strong className="text-foreground">Top detected techniques</strong> — the 10 ATT&amp;CK techniques that fired the most alerts in the period, useful for identifying over-sensitive rules that may need tuning.</li>
          <li><strong className="text-foreground">Coverage gaps</strong> — techniques with no active rule, flagged as high-priority gaps if they appear in threat intelligence reports for your industry vertical.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Analyst Activity Report</h3>
        <p className="text-muted-foreground mb-2">
          The Analyst Activity report provides per-analyst performance metrics for the selected period.
          It is used for team capacity planning and one-to-one performance reviews. Key metrics include:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Alerts handled</strong> — total alerts where the analyst made at least one status transition or added a comment.</li>
          <li><strong className="text-foreground">Average triage time</strong> — median elapsed time between alert assignment and first status change.</li>
          <li><strong className="text-foreground">Escalation rate</strong> — percentage of the analyst's handled alerts that were escalated to an incident.</li>
          <li><strong className="text-foreground">SLA breach rate</strong> — percentage of assigned alerts where the analyst allowed the SLA timer to breach before actioning. A high breach rate paired with a high total alert count may indicate that an analyst is over-capacity rather than under-performing.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Compliance Evidence Bundle</h3>
        <p className="text-muted-foreground mb-2">
          The Compliance Evidence Bundle is a tamper-evident export package that satisfies the evidence
          requirements of major security frameworks. Each bundle contains:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>A unique report ID (UUID) stamped on every page</li>
          <li>SHA-256 checksum of the full report content, allowing auditors to verify the document has not been modified since export</li>
          <li>Export timestamp in ISO 8601 UTC format</li>
          <li>Digital signature using the platform's signing key (configurable in Settings → Compliance)</li>
          <li>A summary of alert SLA adherence, including every Critical alert and whether it was triaged within the 15-minute target</li>
          <li>Access log excerpt showing which analysts reviewed which alerts during the period</li>
        </ul>
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-muted-foreground mb-3">
          The Compliance Evidence Bundle meets the documentation requirements for SOC 2 Type II
          (CC7.2, CC7.3), PCI-DSS v4.0 (Requirement 10), and ISO 27001:2022 (Annex A 8.15, 8.16).
          Always send the signed PDF variant to auditors, not the JSON export.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Scheduled Reports</h3>
        <p className="text-muted-foreground mb-2">
          Reports can be automated via <strong className="text-foreground">Settings → Scheduled Reports</strong>.
          You can configure the report type, time range (typically "last 7 days" for weekly briefings),
          recipients (email addresses or distribution lists), delivery day/time, and output format.
          Scheduled reports are generated in the background and delivered via the configured SMTP
          server. A delivery log is available in the Scheduled Reports settings panel for debugging
          failed deliveries.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Export Compliance Evidence for Auditors</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Step 1.</strong> Navigate to Reports and select <em>Compliance Evidence Bundle</em> from the report type selector.</li>
          <li><strong className="text-foreground">Step 2.</strong> Set the time range to the exact audit period requested by the auditor (e.g., 1 January – 31 March). Use the custom date-time picker, not a preset.</li>
          <li><strong className="text-foreground">Step 3.</strong> Click <em>Generate Report</em>. Generation may take 30–90 seconds for large time ranges.</li>
          <li><strong className="text-foreground">Step 4.</strong> When generation completes, review the report preview. Verify the time range header, report ID, and that alert counts look consistent with your expectations for the period.</li>
          <li><strong className="text-foreground">Step 5.</strong> Click <em>Download Signed PDF</em>. Send this file to auditors. Record the report ID and SHA-256 checksum in your audit evidence register.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>Export monthly Executive Summary and Compliance Evidence snapshots even when no audit is scheduled. Historical reports are far easier to produce on demand than to reconstruct from raw data after the fact.</li>
          <li>Set up a weekly scheduled Executive Summary to the SOC Manager and CISO distribution list. This creates a rhythm of visibility that reduces ad-hoc reporting requests.</li>
          <li>Review the Detection Coverage report at the start of each quarter to identify gaps before they are pointed out by auditors or discovered during a breach.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Common Mistakes</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Exporting without verifying the time range.</strong> A Compliance Evidence Bundle for the wrong period is useless to an auditor and may require an emergency re-export with a tight deadline.</li>
          <li><strong className="text-foreground">Sending the unsigned JSON export to auditors instead of the signed PDF.</strong> The JSON export lacks the SHA-256 checksum and signature that give the document evidentiary value. Auditors may reject unsigned reports.</li>
          <li><strong className="text-foreground">Not scheduling recurring reports.</strong> Manual report generation is easy to forget. Scheduled reports ensure continuity even when the responsible team member is on leave.</li>
        </ul>

      </div>
    ),
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // Sources
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'sources',
    name: 'Sources',
    route: '/app/sources',
    category: 'Operations',
    icon: '🔌',
    tagline: 'Connector health, onboarding status, ingestion lag SLOs, and error budget monitoring.',
    keywords: ['source', 'connector', 'health', 'ingest', 'slo', 'error', 'budget', 'crowdstrike', 'splunk', 'okta', 'siem', 'edr', 'cloud', 'identity', 'network', 'lag', 'stale'],
    details: (
      <div className="space-y-6 text-sm">

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Overview</h3>
        <p className="text-muted-foreground mb-2">
          The Sources page provides visibility into whether your detection coverage is actually
          receiving data. A detection rule is only as good as the data flowing into it. KESTREL
          can have hundreds of well-crafted rules, but if an EDR connector goes silent, every
          endpoint-based detection becomes blind without any visible error in the alert queue.
          The Sources page surfaces the health of each connector so that coverage gaps caused by
          data pipeline failures are caught immediately rather than discovered during a post-incident
          review.
        </p>
        <p className="text-muted-foreground mb-2">
          Each source is represented by a card showing its logo, category, connection mode (Push
          or Pull), current health status, last-seen timestamp, ingest rate (events per minute),
          and error budget consumption. The card colour and status dot provide an at-a-glance
          health signal without requiring you to read the detail.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Source Categories</h3>
        <p className="text-muted-foreground mb-2">
          KESTREL organises connectors into the following categories. Each category covers a
          distinct layer of your security stack. Gaps in coverage often correspond to entire
          attack surface areas with no visibility:
        </p>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Category</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">Examples</th>
              <th className="text-left px-3 py-2 bg-muted/20 border border-border text-xs font-medium text-muted-foreground uppercase tracking-wide">What goes blind if this category fails</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">SIEM</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Splunk, QRadar</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Aggregated log correlation, legacy system alerts</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">EDR</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">CrowdStrike, SentinelOne, Microsoft Defender</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Endpoint process, memory, and file-based detections</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Cloud</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">AWS GuardDuty, GCP Security Command Center</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Cloud infrastructure threat detection and configuration findings</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Identity</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Okta, Azure AD</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Authentication anomalies, MFA bypass, account compromise detection</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Network</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Suricata, Palo Alto NGFW</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Network intrusion detection, C2 traffic, lateral movement</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Email</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Microsoft 365 Defender, Google Workspace</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Phishing, BEC, malicious attachment detections</td>
            </tr>
            <tr>
              <td className="px-3 py-2 border border-border text-foreground">Vulnerability</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Tenable, Qualys</td>
              <td className="px-3 py-2 border border-border text-muted-foreground">Vulnerability scan results used for asset risk scoring</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Health Indicators</h3>
        <p className="text-muted-foreground mb-2">
          Each source card displays one of three health states. Understanding the distinction between
          amber and red is critical for prioritising remediation:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Green — Healthy.</strong> The source is actively
            sending or being polled successfully. Error rate is within the 99.5% SLO. Ingest lag
            is within the configured threshold (default: under 5 minutes). No action required.
          </li>
          <li>
            <strong className="text-foreground">Amber — Degraded.</strong> The source is experiencing
            elevated errors or intermittent connectivity but has not yet exhausted its error budget.
            You are still receiving some data, but reliability is reduced. Investigate within the
            current shift. Common causes: transient network issues, API rate limiting, expiring credentials.
          </li>
          <li>
            <strong className="text-foreground">Red — Stale / SLO Breached.</strong> No data has been
            received from this source for longer than the configured staleness threshold (default:
            15 minutes). The error budget is exhausted. Your detection coverage for this source's
            asset category is now effectively blind. This requires immediate investigation.
          </li>
        </ul>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-muted-foreground mb-3">
          Warning: A source in red state does not generate an alert in the alert queue — it simply
          stops producing alerts. This is why source health monitoring is a separate operational
          discipline from alert triage. You must proactively check the Sources page; the absence
          of alerts is not evidence of good coverage.
        </div>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Connector Modes</h3>
        <p className="text-muted-foreground mb-2">
          KESTREL supports two data collection modes. Understanding which mode your source uses
          determines how you diagnose and fix connectivity problems:
        </p>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Push mode</strong> — the source (agent, webhook,
            or security tool) sends data directly to KESTREL's Ingest API endpoint
            (<code className="text-xs bg-muted px-1 rounded">POST /ingest/events</code>). The
            source is responsible for delivery. If the source stops sending, KESTREL goes stale.
            Push mode is used by: Suricata, Windows Event Log forwarders, Snort, Defender for
            Endpoint via webhook.
          </li>
          <li>
            <strong className="text-foreground">Pull mode</strong> — KESTREL's connector engine
            periodically polls the source's API on a configured schedule (typically every 5 minutes).
            KESTREL is responsible for collection. If the API key expires or the source's API is
            unreachable, KESTREL goes stale. Pull mode is used by: CrowdStrike, SentinelOne, Okta,
            Azure AD, GuardDuty, Splunk, QRadar, Tenable, Qualys.
          </li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Setup Flow</h3>
        <p className="text-muted-foreground mb-2">
          To configure a new source, click the <strong className="text-foreground">Setup Guide</strong>
          button on any unconfigured source card. A step-by-step integration panel slides open on the
          right side of the screen, providing connector-specific instructions including: where to find
          API credentials in the source's admin console, the exact KESTREL configuration fields to
          populate, network requirements (IP allowlist entries, webhook URLs), and a "Test Connection"
          button to verify the integration before saving.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Error Budget</h3>
        <p className="text-muted-foreground mb-2">
          Each source operates under a 99.5% monthly success rate SLO. The error budget widget on each
          source card shows the percentage of budget remaining for the current calendar month. A budget
          at 100% means no errors have occurred. A budget at 0% means the SLO has been breached and
          the source is in a red state. The error budget resets on the first of each month.
        </p>
        <p className="text-muted-foreground mb-2">
          Error budget consumption is tracked per API call (for Pull sources) or per ingest request
          (for Push sources). A failed poll attempt counts as one budget unit consumed. Viewing the
          error log (available by clicking the source card) shows the exact timestamps and error
          messages for each failed attempt.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Ingest Lag</h3>
        <p className="text-muted-foreground mb-2">
          Ingest lag is the measured time between an event occurring in the source system and the
          resulting alert appearing in KESTREL. It is displayed on each source card as a rolling
          5-minute average. High ingest lag (above 10 minutes for a Critical-tier source) means that
          your detection response time is structurally degraded — an attacker completing an objective
          in 8 minutes may never trigger a timely alert even if the detection rule fires correctly.
        </p>
        <p className="text-muted-foreground mb-2">
          Acceptable lag thresholds vary by source type. Real-time EDR sources should maintain under
          2 minutes. SIEM aggregation sources may have 5–10 minutes of inherent batch lag. Vulnerability
          scanners are batch by nature and lag is measured in hours, not minutes.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Stale Source Alerting</h3>
        <p className="text-muted-foreground mb-2">
          KESTREL automatically sends a notification when any source goes silent for more than 15
          minutes (configurable per source in Settings → Sources → Source Name → Alerting). Notifications
          can be delivered via email, Slack, PagerDuty, or any configured webhook. Stale source
          notifications are separate from the alert queue — they are operational infrastructure alerts,
          not security alerts. Ensure that on-call rotation members receive these notifications so
          that coverage gaps are caught 24/7.
        </p>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Onboard a New CrowdStrike Connector</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Step 1.</strong> In the CrowdStrike Falcon console, navigate to Support → API Clients and Keys. Create a new API client with Read permissions on Detections, Events, and Hosts scopes.</li>
          <li><strong className="text-foreground">Step 2.</strong> Copy the Client ID and Client Secret. These are shown only once — store them in your secrets manager immediately.</li>
          <li><strong className="text-foreground">Step 3.</strong> In KESTREL, open Sources and click Setup Guide on the CrowdStrike card. Enter the Client ID, Client Secret, and your Falcon cloud region (US-1, US-2, EU-1, etc.).</li>
          <li><strong className="text-foreground">Step 4.</strong> Click Test Connection. KESTREL will make a single API call to verify credentials and permissions. A green success indicator confirms connectivity.</li>
          <li><strong className="text-foreground">Step 5.</strong> Set the poll interval (default: 5 minutes) and configure the look-back window for the first poll (default: 24 hours to backfill recent detections).</li>
          <li><strong className="text-foreground">Step 6.</strong> Click Save. Wait one poll interval and confirm that the source card turns green and that alert counts increase. Verify that CrowdStrike alert titles are appearing in the Alerts page with the correct MITRE mappings.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Workflow: Diagnose a Red or Amber Source</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li><strong className="text-foreground">Step 1 — Check last_seen timestamp.</strong> Click the source card to open the detail flyout. The last_seen timestamp tells you exactly when data was last received. If it was 3 hours ago but the connector is marked amber, verify that the staleness threshold is configured correctly.</li>
          <li><strong className="text-foreground">Step 2 — Check the API key or webhook credentials.</strong> For Pull sources: confirm that the API key has not expired or been revoked in the source system. For Push sources: confirm that the source agent is still running and configured with the correct KESTREL ingest URL and bearer token.</li>
          <li><strong className="text-foreground">Step 3 — Check network connectivity.</strong> For Pull sources: verify that the KESTREL server can reach the source's API endpoint (firewall rules, DNS resolution, TLS certificate validity). For Push sources: verify that the source can reach the KESTREL ingest endpoint — check that KESTREL's IP is allowlisted on any intermediate firewalls.</li>
          <li><strong className="text-foreground">Step 4 — Review the error log.</strong> In the source detail flyout, expand the Error Log section. The most recent errors will show the exact HTTP status codes or connection errors returned. A 401 means credential failure; a 403 means permission scope issue; a 503 means the source API is unavailable.</li>
          <li><strong className="text-foreground">Step 5 — Re-test and monitor.</strong> After resolving the identified issue, click Test Connection. If it succeeds, monitor the source card for 10 minutes to confirm it transitions from red/amber to green and that ingest lag returns to normal.</li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Best Practices</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            Never rely on a single source to cover an entire MITRE tactic. For example, if CrowdStrike
            is your only EDR source and it goes red, your Execution and Persistence tactic detections
            are completely blind. Deploy overlapping sources for your highest-priority tactics.
          </li>
          <li>
            Always verify that a newly onboarded source is actively receiving data before treating it
            as part of your detection coverage. A green setup wizard result confirms credentials work,
            but watching the first 24 hours of live data confirms that events are actually flowing.
          </li>
          <li>
            Rotate API keys on a scheduled basis (every 90 days is a common policy). Plan rotations
            in advance — update the key in KESTREL before revoking the old one to avoid a gap in coverage.
          </li>
        </ul>

        <h3 className="text-sm font-semibold text-foreground mt-4 mb-2">Common Mistakes</h3>
        <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
          <li>
            <strong className="text-foreground">Forgetting to whitelist the KESTREL server IP on the source firewall.</strong>
            Pull connectors require outbound connectivity from KESTREL to the source API. Push connectors
            require inbound connectivity from the source agent to KESTREL's ingest endpoint. Both directions
            must be allowlisted. Firewall configuration is the most common cause of new connector failures.
          </li>
          <li>
            <strong className="text-foreground">Not testing after API key rotation.</strong>
            API key rotations are a routine maintenance task that frequently cause source outages when the
            old key is revoked before the new one is entered in KESTREL. Always update KESTREL first,
            run a connection test, then revoke the old key.
          </li>
          <li>
            <strong className="text-foreground">Treating the absence of red sources as confirmation of complete coverage.</strong>
            A source that was never configured cannot go red — it simply does not exist. The Sources page
            shows only configured connectors. Review your asset inventory against the source categories
            periodically to identify asset types that have no connector at all.
          </li>
        </ul>

      </div>
    ),
  },
]

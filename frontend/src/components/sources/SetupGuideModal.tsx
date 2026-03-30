import { Copy } from 'lucide-react'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'

export interface SetupGuideContent {
  title: string
  instructions: string
  codeBlocks: string[]
}

export const SETUP_GUIDES: Record<string, SetupGuideContent> = {
  windows_event: {
    title: 'Configure Windows Event Log',
    instructions: `Send Windows security events to KESTREL using Winlogbeat or NXLog.

1. Install Winlogbeat on your Windows host
2. Configure winlogbeat.yml output:
   hosts: ['your-kestrel-host:8000']
   path: /api/v1/ingest
   headers:
     Authorization: Bearer YOUR_API_TOKEN
3. Set event log channels:
   - Security
   - System
   - Application
4. Start Winlogbeat service

Or send directly via PowerShell:`,
    codeBlocks: [
      `$r = Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/auth/login" \`
  -Method POST -ContentType "application/json" \`
  -Body '{"username":"admin","password":"YourPassword123!!"}'

$token = $r.access_token
$h = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/ingest" \`
  -Method POST -Headers $h \`
  -Body '{"source":"WindowsEventLog","events":[{"EventID":4625,"EventData":{"TargetUserName":"administrator","IpAddress":"10.0.0.5"}}]}'`,
    ],
  },
  windows: {
    title: 'Configure Windows Event Log',
    instructions: `Send Windows security events to KESTREL using Winlogbeat or NXLog.

1. Install Winlogbeat on your Windows host
2. Configure winlogbeat.yml output:
   hosts: ['your-kestrel-host:8000']
   path: /api/v1/ingest
   headers:
     Authorization: Bearer YOUR_API_TOKEN
3. Set event log channels:
   - Security
   - System
   - Application
4. Start Winlogbeat service

Or send directly via PowerShell:`,
    codeBlocks: [
      `$r = Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/auth/login" \`
  -Method POST -ContentType "application/json" \`
  -Body '{"username":"admin","password":"YourPassword123!!"}'

$token = $r.access_token
$h = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/ingest" \`
  -Method POST -Headers $h \`
  -Body '{"source":"WindowsEventLog","events":[{"EventID":4625,"EventData":{"TargetUserName":"administrator","IpAddress":"10.0.0.5"}}]}'`,
    ],
  },
  defender: {
    title: 'Configure Microsoft Defender',
    instructions: `Forward Defender alerts to KESTREL via Logic App or direct API push.

1. In Microsoft Defender portal go to:
   Settings → Endpoints → Advanced features
2. Enable SIEM integration
3. Configure webhook to:
   POST https://your-kestrel-host/api/v1/ingest
   Authorization: Bearer YOUR_API_TOKEN
4. Or use the PowerShell script:`,
    codeBlocks: [
      `$r = Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/auth/login" \`
  -Method POST -ContentType "application/json" \`
  -Body '{"username":"admin","password":"YourPassword123!!"}'
$token = $r.access_token
$h = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }
Invoke-RestMethod -Uri "https://your-kestrel-host/api/v1/ingest" \`
  -Method POST -Headers $h \`
  -Body '{"source":"Defender","events":[{"AlertName":"Suspicious activity","Severity":"High"}]}'`,
    ],
  },
  suricata: {
    title: 'Configure Suricata IDS',
    instructions: `Forward Suricata EVE JSON logs to KESTREL.

1. In /etc/suricata/suricata.yaml set:
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: /var/log/suricata/eve.json
2. Use Filebeat to forward to KESTREL:
   POST https://your-kestrel-host/api/v1/ingest
   Authorization: Bearer YOUR_API_TOKEN
3. Or pipe directly:`,
    codeBlocks: [
      `# Stream EVE JSON to KESTREL (example single event)
curl -X POST https://your-kestrel-host/api/v1/ingest \\
  -H "Authorization: Bearer YOUR_API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"source":"Suricata","events":[{"event_type":"alert","timestamp":"2025-01-01T00:00:00.000000Z"}]}'`,
    ],
  },
  snort: {
    title: 'Configure Snort IDS',
    instructions: `Forward Snort unified2 or alert logs to KESTREL.

1. Configure Snort output plugin:
   output unified2: filename snort.log
2. Use u2boat or barnyard2 to forward:
   POST https://your-kestrel-host/api/v1/ingest
   Authorization: Bearer YOUR_API_TOKEN`,
    codeBlocks: [
      `# Example: send Snort alert JSON to KESTREL
curl -X POST https://your-kestrel-host/api/v1/ingest \\
  -H "Authorization: Bearer YOUR_API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"source":"Snort","events":[{"message":"Snort alert","signature_id":12345}]}'`,
    ],
  },
}

interface SetupGuideModalProps {
  sourceId: string | null
  onClose: () => void
}

export function SetupGuideModal({ sourceId, onClose }: SetupGuideModalProps) {
  const content = sourceId ? SETUP_GUIDES[sourceId] : null

  if (!sourceId || !content) return null

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-50" onClick={onClose} aria-hidden />
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-auto"
        role="dialog"
        aria-modal="true"
        aria-labelledby="setup-guide-title"
      >
        <div className="bg-card border border-border rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-auto my-4">
          <div className="p-6">
            <h2 id="setup-guide-title" className="text-lg font-semibold text-foreground mb-4">
              {content.title}
            </h2>
            <div className="text-sm text-muted-foreground whitespace-pre-wrap mb-4">
              {content.instructions}
            </div>
            {content.codeBlocks.map((block, idx) => (
              <div key={idx} className="mb-4">
                <div className="flex items-center justify-end gap-2 mb-1">
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(block)
                      toast.success('Copied to clipboard')
                    }}
                    className={cn(
                      'inline-flex items-center gap-1 px-2 py-1 rounded border border-border',
                      'text-muted-foreground hover:text-foreground text-xs'
                    )}
                  >
                    <Copy className="w-3 h-3" />
                    Copy
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-background border border-border text-xs text-foreground overflow-x-auto">
                  <code>{block}</code>
                </pre>
              </div>
            ))}
            <p className="text-xs text-muted-foreground mt-4 mb-6">
              Status will automatically update to Active once KESTREL receives the first event from this source.
            </p>
            <div className="flex justify-end">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg border border-border bg-background text-foreground text-sm hover:bg-muted/50"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

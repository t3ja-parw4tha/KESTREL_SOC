param(
    [Parameter(Mandatory = $true)]
    [string]$Owner,

    [Parameter(Mandatory = $true)]
    [string]$Repo,

    [string]$Branch = "dev"
)

$ErrorActionPreference = "Stop"

if (-not $env:GITHUB_TOKEN) {
    throw "GITHUB_TOKEN environment variable is required."
}

$headers = @{
    Authorization = "Bearer $($env:GITHUB_TOKEN)"
    Accept        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

$requiredChecks = @(
    "CI / lint",
    "CI / type-check",
    "CI / test",
    "CI / security-tests",
    "Security Scan / sast",
    "Dependency Security Audit / python-audit",
    "Dependency Security Audit / frontend-audit",
    "CodeQL / analyze (python)",
    "CodeQL / analyze (javascript-typescript)",
    "DAST And API Security / api-security-smoke",
    "DAST And API Security / dast-zap-baseline"
)

$body = @{
    required_status_checks = @{
        strict   = $true
        contexts = $requiredChecks
    }
    enforce_admins = $true
    required_pull_request_reviews = @{
        dismissal_restrictions      = @{}
        dismiss_stale_reviews       = $true
        require_code_owner_reviews  = $true
        required_approving_review_count = 2
        require_last_push_approval  = $true
    }
    restrictions = $null
    required_linear_history = $false
    allow_force_pushes = $false
    allow_deletions = $false
    block_creations = $false
    required_conversation_resolution = $true
    lock_branch = $false
    allow_fork_syncing = $false
}

$uri = "https://api.github.com/repos/$Owner/$Repo/branches/$Branch/protection"
Write-Host "Applying branch protection to $Owner/$Repo:$Branch ..."
Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 20) -ContentType "application/json" | Out-Null
Write-Host "Branch protection updated successfully."

# Server.ps1 - tiny HttpListener front-end for FirewallApi.ps1.
# Loopback only, single-threaded, token-authenticated. Started by Start-Firewall++.ps1.

param(
    [int]$Port = 8777,
    [string]$Token = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'FirewallApi.ps1')

$script:WebRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'web'
$script:Running = $true

$MimeTypes = @{
    '.html' = 'text/html; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.js'   = 'text/javascript; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.ico'  = 'image/x-icon'
}

# ---------------------------------------------------------------- plumbing

function Send-Bytes {
    param($Ctx, [byte[]]$Bytes, [string]$ContentType, [int]$Status = 200, [hashtable]$Headers)
    try {
        $res = $Ctx.Response
        $res.StatusCode = $Status
        $res.ContentType = $ContentType
        $res.Headers['X-Content-Type-Options'] = 'nosniff'
        $res.Headers['Cache-Control'] = 'no-store'
        $res.Headers['Referrer-Policy'] = 'no-referrer'
        if ($Headers) { foreach ($k in $Headers.Keys) { $res.Headers[$k] = $Headers[$k] } }
        $res.ContentLength64 = $Bytes.Length
        $res.OutputStream.Write($Bytes, 0, $Bytes.Length)
        $res.OutputStream.Close()
    } catch { }
}

function Send-Text {
    param($Ctx, [string]$Text, [string]$ContentType = 'text/plain; charset=utf-8', [int]$Status = 200, [hashtable]$Headers)
    Send-Bytes -Ctx $Ctx -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)) -ContentType $ContentType -Status $Status -Headers $Headers
}

function Send-Json {
    param($Ctx, $Data, [int]$Status = 200)
    $json = if ($Data -is [string]) { $Data } else { $Data | ConvertTo-Json -Depth 8 -Compress }
    Send-Text -Ctx $Ctx -Text $json -ContentType 'application/json; charset=utf-8' -Status $Status
}

function Send-Error {
    param($Ctx, [string]$Message, [int]$Status = 400)
    Send-Json -Ctx $Ctx -Data @{ error = $Message } -Status $Status
}

function Read-Body {
    param($Ctx)
    if (-not $Ctx.Request.HasEntityBody) { return $null }
    $enc = $Ctx.Request.ContentEncoding
    if (-not $enc) { $enc = [Text.Encoding]::UTF8 }
    $reader = New-Object System.IO.StreamReader($Ctx.Request.InputStream, $enc)
    $raw = $reader.ReadToEnd()
    $reader.Close()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Get-Query {
    param($Ctx, [string]$Key, [string]$Default = '')
    $v = $Ctx.Request.QueryString[$Key]
    if ([string]::IsNullOrEmpty($v)) { return $Default }
    return $v
}

function Serve-Static {
    param($Ctx, [string]$RelPath)
    if ([string]::IsNullOrWhiteSpace($RelPath) -or $RelPath -eq '/') { $RelPath = '/index.html' }
    $clean = $RelPath.TrimStart('/').Replace('/', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $script:WebRoot $clean))
    # Path-traversal guard: the resolved path must stay inside web/.
    if (-not $full.StartsWith([IO.Path]::GetFullPath($script:WebRoot), [StringComparison]::OrdinalIgnoreCase)) {
        Send-Text -Ctx $Ctx -Text 'Forbidden' -Status 403; return
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Send-Text -Ctx $Ctx -Text 'Not found' -Status 404; return
    }
    $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
    $type = if ($MimeTypes.ContainsKey($ext)) { $MimeTypes[$ext] } else { 'application/octet-stream' }
    Send-Bytes -Ctx $Ctx -Bytes ([IO.File]::ReadAllBytes($full)) -ContentType $type
}

# ---------------------------------------------------------------- routing

function Invoke-Api {
    param($Ctx, [string]$Path, [string]$Method)

    switch -Regex ("$Method $Path") {

        '^GET /api/status$' {
            return (Get-FirewallStatus)
        }

        '^POST /api/profile$' {
            return (Set-ProfileSettings -Body (Read-Body $Ctx))
        }

        '^GET /api/rules$' {
            $store = if ((Get-Query $Ctx 'store') -eq 'active') { 'ActiveStore' } else { 'PersistentStore' }
            $force = (Get-Query $Ctx 'refresh') -eq '1'
            $rules = Get-RuleTable -Store $store -Force:$force
            return @{ rules = $rules; count = $rules.Count; store = $store
                      groups = @($rules | ForEach-Object { $_.group } | Where-Object { $_ } | Sort-Object -Unique) }
        }

        '^POST /api/rules$' {
            return (New-FwRule -Body (Read-Body $Ctx))
        }

        '^POST /api/rules/update$' {
            $b = Read-Body $Ctx
            return (Set-FwRule -Name "$($b.name)" -Body $b)
        }

        '^POST /api/rules/bulk$' {
            $b = Read-Body $Ctx
            return (Invoke-RuleBulk -Op "$($b.op)" -Names @($b.names))
        }

        '^POST /api/rules/duplicate$' {
            $b = Read-Body $Ctx
            return (Copy-FwRule -Name "$($b.name)")
        }

        '^POST /api/quick$' {
            return (Invoke-QuickAction -Body (Read-Body $Ctx))
        }

        '^GET /api/connections$' {
            return @{ connections = (Get-LiveConnections) }
        }

        '^POST /api/whatif$' {
            return (Test-FirewallPath -Q (Read-Body $Ctx))
        }

        '^GET /api/audit$' {
            return (Get-RuleAudit)
        }

        '^GET /api/history$' {
            return @{ entries = (Get-AuditEntries -Take 400) }
        }

        '^GET /api/log$' {
            return (Get-FirewallLog -Take ([int](Get-Query $Ctx 'take' '500')) -Filter (Get-Query $Ctx 'filter'))
        }

        '^GET /api/backups$' {
            return @{ backups = (Get-Backups) }
        }

        '^POST /api/backup$' {
            return (Backup-FwPolicy)
        }

        '^POST /api/restore$' {
            $b = Read-Body $Ctx
            return (Restore-FwPolicy -Path "$($b.path)")
        }

        '^GET /api/export$' {
            $fmt = Get-Query $Ctx 'format' 'json'
            $body = Export-FwRules -Format $fmt
            $ext  = @{ json = 'json'; csv = 'csv'; ps1 = 'ps1' }[$fmt]
            $type = @{ json = 'application/json'; csv = 'text/csv'; ps1 = 'text/plain' }[$fmt]
            $file = "firewall-rules-$(Get-Date -Format 'yyyyMMdd-HHmmss').$ext"
            Send-Text -Ctx $Ctx -Text $body -ContentType "$type; charset=utf-8" `
                      -Headers @{ 'Content-Disposition' = "attachment; filename=`"$file`"" }
            return $null
        }

        '^POST /api/shutdown$' {
            Send-Json -Ctx $Ctx -Data @{ ok = $true }
            $script:Running = $false
            return $null
        }

        default { throw "No such endpoint: $Method $Path" }
    }
}

# ---------------------------------------------------------------- main loop

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
try {
    $listener.Start()
} catch {
    Write-Host "`n  Could not bind to port $Port : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  This port was taken between launch and start - try again or use: .\Start-Firewall++.ps1 -Port $($Port+1)`n" -ForegroundColor Yellow
    exit 1
}

# Warm the rule cache up front: the first CIM sweep of a few hundred rules
# takes several seconds, and doing it here keeps the first page load snappy.
Write-Host '  Indexing firewall rules...' -ForegroundColor DarkGray -NoNewline
$warm = [Diagnostics.Stopwatch]::StartNew()
$null = Get-RuleTable
$warm.Stop()
Write-Host " $((Get-RuleTable).Count) rules in $([int]$warm.Elapsed.TotalSeconds)s" -ForegroundColor DarkGray

Write-Host ''
Write-Host '  Firewall++ is running.' -ForegroundColor Green
Write-Host "  URL:   http://127.0.0.1:$Port/#$Token"
Write-Host "  Admin: $(if (Test-Elevated) { 'yes - changes will apply' } else { 'NO - read-only, restart elevated to make changes' })" -ForegroundColor $(if (Test-Elevated) { 'Green' } else { 'Yellow' })
Write-Host '  Press Ctrl+C in this window to stop the server.' -ForegroundColor DarkGray
Write-Host ''

while ($script:Running -and $listener.IsListening) {
    try {
        $ctx = $listener.GetContext()
    } catch { break }

    try {
        $req    = $ctx.Request
        $path   = $req.Url.AbsolutePath
        $method = $req.HttpMethod

        # Loopback + Host checks: refuse anything that did not come from this
        # machine addressed to our own origin (blocks DNS-rebinding attempts).
        if (-not $req.IsLocal) { Send-Text -Ctx $ctx -Text 'Forbidden' -Status 403; continue }
        $hostHdr = "$($req.Headers['Host'])"
        if ($hostHdr -and $hostHdr -ne "127.0.0.1:$Port") {
            Send-Text -Ctx $ctx -Text 'Forbidden host header' -Status 403; continue
        }

        if ($path -like '/api/*') {
            # Cross-origin pages cannot read the token, and we never answer a
            # preflight, so a hostile local page cannot drive the API.
            $origin = "$($req.Headers['Origin'])"
            if ($origin -and $origin -ne "http://127.0.0.1:$Port") {
                Send-Error -Ctx $ctx -Message 'Cross-origin requests are not allowed.' -Status 403; continue
            }
            if ("$($req.Headers['X-FW-Token'])" -ne $Token) {
                Send-Error -Ctx $ctx -Message 'Invalid or missing session token. Reopen the URL printed by the launcher.' -Status 401; continue
            }
            # POST is used for a couple of read-only queries too; only genuine
            # policy changes require elevation.
            $readOnlyPosts = @('/api/whatif')
            $mutating = ($method -ne 'GET') -and ($path -notin $readOnlyPosts)
            if ($mutating -and -not (Test-Elevated)) {
                Send-Error -Ctx $ctx -Message 'This server is not running as Administrator, so firewall changes are refused. Restart it elevated.' -Status 403
                continue
            }
            try {
                $result = Invoke-Api -Ctx $ctx -Path $path -Method $method
                if ($null -ne $result) { Send-Json -Ctx $ctx -Data $result }
            } catch {
                $msg = "$($_.Exception.Message)"
                Write-Host "  ! $method $path -> $msg" -ForegroundColor DarkYellow
                Send-Error -Ctx $ctx -Message $msg -Status 400
            }
        } elseif ($method -eq 'GET') {
            Serve-Static -Ctx $ctx -RelPath $path
        } else {
            Send-Text -Ctx $ctx -Text 'Method not allowed' -Status 405
        }
    } catch {
        try { Send-Error -Ctx $ctx -Message "$($_.Exception.Message)" -Status 500 } catch { }
    }
}

$listener.Stop()
$listener.Close()
Write-Host '  Firewall++ stopped.' -ForegroundColor DarkGray

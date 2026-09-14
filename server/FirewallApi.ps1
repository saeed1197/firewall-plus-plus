# FirewallApi.ps1 - Windows Firewall data + mutation layer for Firewall++.
# Dot-sourced by Server.ps1. No external dependencies (NetSecurity module only).

$script:RuleCache      = $null
$script:RuleCacheStore = $null
$script:RuleCacheTime  = [datetime]::MinValue
$script:DataDir        = Join-Path (Split-Path $PSScriptRoot -Parent) 'data'
$script:AuditPath      = Join-Path $script:DataDir 'audit.jsonl'

# ---------------------------------------------------------------- audit trail

function Write-Audit {
    param([string]$Action, [string]$Target, $Detail, [string]$Result = 'ok')
    try {
        if (-not (Test-Path $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
        $entry = [ordered]@{
            time   = (Get-Date).ToString('o')
            user   = "$env:USERDOMAIN\$env:USERNAME"
            action = $Action
            target = $Target
            result = $Result
            detail = $Detail
        }
        Add-Content -Path $script:AuditPath -Value ($entry | ConvertTo-Json -Depth 6 -Compress) -Encoding UTF8
    } catch { }
}

function Get-AuditEntries {
    param([int]$Take = 300)
    if (-not (Test-Path $script:AuditPath)) { return @() }
    $lines = @(Get-Content -Path $script:AuditPath -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ($lines.Count -eq 0) { return @() }
    $start = [Math]::Max(0, $lines.Count - $Take)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = $lines.Count - 1; $i -ge $start; $i--) {
        if (-not $lines[$i]) { continue }
        try { $out.Add(($lines[$i] | ConvertFrom-Json)) } catch { }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------- helpers

function Join-Multi {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { return (($Value | ForEach-Object { "$_" }) -join ', ') }
    return "$Value"
}

function Split-Multi {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $parts = @($Value -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return $null }
    return $parts
}

function ConvertTo-Bool { param($v) return ($v -eq $true -or "$v" -eq 'true' -or "$v" -eq '1') }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- rule table

# Builds the full rule table in ~7 bulk calls instead of one call per rule.
# The naive `Get-NetFirewallRule | Get-NetFirewallPortFilter` pattern costs an
# O(n) pipeline round-trip per rule and takes minutes on a box with 700 rules;
# joining the -All filter sets on InstanceID keeps it to a couple of seconds.
function Build-RuleTable {
    param([string]$Store = 'PersistentStore')

    $common = @{ PolicyStore = $Store; ErrorAction = 'SilentlyContinue' }

    $rules = @(Get-NetFirewallRule @common)
    $app   = @{}; Get-NetFirewallApplicationFilter   -All @common | ForEach-Object { $app[$_.InstanceID]   = $_ }
    $port  = @{}; Get-NetFirewallPortFilter          -All @common | ForEach-Object { $port[$_.InstanceID]  = $_ }
    $addr  = @{}; Get-NetFirewallAddressFilter       -All @common | ForEach-Object { $addr[$_.InstanceID]  = $_ }
    $svc   = @{}; Get-NetFirewallServiceFilter       -All @common | ForEach-Object { $svc[$_.InstanceID]   = $_ }
    $iface = @{}; Get-NetFirewallInterfaceTypeFilter -All @common | ForEach-Object { $iface[$_.InstanceID] = $_ }
    $sec   = @{}; Get-NetFirewallSecurityFilter      -All @common | ForEach-Object { $sec[$_.InstanceID]   = $_ }

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rules) {
        $id = $r.InstanceID
        $a = $app[$id]; $p = $port[$id]; $d = $addr[$id]; $s = $svc[$id]; $i = $iface[$id]; $x = $sec[$id]

        $program = if ($a -and $a.Program) { "$($a.Program)" } else { 'Any' }
        # Only a concrete, fully-expanded file path can be checked. 'System' is
        # the kernel-mode pseudo-path, and wildcards / unresolved %VARS% are not
        # paths we can stat.
        $missing = $false
        if ($program -and $program -ne 'Any' -and $program -ne 'System' -and $program -match '\\') {
            $expanded = [Environment]::ExpandEnvironmentVariables($program)
            if ($expanded -notmatch '[*?%]') {
                $missing = -not (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue)
            }
        }

        $list.Add([ordered]@{
            name           = "$($r.Name)"
            id             = "$id"
            displayName    = "$($r.DisplayName)"
            description    = "$($r.Description)"
            group          = "$($r.DisplayGroup)"
            groupRaw       = "$($r.Group)"
            enabled        = ("$($r.Enabled)" -eq 'True')
            direction      = "$($r.Direction)"
            action         = "$($r.Action)"
            profile        = "$($r.Profile)"
            program        = $program
            programMissing = $missing
            package        = if ($a -and $a.Package) { "$($a.Package)" } else { '' }
            service        = if ($s -and $s.Service) { "$($s.Service)" } else { 'Any' }
            protocol       = if ($p) { "$($p.Protocol)" } else { 'Any' }
            localPort      = if ($p) { Join-Multi $p.LocalPort }  else { 'Any' }
            remotePort     = if ($p) { Join-Multi $p.RemotePort } else { 'Any' }
            icmpType       = if ($p) { Join-Multi $p.IcmpType }   else { '' }
            localAddress   = if ($d) { Join-Multi $d.LocalAddress }  else { 'Any' }
            remoteAddress  = if ($d) { Join-Multi $d.RemoteAddress } else { 'Any' }
            interfaceType  = if ($i) { Join-Multi $i.InterfaceType } else { 'Any' }
            authentication = if ($x) { "$($x.Authentication)" } else { 'NotRequired' }
            encryption     = if ($x) { "$($x.Encryption)" } else { 'NotRequired' }
            localUser      = if ($x) { "$($x.LocalUser)" } else { 'Any' }
            remoteUser     = if ($x) { "$($x.RemoteUser)" } else { 'Any' }
            edge           = "$($r.EdgeTraversalPolicy)"
            owner          = "$($r.Owner)"
            source         = "$($r.PolicyStoreSourceType)"
            sourceName     = "$($r.PolicyStoreSource)"
            status         = "$($r.PrimaryStatus)"
            readOnly       = ("$($r.PolicyStoreSourceType)" -eq 'GroupPolicy' -or $Store -eq 'ActiveStore')
        })
    }
    return $list.ToArray()
}

function Get-RuleTable {
    param([string]$Store = 'PersistentStore', [switch]$Force)
    $age = (Get-Date) - $script:RuleCacheTime
    if ($Force -or $null -eq $script:RuleCache -or $script:RuleCacheStore -ne $Store -or $age.TotalSeconds -gt 120) {
        $script:RuleCache      = Build-RuleTable -Store $Store
        $script:RuleCacheStore = $Store
        $script:RuleCacheTime  = Get-Date
    }
    return $script:RuleCache
}

function Clear-RuleCache { $script:RuleCache = $null; $script:RuleCacheTime = [datetime]::MinValue }

# ---------------------------------------------------------------- profiles

function Get-FirewallStatus {
    $profiles = @()
    foreach ($n in 'Domain', 'Private', 'Public') {
        $p = Get-NetFirewallProfile -Name $n -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $profiles += [ordered]@{
            name            = $n
            enabled         = ("$($p.Enabled)" -eq 'True')
            defaultInbound  = "$($p.DefaultInboundAction)"
            defaultOutbound = "$($p.DefaultOutboundAction)"
            notifyOnListen  = ("$($p.NotifyOnListen)" -eq 'True')
            allowUnicast    = "$($p.AllowUnicastResponseToMulticast)"
            allowLocalRules = "$($p.AllowLocalFirewallRules)"
            logFile         = [Environment]::ExpandEnvironmentVariables("$($p.LogFileName)")
            logAllowed      = ("$($p.LogAllowed)" -eq 'True')
            logBlocked      = ("$($p.LogBlocked)" -eq 'True')
            logMaxKb        = [int]"$($p.LogMaxSizeKilobytes)"
        }
    }

    $rules = Get-RuleTable
    $active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ interface = "$($_.InterfaceAlias)"; network = "$($_.Name)"; category = "$($_.NetworkCategory)" }
    })

    $stats = [ordered]@{
        total    = $rules.Count
        enabled  = @($rules | Where-Object { $_.enabled }).Count
        disabled = @($rules | Where-Object { -not $_.enabled }).Count
        inbound  = @($rules | Where-Object { $_.direction -eq 'Inbound' }).Count
        outbound = @($rules | Where-Object { $_.direction -eq 'Outbound' }).Count
        allow    = @($rules | Where-Object { $_.action -eq 'Allow' }).Count
        block    = @($rules | Where-Object { $_.action -eq 'Block' }).Count
        gpo      = @($rules | Where-Object { $_.source -eq 'GroupPolicy' }).Count
        orphan   = @($rules | Where-Object { $_.programMissing }).Count
        openIn   = @($rules | Where-Object { $_.enabled -and $_.direction -eq 'Inbound' -and $_.action -eq 'Allow' }).Count
    }

    return [ordered]@{
        profiles    = $profiles
        connections = $active
        stats       = $stats
        computer    = $env:COMPUTERNAME
        elevated    = (Test-Elevated)
        psVersion   = "$($PSVersionTable.PSVersion)"
        serverTime  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Set-ProfileSettings {
    param($Body)
    $name = "$($Body.name)"
    if ($name -notin @('Domain', 'Private', 'Public')) { throw "Unknown profile '$name'." }
    $p = @{ Name = $name; ErrorAction = 'Stop' }
    if ($null -ne $Body.enabled)         { $p.Enabled = if (ConvertTo-Bool $Body.enabled) { 'True' } else { 'False' } }
    if ($Body.defaultInbound)            { $p.DefaultInboundAction  = "$($Body.defaultInbound)" }
    if ($Body.defaultOutbound)           { $p.DefaultOutboundAction = "$($Body.defaultOutbound)" }
    if ($null -ne $Body.notifyOnListen)  { $p.NotifyOnListen = if (ConvertTo-Bool $Body.notifyOnListen) { 'True' } else { 'False' } }
    if ($null -ne $Body.logBlocked)      { $p.LogBlocked = if (ConvertTo-Bool $Body.logBlocked) { 'True' } else { 'False' } }
    if ($null -ne $Body.logAllowed)      { $p.LogAllowed = if (ConvertTo-Bool $Body.logAllowed) { 'True' } else { 'False' } }
    if ($Body.logMaxKb)                  { $p.LogMaxSizeKilobytes = [int]$Body.logMaxKb }

    Set-NetFirewallProfile @p
    Write-Audit -Action 'profile.set' -Target $name -Detail $Body
    return (Get-FirewallStatus)
}

# ---------------------------------------------------------------- rule CRUD

function Resolve-RuleParams {
    param($B, [switch]$ForUpdate)
    $p = @{}

    if ("$($B.displayName)" -ne '') {
        if ($ForUpdate) { $p.NewDisplayName = "$($B.displayName)" } else { $p.DisplayName = "$($B.displayName)" }
    }
    if ($null -ne $B.description) { $p.Description = "$($B.description)" }
    if ($null -ne $B.enabled)     { $p.Enabled   = if (ConvertTo-Bool $B.enabled) { 'True' } else { 'False' } }
    if ($B.direction)             { $p.Direction = "$($B.direction)" }
    if ($B.action)                { $p.Action    = "$($B.action)" }
    if ("$($B.profile)" -ne '')   { $p.Profile   = (Split-Multi "$($B.profile)") }
    if ("$($B.edge)" -ne '' -and "$($B.edge)" -ne 'NotConfigured') { $p.EdgeTraversalPolicy = "$($B.edge)" }
    if (-not $ForUpdate -and "$($B.group)" -ne '') { $p.Group = "$($B.group)" }

    $map = @(
        @{ k = 'program';       n = 'Program' }
        @{ k = 'service';       n = 'Service' }
        @{ k = 'localAddress';  n = 'LocalAddress' }
        @{ k = 'remoteAddress'; n = 'RemoteAddress' }
        @{ k = 'localPort';     n = 'LocalPort' }
        @{ k = 'remotePort';    n = 'RemotePort' }
        @{ k = 'interfaceType'; n = 'InterfaceType' }
    )
    foreach ($pair in $map) {
        $v = "$($B.($pair.k))".Trim()
        if ($v -eq '') { continue }
        if ($v -ieq 'any') { $p[$pair.n] = 'Any'; continue }
        $multi = Split-Multi $v
        $p[$pair.n] = if ($multi -and $multi.Count -gt 1) { $multi } else { $v }
    }

    $proto = "$($B.protocol)".Trim()
    if ($proto -ne '') { $p.Protocol = if ($proto -ieq 'any') { 'Any' } else { $proto } }
    if ("$($B.icmpType)" -ne '') { $p.IcmpType = (Split-Multi "$($B.icmpType)") }

    # Ports are only legal on TCP/UDP rules; drop them otherwise so the cmdlet
    # does not fail with a confusing parameter-binding error.
    if ($p.Protocol -and "$($p.Protocol)" -notin @('TCP', 'UDP', '6', '17')) {
        $p.Remove('LocalPort'); $p.Remove('RemotePort')
    }
    return $p
}

function New-FwRule {
    param($Body)
    if ([string]::IsNullOrWhiteSpace("$($Body.displayName)")) { throw 'A rule name is required.' }
    $p = Resolve-RuleParams -B $Body
    $p.Name = [guid]::NewGuid().ToString()
    if (-not $p.Direction) { $p.Direction = 'Inbound' }
    if (-not $p.Action)    { $p.Action    = 'Allow' }
    if (-not $p.Profile)   { $p.Profile   = 'Any' }
    $p.ErrorAction = 'Stop'

    $r = New-NetFirewallRule @p
    Clear-RuleCache
    Write-Audit -Action 'rule.create' -Target "$($Body.displayName)" -Detail $Body
    return @{ name = "$($r.Name)" }
}

function Set-FwRule {
    param([string]$Name, $Body)
    $existing = Get-NetFirewallRule -Name $Name -ErrorAction Stop
    if ("$($existing.PolicyStoreSourceType)" -eq 'GroupPolicy') {
        throw 'This rule comes from Group Policy and cannot be edited locally.'
    }
    $p = Resolve-RuleParams -B $Body -ForUpdate
    $p.Name = $Name
    $p.ErrorAction = 'Stop'
    Set-NetFirewallRule @p
    Clear-RuleCache
    Write-Audit -Action 'rule.update' -Target "$($existing.DisplayName)" -Detail $Body
    return @{ name = $Name }
}

function Invoke-RuleBulk {
    param([string]$Op, [string[]]$Names)
    $done = 0
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($n in $Names) {
        try {
            switch ($Op) {
                'enable'  { Enable-NetFirewallRule  -Name $n -ErrorAction Stop }
                'disable' { Disable-NetFirewallRule -Name $n -ErrorAction Stop }
                'delete'  { Remove-NetFirewallRule  -Name $n -ErrorAction Stop }
                'allow'   { Set-NetFirewallRule -Name $n -Action Allow -ErrorAction Stop }
                'block'   { Set-NetFirewallRule -Name $n -Action Block -ErrorAction Stop }
                default   { throw "Unknown operation '$Op'." }
            }
            $done++
        } catch {
            $errors.Add("$($_.Exception.Message)")
        }
    }
    Clear-RuleCache
    Write-Audit -Action "rule.$Op" -Target "$($Names.Count) rule(s)" -Detail @{ ok = $done; errors = $errors.ToArray() } `
                -Result $(if ($errors.Count) { 'partial' } else { 'ok' })
    return @{ changed = $done; errors = $errors.ToArray() }
}

function Copy-FwRule {
    param([string]$Name)
    $src = Get-RuleTable | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $src) { throw "Rule '$Name' not found." }
    $body = @{}
    foreach ($k in 'description', 'direction', 'action', 'profile', 'program', 'service', 'protocol',
                   'localPort', 'remotePort', 'localAddress', 'remoteAddress', 'interfaceType') {
        $v = "$($src[$k])"
        if ($v -ne '' -and $v -ne 'Any' -and $v -ne 'NotConfigured') { $body[$k] = $v }
    }
    $body.displayName = "$($src.displayName) (copy)"
    $body.group       = "$($src.groupRaw)"
    $body.enabled     = $false
    return (New-FwRule -Body ([pscustomobject]$body))
}

# ---------------------------------------------------------------- quick actions

function Invoke-QuickAction {
    param($Body)
    $kind = "$($Body.kind)"
    switch ($kind) {
        { $_ -in 'blockApp', 'allowApp' } {
            $path = "$($Body.program)"
            if (-not $path) { throw 'Program path required.' }
            $verb = if ($kind -eq 'blockApp') { 'Block' } else { 'Allow' }
            $leaf = Split-Path $path -Leaf
            $dirs = Split-Multi "$($Body.directions)"
            if (-not $dirs) { $dirs = @('Outbound') }
            $made = New-Object System.Collections.Generic.List[string]
            foreach ($d in $dirs) {
                $made.Add((New-FwRule -Body ([pscustomobject]@{
                    displayName = "$verb $leaf ($d)"
                    description = 'Created by Firewall++ quick action'
                    group = 'Firewall++'; direction = $d; action = $verb
                    profile = 'Any'; program = $path; enabled = $true
                })).name)
            }
            return @{ created = $made.ToArray() }
        }
        'blockIp' {
            $ip = "$($Body.address)"
            if (-not $ip) { throw 'Remote address required.' }
            $made = New-Object System.Collections.Generic.List[string]
            foreach ($d in @('Inbound', 'Outbound')) {
                $made.Add((New-FwRule -Body ([pscustomobject]@{
                    displayName = "Block IP $ip ($d)"
                    description = 'Created by Firewall++ quick action'
                    group = 'Firewall++'; direction = $d; action = 'Block'
                    profile = 'Any'; remoteAddress = $ip; enabled = $true
                })).name)
            }
            return @{ created = $made.ToArray() }
        }
        'openPort' {
            $port = "$($Body.port)"
            if (-not $port) { throw 'Port required.' }
            $proto = "$($Body.protocol)"; if (-not $proto) { $proto = 'TCP' }
            $scope = "$($Body.remoteAddress)"; if (-not $scope) { $scope = 'Any' }
            $prof  = "$($Body.profile)"; if (-not $prof) { $prof = 'Any' }
            return (New-FwRule -Body ([pscustomobject]@{
                displayName = "Allow $proto $port inbound"
                description = 'Created by Firewall++ quick action'
                group = 'Firewall++'; direction = 'Inbound'; action = 'Allow'
                profile = $prof; protocol = $proto; localPort = $port
                remoteAddress = $scope; enabled = $true
            }))
        }
        'panic' {
            foreach ($n in 'Domain', 'Private', 'Public') {
                Set-NetFirewallProfile -Name $n -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
            }
            Write-Audit -Action 'quick.panic' -Target 'all profiles' -Detail @{ note = 'default inbound+outbound set to Block' }
            return @{ ok = $true }
        }
        'restoreDefaults' {
            foreach ($n in 'Domain', 'Private', 'Public') {
                Set-NetFirewallProfile -Name $n -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
            }
            Write-Audit -Action 'quick.restoreDefaults' -Target 'all profiles' -Detail @{ note = 'Windows default posture' }
            return @{ ok = $true }
        }
        default { throw "Unknown quick action '$kind'." }
    }
}

# ---------------------------------------------------------------- connections

function Get-LiveConnections {
    $procs = @{}
    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($procs.ContainsKey($proc.Id)) { continue }
        $path = $null
        try { $path = $proc.Path } catch { }
        $procs[$proc.Id] = @{ name = $proc.ProcessName; path = "$path" }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $pi = $procs[[int]$c.OwningProcess]
        $rows.Add([ordered]@{
            protocol      = 'TCP'
            localAddress  = "$($c.LocalAddress)"
            localPort     = [int]$c.LocalPort
            remoteAddress = "$($c.RemoteAddress)"
            remotePort    = [int]$c.RemotePort
            state         = "$($c.State)"
            pid           = [int]$c.OwningProcess
            process       = if ($pi) { $pi.name } else { '' }
            path          = if ($pi) { $pi.path } else { '' }
        })
    }
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $pi = $procs[[int]$u.OwningProcess]
        $rows.Add([ordered]@{
            protocol      = 'UDP'
            localAddress  = "$($u.LocalAddress)"
            localPort     = [int]$u.LocalPort
            remoteAddress = '*'
            remotePort    = 0
            state         = 'Listen'
            pid           = [int]$u.OwningProcess
            process       = if ($pi) { $pi.name } else { '' }
            path          = if ($pi) { $pi.path } else { '' }
        })
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------- what-if / analysis

function Test-PortMatch {
    param([string]$RuleSpec, [string]$Port)
    $p = 0
    if (-not [int]::TryParse($Port, [ref]$p)) { return $true }
    foreach ($chunk in ($RuleSpec -split ',')) {
        $c = $chunk.Trim()
        if ($c -eq '' -or $c -ieq 'any') { return $true }
        if ($c -match '^(\d+)\s*-\s*(\d+)$') {
            if ($p -ge [int]$Matches[1] -and $p -le [int]$Matches[2]) { return $true }
            continue
        }
        if ($c -match '^\d+$' -and [int]$c -eq $p) { return $true }
    }
    return $false
}

# True when $Address definitely falls inside the rule's address spec. Keyword
# scopes (LocalSubnet, DNS, PlayToDevice, ...) are not resolvable from here, so
# they return $false - the caller treats that as "cannot confirm".
function Test-AddressMatch {
    param([string]$Spec, [string]$Address)
    if (-not $Address) { return $false }
    $target = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$target)) { return $false }

    foreach ($chunk in ($Spec -split ',')) {
        $c = $chunk.Trim()
        if ($c -eq '' -or $c -ieq 'any') { return $true }
        if ($c -ieq $Address) { return $true }

        if ($c -match '^(.+)/(\d{1,3})$') {
            $base = $null
            if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$base)) { continue }
            $bits = [int]$Matches[2]
            $tb = $target.GetAddressBytes(); $bb = $base.GetAddressBytes()
            if ($tb.Length -ne $bb.Length) { continue }
            $ok = $true
            for ($i = 0; $i -lt $tb.Length -and $ok; $i++) {
                $take = [Math]::Min(8, [Math]::Max(0, $bits - ($i * 8)))
                if ($take -eq 0) { break }
                $mask = [byte](0xFF -shl (8 - $take))
                if (($tb[$i] -band $mask) -ne ($bb[$i] -band $mask)) { $ok = $false }
            }
            if ($ok) { return $true }
            continue
        }

        if ($c -match '^(.+?)\s*-\s*(.+)$') {
            $lo = $null; $hi = $null
            if (-not [System.Net.IPAddress]::TryParse($Matches[1].Trim(), [ref]$lo)) { continue }
            if (-not [System.Net.IPAddress]::TryParse($Matches[2].Trim(), [ref]$hi)) { continue }
            $t = $target.GetAddressBytes(); $l = $lo.GetAddressBytes(); $h = $hi.GetAddressBytes()
            if ($t.Length -ne $l.Length -or $t.Length -ne $h.Length) { continue }
            $geLo = $true; $leHi = $true
            for ($i = 0; $i -lt $t.Length; $i++) {
                if ($t[$i] -ne $l[$i]) { $geLo = $t[$i] -gt $l[$i]; break }
            }
            for ($i = 0; $i -lt $t.Length; $i++) {
                if ($t[$i] -ne $h[$i]) { $leHi = $t[$i] -lt $h[$i]; break }
            }
            if ($geLo -and $leHi) { return $true }
        }
    }
    return $false
}

# Evaluates which enabled rules would match a hypothetical packet and reports
# the effective verdict using the real precedence order:
# explicit block > explicit allow > profile default action.
#
# A rule is only counted when every restriction it carries can be *confirmed*
# against the query. A rule scoped to a program, a service, a package or a
# specific address does not match a query that leaves that field blank - saying
# otherwise is how a simulator ends up claiming an EmEditor block rule stops
# your browser's HTTPS traffic.
function Test-FirewallPath {
    param($Q)

    $dir     = if ("$($Q.direction)") { "$($Q.direction)" } else { 'Outbound' }
    $proto   = if ("$($Q.protocol)")  { "$($Q.protocol)"  } else { 'TCP' }
    $prof    = if ("$($Q.profile)")   { "$($Q.profile)"   } else { 'Private' }
    $port    = "$($Q.port)".Trim()
    $addr    = "$($Q.address)".Trim()
    $program = "$($Q.program)".Trim()
    $leaf    = if ($program) { Split-Path $program -Leaf } else { '' }

    $hits      = New-Object System.Collections.Generic.List[object]
    $unconfirm = 0

    foreach ($r in (Get-RuleTable)) {
        if (-not $r.enabled) { continue }
        if ($r.direction -ne $dir) { continue }
        if ($r.profile -ne 'Any' -and $r.profile -notmatch $prof) { continue }
        if ($r.protocol -ne 'Any' -and $r.protocol -ne $proto) { continue }

        $spec = if ($dir -eq 'Inbound') { "$($r.localPort)" } else { "$($r.remotePort)" }
        if ($spec -and $spec -ne 'Any') {
            if (-not $port) { $unconfirm++; continue }
            if (-not (Test-PortMatch $spec $port)) { continue }
        }

        if ($r.package) { $unconfirm++; continue }              # store-app (AppContainer) scope
        if ($r.service -and $r.service -ne 'Any') { $unconfirm++; continue }

        if ($r.program -and $r.program -ne 'Any') {
            if (-not $leaf) { $unconfirm++; continue }
            if ("$($r.program)" -notlike "*$leaf") { continue }
        }

        if ($r.remoteAddress -and $r.remoteAddress -ne 'Any') {
            if (-not $addr) { $unconfirm++; continue }
            if (-not (Test-AddressMatch "$($r.remoteAddress)" $addr)) { continue }
        }

        $hits.Add($r)
    }

    $blocks = @($hits | Where-Object { $_.action -eq 'Block' })
    $allows = @($hits | Where-Object { $_.action -eq 'Allow' })
    $pObj   = Get-NetFirewallProfile -Name $prof -ErrorAction SilentlyContinue
    $default = if ($dir -eq 'Inbound') { "$($pObj.DefaultInboundAction)" } else { "$($pObj.DefaultOutboundAction)" }
    if (-not $default -or $default -eq 'NotConfigured') {
        $default = if ($dir -eq 'Inbound') { 'Block' } else { 'Allow' }
    }

    $verdict = if ($blocks.Count) { 'Blocked' } elseif ($allows.Count) { 'Allowed' } else { $default }
    $reason  = if ($blocks.Count) { "Blocked by: $($blocks[0].displayName)" }
               elseif ($allows.Count) { "Allowed by: $($allows[0].displayName)" }
               else { "No rule matches - falls through to the $prof profile default for $dir traffic ($default)" }
    $note    = if ($unconfirm) {
                   "$unconfirm other rule(s) were skipped: they are scoped to a program, service, store app or address that this query did not specify. Fill those fields in for a sharper answer."
               } else { '' }

    return @{
        verdict   = $verdict
        reason    = $reason
        note      = $note
        matches   = @($blocks + $allows)
        byDefault = ($hits.Count -eq 0)
    }
}

# Finds rules that are pointless, risky, or redundant.
function Get-RuleAudit {
    $rules = Get-RuleTable
    $f = New-Object System.Collections.Generic.List[object]

    foreach ($r in ($rules | Where-Object { $_.programMissing })) {
        $f.Add([ordered]@{ severity = 'warn'; kind = 'Orphaned program'; rule = $r.displayName; name = $r.name
            detail = "Program path no longer exists: $($r.program)" })
    }

    # A package (store-app) scope is a real restriction even though the rule
    # reports Program = Any, so those are not wide open.
    foreach ($r in ($rules | Where-Object {
        $_.enabled -and $_.direction -eq 'Inbound' -and $_.action -eq 'Allow' -and
        $_.remoteAddress -eq 'Any' -and $_.program -eq 'Any' -and $_.service -eq 'Any' -and
        -not $_.package -and $_.localUser -eq 'Any' -and $_.profile -match 'Public|Any'
    })) {
        $scope = if ($r.localPort -eq 'Any') { 'every port' } else { "$($r.protocol)/$($r.localPort)" }
        $f.Add([ordered]@{ severity = 'high'; kind = 'Wide-open inbound'; rule = $r.displayName; name = $r.name
            detail = "Allows inbound $scope from any address on a public-facing profile, with no program, service or user restriction" })
    }

    foreach ($r in ($rules | Where-Object { $_.enabled -and $_.direction -eq 'Inbound' -and $_.action -eq 'Allow' -and $_.edge -eq 'Allow' })) {
        $f.Add([ordered]@{ severity = 'warn'; kind = 'Edge traversal'; rule = $r.displayName; name = $r.name
            detail = 'Accepts unsolicited inbound traffic arriving through NAT/Teredo tunnels' })
    }

    $risky = [ordered]@{ '23' = 'Telnet'; '135' = 'RPC'; '139' = 'NetBIOS'; '445' = 'SMB'; '1433' = 'MSSQL'
                         '3306' = 'MySQL'; '3389' = 'RDP'; '5432' = 'PostgreSQL'; '5900' = 'VNC'
                         '6379' = 'Redis'; '27017' = 'MongoDB' }
    foreach ($r in ($rules | Where-Object { $_.enabled -and $_.direction -eq 'Inbound' -and $_.action -eq 'Allow' -and $_.localPort -ne 'Any' -and $_.localPort })) {
        foreach ($k in $risky.Keys) {
            if (Test-PortMatch "$($r.localPort)" $k) {
                $f.Add([ordered]@{ severity = 'high'; kind = 'Sensitive service exposed'; rule = $r.displayName; name = $r.name
                    detail = "Inbound allow covers port $k ($($risky[$k])) - scope: $($r.remoteAddress), profile: $($r.profile)" })
            }
        }
    }

    # Every match criterion goes into the key - two rules are only redundant if
    # they agree on all of them, package and service scope included.
    $seen = @{}
    foreach ($r in ($rules | Where-Object { $_.enabled })) {
        $key = ($r.direction, $r.action, $r.protocol, $r.localPort, $r.remotePort, $r.localAddress,
                $r.remoteAddress, $r.program, $r.package, $r.service, $r.profile, $r.localUser) -join '|'
        if ($seen.ContainsKey($key)) {
            $f.Add([ordered]@{ severity = 'info'; kind = 'Duplicate rule'; rule = $r.displayName; name = $r.name
                detail = "Identical match criteria to '$($seen[$key])' - one of the two is redundant" })
        } else { $seen[$key] = $r.displayName }
    }

    $all = $f.ToArray()
    $rank = @{ high = 0; warn = 1; info = 2 }
    $sorted = @($all | Sort-Object { $rank[$_.severity] })
    return @{
        # Cap the payload: the summary still counts everything.
        findings  = @($sorted | Select-Object -First 250)
        truncated = [Math]::Max(0, $sorted.Count - 250)
        summary   = [ordered]@{
            high = @($all | Where-Object { $_.severity -eq 'high' }).Count
            warn = @($all | Where-Object { $_.severity -eq 'warn' }).Count
            info = @($all | Where-Object { $_.severity -eq 'info' }).Count
        }
    }
}

# ---------------------------------------------------------------- firewall log

function Get-FirewallLog {
    param([int]$Take = 500, [string]$Filter = '')
    $p = Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue
    $path = [Environment]::ExpandEnvironmentVariables("$($p.LogFileName)")
    if (-not $path -or -not (Test-Path -LiteralPath $path)) {
        return @{ available = $false; path = $path; entries = @()
                  message = 'No firewall log file yet. Turn on "Log dropped packets" on the Profiles tab, then generate some traffic.' }
    }

    try {
        # The firewall service holds the log open, so a plain Get-Content fails.
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $sr = New-Object System.IO.StreamReader($fs)
        $raw = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
    } catch {
        return @{ available = $false; path = $path; entries = @(); message = "Could not read the log file: $($_.Exception.Message)" }
    }

    $lines = @($raw -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') })
    $entries = New-Object System.Collections.Generic.List[object]
    for ($i = $lines.Count - 1; $i -ge 0 -and $entries.Count -lt $Take; $i--) {
        if ($Filter -and $lines[$i] -notmatch [regex]::Escape($Filter)) { continue }
        $f = $lines[$i] -split '\s+'
        if ($f.Count -lt 8) { continue }
        $entries.Add([ordered]@{
            date = $f[0]; time = $f[1]; action = $f[2]; protocol = $f[3]
            srcIp = $f[4]; dstIp = $f[5]; srcPort = $f[6]; dstPort = $f[7]
            size = $(if ($f.Count -gt 8) { $f[8] } else { '' })
            direction = $(if ($f.Count -gt 15) { $f[15] } else { '' })
            path = $(if ($f.Count -gt 16) { $f[16] } else { '' })
        })
    }
    return @{ available = $true; path = $path; entries = $entries.ToArray(); total = $lines.Count }
}

# ---------------------------------------------------------------- import / export

function Export-FwRules {
    param([string]$Format = 'json')
    $rules = Get-RuleTable -Force
    switch ($Format) {
        'json' { return ($rules | ConvertTo-Json -Depth 6) }
        'csv' {
            $cols = 'displayName', 'enabled', 'direction', 'action', 'profile', 'protocol', 'localPort',
                    'remotePort', 'localAddress', 'remoteAddress', 'program', 'service', 'group', 'source', 'name'
            $objs = foreach ($r in $rules) {
                $o = [ordered]@{}
                foreach ($c in $cols) { $o[$c] = $r[$c] }
                [pscustomobject]$o
            }
            return (($objs | ConvertTo-Csv -NoTypeInformation) -join "`r`n")
        }
        'ps1' {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("# Windows Firewall rules exported by Firewall++ on $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
            [void]$sb.AppendLine("# Re-create these rules on another machine by running this script elevated.")
            foreach ($r in $rules) {
                $a = New-Object System.Collections.Generic.List[string]
                $a.Add("-DisplayName '" + ($r.displayName -replace "'", "''") + "'")
                $a.Add("-Direction $($r.direction)")
                $a.Add("-Action $($r.action)")
                $a.Add("-Enabled $(if ($r.enabled) { 'True' } else { 'False' })")
                $a.Add("-Profile $($r.profile -replace ' ', '')")
                if ($r.protocol -ne 'Any')      { $a.Add("-Protocol $($r.protocol)") }
                if ($r.localPort  -notin @('', 'Any')) { $a.Add("-LocalPort '"  + ($r.localPort  -replace ', ', "','") + "'") }
                if ($r.remotePort -notin @('', 'Any')) { $a.Add("-RemotePort '" + ($r.remotePort -replace ', ', "','") + "'") }
                if ($r.program    -notin @('', 'Any')) { $a.Add("-Program '" + ($r.program -replace "'", "''") + "'") }
                if ($r.service    -notin @('', 'Any')) { $a.Add("-Service '$($r.service)'") }
                if ($r.remoteAddress -notin @('', 'Any')) { $a.Add("-RemoteAddress '" + ($r.remoteAddress -replace ', ', "','") + "'") }
                [void]$sb.AppendLine("New-NetFirewallRule $($a -join ' ')")
            }
            return $sb.ToString()
        }
        default { throw "Unknown export format '$Format'." }
    }
}

function Backup-FwPolicy {
    param([string]$Path)
    if (-not (Test-Path $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
    if (-not $Path) { $Path = Join-Path $script:DataDir "firewall-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').wfw" }
    $out = & netsh advfirewall export "$Path" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh export failed: $out" }
    Write-Audit -Action 'policy.backup' -Target $Path -Detail @{ }
    return @{ path = "$((Resolve-Path -LiteralPath $Path).Path)" }
}

function Restore-FwPolicy {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Backup file not found: $Path" }
    $out = & netsh advfirewall import "$Path" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh import failed: $out" }
    Clear-RuleCache
    Write-Audit -Action 'policy.restore' -Target $Path -Detail @{ }
    return @{ ok = $true; output = "$out" }
}

function Get-Backups {
    if (-not (Test-Path $script:DataDir)) { return @() }
    return @(Get-ChildItem -Path $script:DataDir -Filter '*.wfw' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | ForEach-Object {
            [ordered]@{ name = $_.Name; path = $_.FullName; sizeKb = [math]::Round($_.Length / 1KB, 1)
                        modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
        })
}

<#
    .SYNOPSIS
    Collects the Windows listening-port surface, owning processes, hosted
    services, and effective firewall policy as one JSON payload.

    .DESCRIPTION
    CLM-safe by construction: cmdlets, pipeline operators, and instance
    method calls (`.ToString()`) only. No `New-Object`, no `[Type]::`
    static-member access, no construction of arbitrary .NET types. Under
    Constrained Language Mode this script still runs; anything a locked-
    down host additionally blocks (e.g. an unallowlisted module) degrades
    to an empty collection for that section via `-ErrorAction
    SilentlyContinue`, never a thrown error that kills the whole run.

    Firewall rules are joined to their port/application/service filters
    with hashtables keyed on InstanceID, each built from exactly one bulk
    query per filter type. Never pipe each rule into
    Get-NetFirewallPortFilter individually -- that is one additional COM
    round trip per rule and takes minutes on a host with a large rule set
    (e.g. a domain controller).

    Output goes to -OutputPath as UTF-8 JSON, never to stdout: warning,
    verbose, and progress streams can contaminate stdout in ways that are
    painful to filter reliably. A file this script alone writes cannot be
    contaminated that way.

    .PARAMETER OutputPath
    Full path of the JSON file to write. The caller reads and deletes this
    file; nothing is written to stdout.
#>
param(
    [Parameter(Mandatory)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Continue'

$languageMode = $ExecutionContext.SessionState.LanguageMode

$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess, State

$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess

$processes = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine

$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, ProcessId, State, PathName, StartMode

# Bulk-fetch each firewall filter class exactly once, then index each by
# InstanceID, so joining every rule to its filters costs three queries
# total -- not one query per rule.
$portFilters = @{}
foreach ($filter in (Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
    $portFilters[$filter.InstanceID] = $filter
}
$appFilters = @{}
foreach ($filter in (Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
    $appFilters[$filter.InstanceID] = $filter
}
$svcFilters = @{}
foreach ($filter in (Get-NetFirewallServiceFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
    $svcFilters[$filter.InstanceID] = $filter
}

$rules = @()
foreach ($rule in (Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
    $portFilter = $portFilters[$rule.InstanceID]
    $appFilter = $appFilters[$rule.InstanceID]
    $svcFilter = $svcFilters[$rule.InstanceID]

    $protocol = $null
    $localPortSpec = $null
    if ($portFilter) {
        $protocol = $portFilter.Protocol.ToString()
        $localPortSpec = ($portFilter.LocalPort -join ',')
    }

    $program = $null
    if ($appFilter) {
        $program = $appFilter.Program
    }

    $serviceName = $null
    if ($svcFilter) {
        $serviceName = $svcFilter.ServiceName
    }

    $rules += [ordered]@{
        rule_id         = $rule.InstanceID.ToString()
        display_name    = $rule.DisplayName
        direction       = $rule.Direction.ToString()
        action          = $rule.Action.ToString()
        protocol        = $protocol
        local_port_spec = $localPortSpec
        program_filter  = $program
        service_filter  = $serviceName
        enabled         = ($rule.Enabled.ToString() -eq 'True')
        policy_store    = $rule.PolicyStoreSourceType.ToString()
    }
}

$profiles = @()
foreach ($fwProfile in (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
    $profiles += [ordered]@{
        name                    = $fwProfile.Name.ToString()
        enabled                 = ($fwProfile.Enabled.ToString() -eq 'True')
        default_inbound_action  = $fwProfile.DefaultInboundAction.ToString()
        default_outbound_action = $fwProfile.DefaultOutboundAction.ToString()
    }
}

# @(...) forces a JSON array even when a section returned zero or exactly
# one object -- ConvertTo-Json otherwise emits a bare object instead of a
# one-element array for a singleton pipeline result, which the Rust-side
# parser would then reject as a shape mismatch rather than silently
# misread.
$payload = [ordered]@{
    LanguageMode      = $languageMode.ToString()
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    TcpEndpoints      = @($tcp)
    UdpEndpoints      = @($udp)
    Processes         = @($processes)
    Services          = @($services)
    FirewallRules     = @($rules)
    FirewallProfiles  = @($profiles)
}

$payload | ConvertTo-Json -Depth 6 -Compress | Out-File -FilePath $OutputPath -Encoding utf8 -Force

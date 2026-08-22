<#
.SYNOPSIS
    Collects Windows listening endpoints, processes, services, and effective
    Windows Firewall policy into a versioned JSON payload.

.DESCRIPTION
    Intended for execution by a supervising Rust application.

    Properties:
      - Windows PowerShell 5.1 and PowerShell 7 compatible
      - Constrained Language Mode friendly
      - No Add-Type, reflection, dynamic code, New-Object, or static .NET calls
      - Bulk firewall-filter queries, never one filter query per rule
      - Stable arrays for zero, one, or many results
      - Section-level collection status and diagnostics
      - Sensitive process/service fields are opt-in
      - Same-directory temporary write followed by final publication
      - Existing final output remains intact if collection/publication fails
      - Emits no JSON to stdout

    The caller should use a unique OutputPath for each invocation, wait for a
    zero exit code, validate SchemaName and SchemaVersion, enforce a maximum
    file size, parse an optional UTF-8 BOM, and delete the result afterward.

.PARAMETER OutputPath
    Final JSON path. Its parent directory must already exist.

.PARAMETER IncludeCommandLine
    Include process command lines. These can contain credentials or tokens.

.PARAMETER IncludeExecutablePath
    Include process executable paths.

.PARAMETER IncludeServicePath
    Include service PathName values. These can contain arguments or secrets.

.PARAMETER IncludeDisabledFirewallRules
    Include disabled firewall rules. By default, only enabled rules are emitted.

.PARAMETER CorrelationId
    Optional caller-supplied correlation identifier copied into the payload.

.PARAMETER MaxOutputBytes
    Maximum size in bytes of the serialized JSON payload. If the payload
    exceeds this cap, the script does NOT publish and exits 1 with the
    reason on stderr. Default 8 MiB; minimum 1 KiB; maximum 100 MiB.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeCommandLine,

    [Parameter()]
    [switch]$IncludeExecutablePath,

    [Parameter()]
    [switch]$IncludeServicePath,

    [Parameter()]
    [switch]$IncludeDisabledFirewallRules,

    [Parameter()]
    [ValidateLength(0, 256)]
    [string]$CorrelationId,

    [Parameter()]
    [ValidateRange(1024, 104857600)]
    [int64]$MaxOutputBytes = 8388608
)

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

$scriptStart = Get-Date
$tempPath = $null
$published = $false
$diagnostics = @()
$collectionStatus = [ordered]@{}

try {
    # Validate and normalize the destination through its existing parent.
    if (($null -eq $OutputPath) -or ($OutputPath.Trim().Length -eq 0)) {
        throw 'OutputPath cannot be empty or whitespace.'
    }

    # -LiteralPath's parameter set has no -Parent switch (PowerShell 7); the
    # parent directory is its default, implicit return value.
    $outputDirectory = Split-Path -LiteralPath $OutputPath
    $outputLeafName = Split-Path -Path $OutputPath -Leaf

    if (($null -eq $outputDirectory) -or ($outputDirectory.Trim().Length -eq 0)) {
        throw 'OutputPath must include an explicit parent directory.'
    }

    if (($null -eq $outputLeafName) -or ($outputLeafName.Trim().Length -eq 0)) {
        throw 'OutputPath must include a file name.'
    }

    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        throw 'The parent directory of OutputPath does not exist.'
    }

    if (Test-Path -LiteralPath $OutputPath -PathType Container) {
        throw 'OutputPath identifies a directory.'
    }

    $resolvedOutputDirectory = (
        Get-Item -LiteralPath $outputDirectory -Force -ErrorAction Stop
    ).FullName
    $OutputPath = Join-Path -Path $resolvedOutputDirectory -ChildPath $outputLeafName
    $tempPath = '{0}.{1}.tmp' -f $OutputPath, $PID

    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop
    }

    $languageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
    $powerShellVersion = $PSVersionTable.PSVersion.ToString()

    # TCP listeners.
    $tcpRaw = @()
    try {
        $tcpRaw = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $collectionStatus.TcpEndpoints = [ordered]@{
            status = 'Success'
            count = $tcpRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'TcpEndpoints'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.TcpEndpoints = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $tcpRaw = @()
    }

    $tcp = @(
        foreach ($endpoint in $tcpRaw) {
            [ordered]@{
                local_address = $endpoint.LocalAddress
                local_port = $endpoint.LocalPort
                owning_process = $endpoint.OwningProcess
                state = if ($null -ne $endpoint.State) {
                    $endpoint.State.ToString()
                }
                else {
                    $null
                }
            }
        }
    )

    # UDP endpoints.
    $udpRaw = @()
    try {
        $udpRaw = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $collectionStatus.UdpEndpoints = [ordered]@{
            status = 'Success'
            count = $udpRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'UdpEndpoints'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.UdpEndpoints = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $udpRaw = @()
    }

    $udp = @(
        foreach ($endpoint in $udpRaw) {
            [ordered]@{
                local_address = $endpoint.LocalAddress
                local_port = $endpoint.LocalPort
                owning_process = $endpoint.OwningProcess
            }
        }
    )

    # Processes. Sensitive fields are opt-in.
    $processRaw = @()
    try {
        $processProperties = @('ProcessId', 'ParentProcessId', 'Name', 'CreationDate')
        if ($IncludeExecutablePath) {
            $processProperties += 'ExecutablePath'
        }
        if ($IncludeCommandLine) {
            $processProperties += 'CommandLine'
        }

        $processRaw = @(
            Get-CimInstance -ClassName Win32_Process `
                -Property $processProperties -ErrorAction Stop
        )
        $collectionStatus.Processes = [ordered]@{
            status = 'Success'
            count = $processRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'Processes'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.Processes = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $processRaw = @()
    }

    $processes = @(
        foreach ($processItem in $processRaw) {
            $record = [ordered]@{
                process_id = $processItem.ProcessId
                parent_process_id = $processItem.ParentProcessId
                name = $processItem.Name
                creation_date = $processItem.CreationDate
            }
            if ($IncludeExecutablePath) {
                $record.executable_path = $processItem.ExecutablePath
            }
            if ($IncludeCommandLine) {
                $record.command_line = $processItem.CommandLine
            }
            $record
        }
    )

    # Services. PathName is opt-in.
    $serviceRaw = @()
    try {
        $serviceProperties = @(
            'Name', 'DisplayName', 'ProcessId', 'State', 'Status',
            'StartMode', 'StartName', 'ServiceType'
        )
        if ($IncludeServicePath) {
            $serviceProperties += 'PathName'
        }

        $serviceRaw = @(
            Get-CimInstance -ClassName Win32_Service `
                -Property $serviceProperties -ErrorAction Stop
        )
        $collectionStatus.Services = [ordered]@{
            status = 'Success'
            count = $serviceRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'Services'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.Services = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $serviceRaw = @()
    }

    $services = @(
        foreach ($serviceItem in $serviceRaw) {
            $record = [ordered]@{
                name = $serviceItem.Name
                display_name = $serviceItem.DisplayName
                process_id = $serviceItem.ProcessId
                state = $serviceItem.State
                status = $serviceItem.Status
                start_mode = $serviceItem.StartMode
                start_name = $serviceItem.StartName
                service_type = $serviceItem.ServiceType
            }
            if ($IncludeServicePath) {
                $record.path_name = $serviceItem.PathName
            }
            $record
        }
    )

    # Bulk firewall filter maps, keyed by normalized InstanceID.
    $portFiltersById = @{}
    $applicationFiltersById = @{}
    $serviceFiltersById = @{}
    $addressFiltersById = @{}
    $interfaceTypeFiltersById = @{}

    try {
        $filterItems = @(
            Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop
        )
        foreach ($filterItem in $filterItems) {
            if ($null -ne $filterItem.InstanceID) {
                $key = $filterItem.InstanceID.ToString().ToUpperInvariant()
                $portFiltersById[$key] = $filterItem
            }
        }
        $collectionStatus.FirewallPortFilters = [ordered]@{
            status = 'Success'
            count = $filterItems.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallPortFilters'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallPortFilters = [ordered]@{
            status = 'Failed'
            count = 0
        }
    }

    try {
        $filterItems = @(
            Get-NetFirewallApplicationFilter -PolicyStore ActiveStore `
                -ErrorAction Stop
        )
        foreach ($filterItem in $filterItems) {
            if ($null -ne $filterItem.InstanceID) {
                $key = $filterItem.InstanceID.ToString().ToUpperInvariant()
                $applicationFiltersById[$key] = $filterItem
            }
        }
        $collectionStatus.FirewallApplicationFilters = [ordered]@{
            status = 'Success'
            count = $filterItems.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallApplicationFilters'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallApplicationFilters = [ordered]@{
            status = 'Failed'
            count = 0
        }
    }

    try {
        $filterItems = @(
            Get-NetFirewallServiceFilter -PolicyStore ActiveStore `
                -ErrorAction Stop
        )
        foreach ($filterItem in $filterItems) {
            if ($null -ne $filterItem.InstanceID) {
                $key = $filterItem.InstanceID.ToString().ToUpperInvariant()
                $serviceFiltersById[$key] = $filterItem
            }
        }
        $collectionStatus.FirewallServiceFilters = [ordered]@{
            status = 'Success'
            count = $filterItems.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallServiceFilters'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallServiceFilters = [ordered]@{
            status = 'Failed'
            count = 0
        }
    }

    try {
        $filterItems = @(
            Get-NetFirewallAddressFilter -PolicyStore ActiveStore `
                -ErrorAction Stop
        )
        foreach ($filterItem in $filterItems) {
            if ($null -ne $filterItem.InstanceID) {
                $key = $filterItem.InstanceID.ToString().ToUpperInvariant()
                $addressFiltersById[$key] = $filterItem
            }
        }
        $collectionStatus.FirewallAddressFilters = [ordered]@{
            status = 'Success'
            count = $filterItems.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallAddressFilters'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallAddressFilters = [ordered]@{
            status = 'Failed'
            count = 0
        }
    }

    try {
        $filterItems = @(
            Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore `
                -ErrorAction Stop
        )
        foreach ($filterItem in $filterItems) {
            if ($null -ne $filterItem.InstanceID) {
                $key = $filterItem.InstanceID.ToString().ToUpperInvariant()
                $interfaceTypeFiltersById[$key] = $filterItem
            }
        }
        $collectionStatus.FirewallInterfaceTypeFilters = [ordered]@{
            status = 'Success'
            count = $filterItems.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallInterfaceTypeFilters'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallInterfaceTypeFilters = [ordered]@{
            status = 'Failed'
            count = 0
        }
    }

    # Firewall rules from the effective ActiveStore.
    $firewallRuleRaw = @()
    try {
        if ($IncludeDisabledFirewallRules) {
            $firewallRuleRaw = @(
                Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
            )
        }
        else {
            $firewallRuleRaw = @(
                Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True `
                    -ErrorAction Stop
            )
        }
        $collectionStatus.FirewallRules = [ordered]@{
            status = 'Success'
            count = $firewallRuleRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallRules'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallRules = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $firewallRuleRaw = @()
    }

    $firewallRules = @(
        foreach ($firewallRule in $firewallRuleRaw) {
            $ruleId = $null
            $ruleName = $null
            $lookupKeys = @()

            if ($null -ne $firewallRule.InstanceID) {
                $ruleId = $firewallRule.InstanceID.ToString()
                $lookupKeys += $ruleId.ToUpperInvariant()
            }
            if ($null -ne $firewallRule.Name) {
                $ruleName = $firewallRule.Name.ToString()
                $nameKey = $ruleName.ToUpperInvariant()
                if ($lookupKeys -notcontains $nameKey) {
                    $lookupKeys += $nameKey
                }
            }

            $portFilter = $null
            $applicationFilter = $null
            $serviceFilter = $null
            $addressFilter = $null
            $interfaceTypeFilter = $null

            foreach ($lookupKey in $lookupKeys) {
                if ($null -eq $portFilter) {
                    $portFilter = $portFiltersById[$lookupKey]
                }
                if ($null -eq $applicationFilter) {
                    $applicationFilter = $applicationFiltersById[$lookupKey]
                }
                if ($null -eq $serviceFilter) {
                    $serviceFilter = $serviceFiltersById[$lookupKey]
                }
                if ($null -eq $addressFilter) {
                    $addressFilter = $addressFiltersById[$lookupKey]
                }
                if ($null -eq $interfaceTypeFilter) {
                    $interfaceTypeFilter = $interfaceTypeFiltersById[$lookupKey]
                }
            }

            $protocol = $null
            $localPorts = @()
            $remotePorts = @()
            $icmpTypes = @()
            $dynamicTarget = $null
            if ($null -ne $portFilter) {
                if ($null -ne $portFilter.Protocol) {
                    $protocol = $portFilter.Protocol.ToString()
                }
                $localPorts = @($portFilter.LocalPort)
                $remotePorts = @($portFilter.RemotePort)
                $icmpTypes = @($portFilter.IcmpType)
                if ($null -ne $portFilter.DynamicTarget) {
                    $dynamicTarget = $portFilter.DynamicTarget.ToString()
                }
            }

            $program = $null
            $package = $null
            if ($null -ne $applicationFilter) {
                $program = $applicationFilter.Program
                $package = $applicationFilter.Package
            }

            $serviceName = $null
            if ($null -ne $serviceFilter) {
                if ($null -ne $serviceFilter.Service) {
                    $serviceName = $serviceFilter.Service
                }
                elseif ($null -ne $serviceFilter.ServiceName) {
                    $serviceName = $serviceFilter.ServiceName
                }
            }

            $localAddresses = @()
            $remoteAddresses = @()
            if ($null -ne $addressFilter) {
                $localAddresses = @($addressFilter.LocalAddress)
                $remoteAddresses = @($addressFilter.RemoteAddress)
            }

            $interfaceTypes = @()
            if ($null -ne $interfaceTypeFilter) {
                $interfaceTypes = @($interfaceTypeFilter.InterfaceType)
            }

            $enabled = $false
            if ($null -ne $firewallRule.Enabled) {
                $enabled = ($firewallRule.Enabled.ToString() -eq 'True')
            }

            [ordered]@{
                rule_id = $ruleId
                name = $ruleName
                display_name = $firewallRule.DisplayName
                description = $firewallRule.Description
                display_group = $firewallRule.DisplayGroup
                group = $firewallRule.Group
                enabled = $enabled
                direction = if ($null -ne $firewallRule.Direction) {
                    $firewallRule.Direction.ToString()
                }
                else {
                    $null
                }
                action = if ($null -ne $firewallRule.Action) {
                    $firewallRule.Action.ToString()
                }
                else {
                    $null
                }
                profiles = @($firewallRule.Profile)
                protocol = $protocol
                local_ports = @($localPorts)
                remote_ports = @($remotePorts)
                icmp_types = @($icmpTypes)
                dynamic_target = $dynamicTarget
                local_addresses = @($localAddresses)
                remote_addresses = @($remoteAddresses)
                program_filter = $program
                package_filter = $package
                service_filter = $serviceName
                interface_types = @($interfaceTypes)
                edge_traversal_policy = if (
                    $null -ne $firewallRule.EdgeTraversalPolicy
                ) {
                    $firewallRule.EdgeTraversalPolicy.ToString()
                }
                else {
                    $null
                }
                # EnforcementStatus can be multi-valued (one entry per
                # policy store a domain-joined host enforces the rule
                # from) even though most of this rule's other fields are
                # genuinely single-valued -- calling .ToString() directly
                # on an array yields the literal text "System.Object[]",
                # not the array's contents, which is exactly the failure
                # this line used to produce on a real domain-joined
                # Windows host. Wrapping in @() first and joining handles
                # both the single- and multi-value case uniformly.
                enforcement_status = if (
                    $null -ne $firewallRule.EnforcementStatus
                ) {
                    (@($firewallRule.EnforcementStatus) | ForEach-Object { $_.ToString() }) -join ','
                }
                else {
                    $null
                }
                primary_status = if ($null -ne $firewallRule.PrimaryStatus) {
                    $firewallRule.PrimaryStatus.ToString()
                }
                else {
                    $null
                }
                status = $firewallRule.Status
                policy_store_source = $firewallRule.PolicyStoreSource
                policy_store_source_type = if (
                    $null -ne $firewallRule.PolicyStoreSourceType
                ) {
                    $firewallRule.PolicyStoreSourceType.ToString()
                }
                else {
                    $null
                }
                filter_resolution = [ordered]@{
                    port_filter_found = ($null -ne $portFilter)
                    application_filter_found = ($null -ne $applicationFilter)
                    service_filter_found = ($null -ne $serviceFilter)
                    address_filter_found = ($null -ne $addressFilter)
                    interface_type_filter_found = ($null -ne $interfaceTypeFilter)
                }
            }
        }
    )

    # Firewall profiles.
    $firewallProfileRaw = @()
    try {
        $firewallProfileRaw = @(
            Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
        )
        $collectionStatus.FirewallProfiles = [ordered]@{
            status = 'Success'
            count = $firewallProfileRaw.Count
        }
    }
    catch {
        $diagnostics += [ordered]@{
            section = 'FirewallProfiles'
            severity = 'Error'
            message = $_.Exception.Message
        }
        $collectionStatus.FirewallProfiles = [ordered]@{
            status = 'Failed'
            count = 0
        }
        $firewallProfileRaw = @()
    }

    $firewallProfiles = @(
        foreach ($firewallProfile in $firewallProfileRaw) {
            [ordered]@{
                name = if ($null -ne $firewallProfile.Name) {
                    $firewallProfile.Name.ToString()
                }
                else {
                    $null
                }
                enabled = if ($null -ne $firewallProfile.Enabled) {
                    $firewallProfile.Enabled.ToString() -eq 'True'
                }
                else {
                    $false
                }
                default_inbound_action = if (
                    $null -ne $firewallProfile.DefaultInboundAction
                ) {
                    $firewallProfile.DefaultInboundAction.ToString()
                }
                else {
                    $null
                }
                default_outbound_action = if (
                    $null -ne $firewallProfile.DefaultOutboundAction
                ) {
                    $firewallProfile.DefaultOutboundAction.ToString()
                }
                else {
                    $null
                }
                allow_inbound_rules = $firewallProfile.AllowInboundRules
                allow_local_firewall_rules = $firewallProfile.AllowLocalFirewallRules
                allow_local_ipsec_rules = $firewallProfile.AllowLocalIPsecRules
                allow_unicast_response_to_multicast = $firewallProfile.AllowUnicastResponseToMulticast
                notify_on_listen = $firewallProfile.NotifyOnListen
                enable_stealth_mode_for_ipsec = $firewallProfile.EnableStealthModeForIPsec
                log_file_name = $firewallProfile.LogFileName
                log_max_size_kilobytes = $firewallProfile.LogMaxSizeKilobytes
                log_allowed = $firewallProfile.LogAllowed
                log_blocked = $firewallProfile.LogBlocked
                log_ignored = $firewallProfile.LogIgnored
                disabled_interface_aliases = @(
                    $firewallProfile.DisabledInterfaceAliases
                )
            }
        }
    )

    # In-memory endpoint ownership/service joins. Snapshots can race with
    # process and service changes, so unresolved owners remain explicit.
    $processById = @{}
    foreach ($processItem in $processes) {
        if ($null -ne $processItem.process_id) {
            $processById[$processItem.process_id.ToString()] = $processItem
        }
    }

    $servicesByProcessId = @{}
    foreach ($serviceItem in $services) {
        if (($null -ne $serviceItem.process_id) -and ($serviceItem.process_id -ne 0)) {
            $processKey = $serviceItem.process_id.ToString()
            if (-not $servicesByProcessId.ContainsKey($processKey)) {
                $servicesByProcessId[$processKey] = @()
            }
            $servicesByProcessId[$processKey] = @(
                $servicesByProcessId[$processKey]
                $serviceItem.name
            )
        }
    }

    $listeningSurface = @(
        foreach ($endpoint in $tcp) {
            $processKey = $endpoint.owning_process.ToString()
            $owner = $processById[$processKey]
            $hostedServices = @($servicesByProcessId[$processKey])
            [ordered]@{
                transport = 'TCP'
                local_address = $endpoint.local_address
                local_port = $endpoint.local_port
                state = $endpoint.state
                owning_process = $endpoint.owning_process
                process_name = if ($null -ne $owner) { $owner.name } else { $null }
                hosted_services = @($hostedServices)
                owner_resolved = ($null -ne $owner)
            }
        }

        foreach ($endpoint in $udp) {
            $processKey = $endpoint.owning_process.ToString()
            $owner = $processById[$processKey]
            $hostedServices = @($servicesByProcessId[$processKey])
            [ordered]@{
                transport = 'UDP'
                local_address = $endpoint.local_address
                local_port = $endpoint.local_port
                state = $null
                owning_process = $endpoint.owning_process
                process_name = if ($null -ne $owner) { $owner.name } else { $null }
                hosted_services = @($hostedServices)
                owner_resolved = ($null -ne $owner)
            }
        }
    )

    $scriptEnd = Get-Date
    $durationMilliseconds = [long](($scriptEnd - $scriptStart).TotalMilliseconds)

    $normalizedCorrelationId = $null
    if (($null -ne $CorrelationId) -and ($CorrelationId.Trim().Length -gt 0)) {
        $normalizedCorrelationId = $CorrelationId
    }

    $is64BitOperatingSystem = $false
    $is64BitProcess = $false
    if (
        ($env:PROCESSOR_ARCHITECTURE -match '^(AMD64|ARM64)$') -or
        ($env:PROCESSOR_ARCHITEW6432 -match '^(AMD64|ARM64)$')
    ) {
        $is64BitOperatingSystem = $true
    }
    if ($env:PROCESSOR_ARCHITECTURE -match '^(AMD64|ARM64)$') {
        $is64BitProcess = $true
    }

    $payload = [ordered]@{
        SchemaName = 'windows-listening-surface'
        SchemaVersion = 2
        Metadata = [ordered]@{
            correlation_id = $normalizedCorrelationId
            collected_at_utc = $scriptEnd.ToUniversalTime().ToString('o')
            duration_milliseconds = $durationMilliseconds
            computer_name = $env:COMPUTERNAME
            process_id = $PID
            language_mode = $languageMode
            powershell_version = $powerShellVersion
            powershell_edition = $PSVersionTable.PSEdition
            is_64_bit_process = $is64BitProcess
            is_64_bit_operating_system = $is64BitOperatingSystem
            policy_store = 'ActiveStore'
            command_lines_included = [bool]$IncludeCommandLine
            executable_paths_included = [bool]$IncludeExecutablePath
            service_paths_included = [bool]$IncludeServicePath
            disabled_firewall_rules_included = [bool]$IncludeDisabledFirewallRules
        }
        CollectionStatus = $collectionStatus
        Diagnostics = @($diagnostics)
        ListeningSurface = @($listeningSurface)
        TcpEndpoints = @($tcp)
        UdpEndpoints = @($udp)
        Processes = @($processes)
        Services = @($services)
        FirewallRules = @($firewallRules)
        FirewallProfiles = @($firewallProfiles)
    }

    # Serialize and validate before touching the published path.
    $json = $payload | ConvertTo-Json -Depth 10 -Compress -ErrorAction Stop
    if (($null -eq $json) -or ($json.Length -eq 0)) {
        throw 'JSON serialization produced an empty result.'
    }
    if ($json.Length -gt $MaxOutputBytes) {
        throw "payload size $($json.Length) bytes exceeds MaxOutputBytes $MaxOutputBytes bytes"
    }

    $json | Out-File -LiteralPath $tempPath -Encoding UTF8 -Force `
        -NoNewline -ErrorAction Stop

    $temporaryFile = Get-Item -LiteralPath $tempPath -Force -ErrorAction Stop
    if ($temporaryFile.PSIsContainer) {
        throw 'The temporary output path unexpectedly identifies a directory.'
    }
    if ($temporaryFile.Length -le 0) {
        throw 'The temporary JSON file is empty.'
    }

    # Same-directory publication. A unique OutputPath per run is recommended.
    Move-Item -LiteralPath $tempPath -Destination $OutputPath -Force `
        -ErrorAction Stop
    $published = $true
}
catch {
    # Surface the failure on stderr so the parent (which reads stdout /
    # the published file) has a real diagnostic trail to follow, instead
    # of seeing only "exit 1" with no error message. The diagnostic
    # entry is the same shape as the per-section $diagnostics array,
    # so a single parser can consume both paths identically.
    $published = $false
    $fatal = [ordered]@{
        section = 'Fatal'
        severity = 'Error'
        message = $_.Exception.Message
        script_stack_trace = $_.ScriptStackTrace
    }
    Write-Error -Message ($fatal | ConvertTo-Json -Compress -ErrorAction SilentlyContinue)
}
finally {
    if (($null -ne $tempPath) -and (Test-Path -LiteralPath $tempPath)) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

if ($published) {
    exit 0
}

exit 1

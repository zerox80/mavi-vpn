# Every network and filesystem cmdlet used by the injected scripts is mocked.
$ErrorActionPreference = 'Stop'
# SETUP_SCRIPT
$script:routes = [System.Collections.Generic.List[object]]::new()
$script:foreign = @(
    [pscustomobject]@{ DestinationPrefix=$targetPrefix; InterfaceIndex=99; NextHop=$nextHop; PolicyStore='ActiveStore' },
    [pscustomobject]@{ DestinationPrefix=$targetPrefix; InterfaceIndex=7; NextHop=$foreignNextHop; PolicyStore='ActiveStore' },
    [pscustomobject]@{ DestinationPrefix=$targetPrefix; InterfaceIndex=7; NextHop=$nextHop; PolicyStore='PersistentStore' },
    [pscustomobject]@{ DestinationPrefix='203.0.113.12/32'; InterfaceIndex=7; NextHop='192.0.2.1'; PolicyStore='ActiveStore' }
)
foreach ($route in $script:foreign) { $script:routes.Add($route) }
$script:owned = [pscustomobject]@{ DestinationPrefix=$targetPrefix; InterfaceIndex=7; NextHop=$nextHop; PolicyStore='ActiveStore' }
if ($existing -or $uninstaller) { $script:routes.Add($script:owned) }
$script:otherOwned = [pscustomobject]@{ DestinationPrefix='2001:db8::11/128'; InterfaceIndex=8; NextHop='fe80::1'; PolicyStore='ActiveStore' }
if ($uninstaller) { $script:routes.Add($script:otherOwned) }
$script:ownedSplits = @()
if ($uninstaller) {
    foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
        $foreignSplit = [pscustomobject]@{ DestinationPrefix=$prefix; InterfaceIndex=99; NextHop='0.0.0.0'; PolicyStore='ActiveStore' }
        $ownedSplit = [pscustomobject]@{ DestinationPrefix=$prefix; InterfaceIndex=42; NextHop='0.0.0.0'; PolicyStore='ActiveStore' }
        $script:foreign += $foreignSplit
        $script:ownedSplits += $ownedSplit
        $script:routes.Add($foreignSplit)
        $script:routes.Add($ownedSplit)
    }
}

function Get-NetRoute {
    [CmdletBinding()]
    param([string]$DestinationPrefix, [uint32]$InterfaceIndex, [string]$NextHop, [string]$PolicyStore)
    if ($DestinationPrefix -eq $defaultPrefix) {
        throw 'Host exception incorrectly queried the default gateway'
    }
    @($script:routes) | Where-Object {
        $_.DestinationPrefix -eq $DestinationPrefix -and
        (-not $InterfaceIndex -or $_.InterfaceIndex -eq $InterfaceIndex) -and
        (-not $NextHop -or $_.NextHop -eq $NextHop) -and
        (-not $PolicyStore -or $_.PolicyStore -eq $PolicyStore)
    }
}
function Find-NetRoute {
    [CmdletBinding()]
    param([string]$RemoteIPAddress)
    if ($RemoteIPAddress -ne $targetPrefix.Split('/')[0]) { throw 'Wrong route lookup destination' }
    # Find-NetRoute also returns the selected local IP. The route must be
    # selected explicitly, preserving the on-link or specific-route next hop.
    [pscustomobject]@{ IPAddress='192.0.2.2'; InterfaceIndex=7 }
    [pscustomobject]@{ DestinationPrefix=$targetPrefix; InterfaceIndex=7; NextHop=$script:nextHop; RouteMetric=1 }
}
function Get-NetAdapter {
    [CmdletBinding()]
    param([uint32]$InterfaceIndex, [switch]$IncludeHidden)
    $name = if ($InterfaceIndex -eq 42) { 'MaviVPN' } else { 'Ethernet' }
    [pscustomobject]@{ Status='Up'; Name=$name; InterfaceDescription='Physical Ethernet' }
}
function New-NetRoute {
    param([string]$DestinationPrefix, [uint32]$InterfaceIndex, [string]$NextHop,
          [string]$PolicyStore, [uint32]$RouteMetric, [switch]$Confirm)
    if (Get-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore $PolicyStore) {
        throw 'An existing route was recreated'
    }
    $script:routes.Add($script:owned)
    $script:owned
}
function Remove-NetRoute {
    [CmdletBinding()]
    param([string]$DestinationPrefix, [uint32]$InterfaceIndex, [string]$NextHop,
          [string]$PolicyStore, [switch]$Confirm,
          [Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($InputObject) { [void]$script:routes.Remove($InputObject) }
        else {
            $matches = @(Get-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore $PolicyStore)
            foreach ($route in $matches) { [void]$script:routes.Remove($route) }
        }
    }
}
function Test-Path { param($Path) return $true }
function Get-Content {
    [CmdletBinding()]
    param($LiteralPath)
    '{"destination":"203.0.113.10","interface_index":7,"next_hop":"192.0.2.1"}'
    '{"destination":"2001:db8::11","interface_index":8,"next_hop":"fe80::1"}'
    # Prefix-only and malformed records must never trigger broad route deletion.
    '203.0.113.12/32'
    '{"destination":"203.0.113.12","interface_index":0,"next_hop":"192.0.2.1"}'
    '{"destination":"203.0.113.12","interface_index":7,"next_hop":"::"}'
}
function Remove-Item {
    [CmdletBinding()]
    param($Path, $LiteralPath, [switch]$Force)
}

if (-not $uninstaller) {
    $record = & {
        # ADD_ROUTE_SCRIPT
    } | ConvertFrom-Json
    if ($record.created -eq $existing) { throw 'Incorrect route ownership' }
    if ($record.interface_index -ne 7 -or $record.next_hop -ne $nextHop) { throw 'Incorrect route identity' }
}

# CLEANUP_SCRIPT

foreach ($route in $script:foreign) {
    if (-not $script:routes.Contains($route)) { throw "Foreign route was removed: $($route | ConvertTo-Json -Compress)" }
}
if ($existing -and $script:routes.Count -ne $script:foreign.Count + 1) { throw 'Existing route was removed' }
if (-not $existing -and $script:routes.Contains($script:owned)) { throw 'Owned route was not removed' }
if ($uninstaller -and $script:routes.Contains($script:otherOwned)) { throw 'Second owned route was not removed' }
foreach ($route in $script:ownedSplits) {
    if ($script:routes.Contains($route)) { throw 'Owned split route was not removed' }
}
Write-Output 'host route ownership checks passed'

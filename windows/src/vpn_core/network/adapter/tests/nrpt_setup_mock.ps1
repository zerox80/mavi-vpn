# FAIL_STEP
function Get-DnsClientNrptRule {
    [CmdletBinding()] param()
    if ($global:failStep -eq 'get') { Write-Error 'NRPT query failed' }
    [PSCustomObject]@{ Comment = 'MaviVPN'; DisplayName = 'MaviVPN DNS Force' }
}
function Remove-DnsClientNrptRule {
    [CmdletBinding()] param([switch]$Force, [Parameter(ValueFromPipeline)]$InputObject)
    if ($global:failStep -eq 'remove') { Write-Error 'NRPT removal failed' }
}
function Add-DnsClientNrptRule {
    [CmdletBinding()] param([string]$Namespace, [string[]]$NameServers, [string]$Comment, [string]$DisplayName)
    if ($global:failStep -eq 'add') { Write-Error 'NRPT installation failed' }
    if ($Namespace -ne '.') { throw 'All DNS namespaces must use the tunnel' }
    $NameServers -join ','
}
function Clear-DnsClientCache {
    [CmdletBinding()] param()
    if ($global:failStep -eq 'clear') { Write-Error 'DNS cache flush failed' }
}
# SETUP_SCRIPT

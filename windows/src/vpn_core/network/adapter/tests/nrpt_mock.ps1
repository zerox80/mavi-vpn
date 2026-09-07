# All operating-system commands invoked by the cleanup are mocked. No actual
# DNS, registry, or file state is read or changed by this regression test.
$ErrorActionPreference = 'Stop'
$script:removed = [System.Collections.Generic.List[string]]::new()
$script:policies = @(
    [pscustomobject]@{Name='foreign-cloudflare';Namespace=@('.');NameServers=@('1.1.1.1');Comment='Corporate DNS';DisplayName='Company'},
    [pscustomobject]@{Name='foreign-google';Namespace=@('.');NameServers=@('8.8.8.8');Comment='';DisplayName=''},
    [pscustomobject]@{Name='foreign-v6';Namespace=@('.');NameServers=@('2606:4700:4700::1111');Comment='';DisplayName=''},
    [pscustomobject]@{Name='owned-comment';Namespace=@('.');NameServers=@('10.99.0.1');Comment='MaviVPN';DisplayName=''},
    [pscustomobject]@{Name='owned-display';Namespace=@('.');NameServers=@('9.9.9.9');Comment='';DisplayName='MaviVPN DNS Force'}
)
function Get-DnsClientNrptRule { $script:policies }
function Remove-DnsClientNrptRule {
    param([Parameter(ValueFromPipeline)]$InputObject, [switch]$Force)
    process { $script:removed.Add($InputObject.Name) }
}
function Test-Path { $true }
function Get-ChildItem {
    param($Path)
    foreach ($policy in $script:policies) {
        [pscustomobject]@{PSPath=($Path + '\' + $policy.Name)}
    }
}
function Get-ItemProperty {
    param($Path)
    $script:policies | Where-Object { $Path.EndsWith('\' + $_.Name) }
}
function Remove-Item {
    param($Path, $LiteralPath, [switch]$Recurse, [switch]$Force)
    if ($Path) { $script:removed.Add(($Path -split '\\')[-1]) }
}
function Get-Content { throw 'Resolver metadata must not authorize policy removal' }
function Clear-DnsClientCache {}
function Register-DnsClient {}

# CLEANUP_SCRIPT

$expected = @('owned-comment', 'owned-display')
if ($script:removed.Count -ne 8 -or @($script:removed | Where-Object { $_ -notin $expected }).Count) {
    throw "Cleanup removed unexpected policies: $($script:removed -join ', ')"
}
Write-Output 'ownership checks passed'

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Stop', 'Install', 'Uninstall')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$serviceName = 'MaviVPNService'

try {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }

    if ($Action -eq 'Install') {
        $binary = Join-Path $InstallDir 'mavi-vpn-service.exe'
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw "Service binary missing: $binary"
        }
        $binaryPath = '"' + $binary + '"'
        if ($service) {
            $serviceConfig = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            $result = Invoke-CimMethod -InputObject $serviceConfig -MethodName Change -Arguments @{
                PathName = $binaryPath
                StartMode = 'Automatic'
                StartName = 'LocalSystem'
            }
            if ($result.ReturnValue -ne 0) {
                throw "Service configuration failed with code $($result.ReturnValue)"
            }
        } else {
            New-Service -Name $serviceName -DisplayName 'Mavi VPN Service' `
                -BinaryPathName $binaryPath -StartupType Automatic | Out-Null
        }
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    } elseif ($Action -eq 'Uninstall' -and $service) {
        $serviceConfig = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        $result = Invoke-CimMethod -InputObject $serviceConfig -MethodName Delete
        if ($result.ReturnValue -ne 0) {
            throw "Service deletion failed with code $($result.ReturnValue)"
        }
    }
    exit 0
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
}

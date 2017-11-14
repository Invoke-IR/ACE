function Get-UniversalTimeString {
    [CmdletBinding()]
    Param
    (
    )

    (Get-Date).ToUniversalTime().ToString('yyyyMMddThhmmssmsmsZ')
}

function Get-FullProcess
{
    $proc = Get-WmiObject win32_process -Filter "Name='explorer.exe'"

    foreach ($p in $proc)
    {
        $props = @{
            Name = $p.Name
            Path = $p.ExecutablePath
            SHA256 = (Get-FileHash -Algorithm SHA256 -Path $p.ExecutablePath).Hash
        }

        $obj = New-Object -TypeName psobject -Property $props
        Write-Output $obj
    }
}

function Start-PSIScan {
    [CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true)]
    [string]
    $ComputerName,

    [Parameter(Mandatory=$true)]
    [string]
    $Uri,

    [Parameter(Mandatory=$true)]
    [Guid]
    $SweepId,
    
    [Parameter(Mandatory=$true)]
    [Guid]
    $ScanId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('CachedDns','LoadedModule','MasterBootRecord','NetworkConnection','Prefetch','FullProcess','ScheduledTask','FullService','SimpleNamedPipe','SecurityEvent')]
    [string]
    $ScanType
    )

    Begin {
        $Output = @{
            computerName = $ComputerName
            scanType = $ScanType
            resultDate = [DateTime]::UtcNow
            resultId = $ScanId
            data = (Get-FullProcess)
        }
    }

    Process {

    } # End Process block

    End {
        $output
        #ConvertTo-Json $Output
        Invoke-WebRequest -Method Post -Uri "$($Uri)/ace/result/$($ScanId)" -Body (ConvertTo-Json $Output) -ContentType 'application/json'
        #Invoke-WebRequest -Method Put -Uri "$($Uri)/ace/sweep/$($SweepId)" -Body (ConvertTo-Json $ScanId) -ContentType 'application/json'
        sleep 1000
    }
}
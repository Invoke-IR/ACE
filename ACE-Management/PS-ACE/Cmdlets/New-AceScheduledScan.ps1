function New-AceScheduledScan
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string[]]
        $ComputerId,

        [Parameter(Mandatory)]
        [string]
        $ScriptId,

        [Parameter(Mandatory)]
        [string]
        $Uri,
        
        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $Thumbprint,

        [Parameter(Mandatory)]
        [Int32]
        $Hour,

        [Parameter(Mandatory)]
        [Int32]
        $Minute,

        [Parameter(Mandatory)]
        [Int32]
        $IntervalInMinutes,

        [Parameter()]
        [Int32]
        $RepeatCount = 0
    )

    $body = @{
        ComputerId = $ComputerId
        ScriptId = $ScriptId
        Uri = $Uri
        Hour = $Hour
        Minute = 0
        Interval = $IntervalInMinutes
        RepeatCount = $RepeatCount
    }

    $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/schedule" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
    Write-Output ($result | ConvertFrom-Json)        
}
function Start-AceSweep
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $Uri,

        [Parameter()]
        [string]
        $ExternalUri,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $Thumbprint,

        [Parameter(Mandatory)]
        [Guid[]]
        $ComputerId,

        [Parameter(Mandatory)]
        [Guid]
        $ScriptId      
    )

    if(-not $PSBoundParameters.ContainsKey('ExternalUri'))
    {
        $ExternalUri = $Uri
    }

    $body = @{
        ComputerId = $ComputerId
        ScriptId = $ScriptId
        Uri = $Uri
        ExternalUri = $ExternalUri
    }

    try
    {
        $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/sweep" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
        Write-Output ($result | ConvertFrom-Json)   
    }
    catch
    {
        
    }
}
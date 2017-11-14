function Get-AceSweepResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $Uri,

        [Parameter(Mandatory)]
        [string]
        $ApiKey,

        [Parameter(Mandatory)]
        [string]
        $Thumbprint,

        [Parameter()]
        [Guid]
        $Id
    )

    try
    {
        $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/scan/$($Id)" -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
        Write-Output ($result | ConvertFrom-Json)        
    }
    catch
    {
        
    }
}
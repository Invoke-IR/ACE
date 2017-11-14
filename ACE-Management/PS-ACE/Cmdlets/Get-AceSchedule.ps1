function Get-AceSchedule
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
        $Thumbprint        
    )

    try
    {
        $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/schedule" -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
        Write-Output ($result | ConvertFrom-Json)        
    }
    catch
    {
        
    }
}
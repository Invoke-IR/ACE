function Get-AceUser
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
        $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/user" -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
        Write-Output ($result | ConvertFrom-Json)        
    }
    catch
    {
        
    }
}
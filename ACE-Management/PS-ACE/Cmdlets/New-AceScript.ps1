function New-AceScript
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

        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $Language,
        
        [Parameter()]
        [string]
        $RoutingKey
    )

    $body = @{
        Name = $Name
        Language = $Language
        RoutingKey = $RoutingKey
        Content = [System.IO.File]::ReadAllBytes($Path)
    }

    try 
    {
        $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/script" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
        Write-Output ($result | ConvertFrom-Json)        
    }
    catch 
    {
        
    }
}
function Download-AceFile
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
        [Guid]
        $ComputerId,

        [Parameter(Mandatory)]
        [string]
        $FilePath
    )

    $body = @{
        Uri = $Uri
        ComputerId = $ComputerId
        FilePath = $FilePath
    }

    try 
    {
        $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/download" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
        Write-Output ($result | ConvertFrom-Json)        
    }
    catch 
    {
       Write-Warning "test" 
    }
}
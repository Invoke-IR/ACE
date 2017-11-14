function Remove-AceCredential
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
        $Id
    )

    try
    {
        $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/credential/delete/$($Id)" -ApiKey $ApiKey -Thumbprint $Thumbprint
        Write-Output ($result | ConvertFrom-Json)   
    }
    catch
    {
        
    }
}
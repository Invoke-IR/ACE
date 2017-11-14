function New-AceCredential
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
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    $body = @{
        UserName = $Credential.UserName
        Password = $Credential.GetNetworkCredential().Password
    }

    try 
    {
        $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/credential" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
        Write-Output ($result | ConvertFrom-Json)    
    }
    catch 
    {
        
    }
}
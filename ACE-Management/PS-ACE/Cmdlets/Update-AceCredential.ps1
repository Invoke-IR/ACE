function Update-AceCredential
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
        $CredentialId,

        [Parameter(Mandatory)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    $body = @{
        UserName = $Credential.UserName
        Password = $Credential.GetNetworkCredential().Password
    }

    $result = Invoke-AceWebRequest -Method Put -Uri "$($Uri)/ace/credential/$($CredentialId)" -Body (ConvertTo-Json $body) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint

    Write-Output ($result.Content | ConvertFrom-Json)
}
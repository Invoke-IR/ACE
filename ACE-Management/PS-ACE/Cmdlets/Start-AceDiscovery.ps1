function Start-AceDiscovery
{
    [CmdletBinding(DefaultParameterSetName = "Domain")]
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

        [Parameter(Mandatory, ParameterSetName = "Domain")]
        [string]
        $Domain,

        [Parameter(Mandatory, ParameterSetName = "ComputerList")]
        [string[]]
        $ComputerName
    )

    switch($PSCmdlet.ParameterSetName)
    {
        ComputerList
        {
            $body = @{
                ComputerName = $ComputerName
                CredentialId = $CredentialId
            }
            
            $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/discover/computerlist" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -Thumbprint $Thumbprint
        }
        Domain
        {
            $body = @{
                Domain = $Domain
                CredentialId = $CredentialId
            }

            $result = Invoke-AceWebRequest -Method Post -Uri "$($Uri)/ace/discover/domain" -Body (ConvertTo-Json $body -Compress) -ContentType application/json -ApiKey $ApiKey -CheckCert
            #$result = Invoke-WebRequest -Method Post -Uri "$($Uri)/ace/discover/domain" -Body (ConvertTo-Json $body) -Headers $header -ContentType application/json
        }
    }

    Write-Output ($result | ConvertFrom-Json)
    #Write-Output ($result.Content | ConvertFrom-Json)
}
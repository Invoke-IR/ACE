function Get-AceCredential
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
        if($PSBoundParameters.ContainsKey('Id'))
        {
            $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/credential/pscredential/$($Id)" -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
            $result = $result | ConvertFrom-Json
            $secpassword = ConvertTo-SecureString -String $result.password -AsPlainText -Force
            $cred = New-Object -TypeName System.Management.Automation.PSCredential($result.userName, $secpassword)
            Write-Output $cred
        }
        else
        {
            $result = Invoke-AceWebRequest -Method Get -Uri "$($Uri)/ace/credential" -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
            Write-Output ($result | ConvertFrom-Json)
        }
    }
    catch
    {
        
    }
}
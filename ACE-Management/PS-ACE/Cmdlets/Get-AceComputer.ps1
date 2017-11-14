function Get-AceComputer
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

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $Url = "$($Uri)/ace/computer/$($Id)"
    }
    else
    {
        $Url = "$($Uri)/ace/computer"
    }
    
    try
    {
        $result = Invoke-AceWebRequest -Method Get -Uri $Url -ApiKey $ApiKey -Thumbprint $Thumbprint -ErrorAction Stop
        Write-Output ($result | ConvertFrom-Json)
    }
    catch
    {

    }   
}
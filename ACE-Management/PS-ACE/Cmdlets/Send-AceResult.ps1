function Send-AceResult
{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes

    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject[]]
        $InputObject,
        
        [Parameter(Mandatory)]
        [string]
        $Uri
    )

    begin
    {
        $header = @{
            'X-API-Version' = '1.0'
        }
    }

    process
    {
        foreach($o in $InputObject)
        {
            $result = Invoke-WebRequest -Method Post -Uri "$($Uri)/ace/result/e989000d-2b98-44bd-94fc-403c41f42bf5" -Body (ConvertTo-Json $o) -Headers $header -ContentType application/json

            Write-Output ($result.Content | ConvertFrom-Json)
        }
    }

    end
    {

    }
}
function Start-AceScript
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ServerUri,

        [Parameter(Mandatory = $true)]
        [string]
        $ScriptUri,

        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]
        $SweepId,

        [Parameter(Mandatory = $true)]
        [string]
        $ScanId,

        [Parameter(Mandatory = $true)]
        [string]
        $RoutingKey
    )

    # Get the FQDN of the target computer and the Timestamp of the scan itself
    $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
    $ResultDate = (Get-Date).ToString("yyyyMMddThhmmssmsmsZ")

    # Create a list of strings to put scan results in
    $dataList = New-Object -TypeName System.Collections.Generic.List['string']

    # Download the script to execute from the server
    Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($ServerUri)$($ScriptUri)"

    foreach($o in (Invoke-Expression $scan.Function))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', $scan.ScanType)
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = $scan.ScanType
        RoutingKey   = $scan.RoutingKey
        ResultDate   = $ResultDate
        ScanId       = $ScanId
        Data         = $dataList.ToArray()
    }
    
    # Submit the results to the server
    Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($ServerUri)/ace/result/$($SweepId)" -Body (ConvertTo-JsonV2 -InputObject $props)
}

function ConvertTo-JsonV2 
{
    param
    (
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    Begin 
    {
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
        $Serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    }

    Process 
    {
        try 
        {
            $Serializer.Serialize($InputObject)
        } 
        catch 
        {
            # Write error message to ACE to let it know that the scan failed
            Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
        }    
    }
}

# Need to update to accept GET requests
function Invoke-AceWebRequest
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [string]
        $Body
    )

    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        $Thumbprint = $Thumbprint
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
    
        if ($certificate -eq $null)
        {
            $Host.UI.WriteErrorLine("Null certificate.")
            return $true
        }
    
        if ($certificate.Thumbprint -eq $Thumbprint)
        {
            return $true
        }
        else
        {
            $Host.UI.WriteErrorLine("Thumbprint mismatch. Certificate thumbprint $($certificate.Thumbprint)")
        }
    
        return $false
    }

    try
    {
        #Write-Host "URI: $($Uri)"

        # Create web request
        $WebRequest = [Net.WebRequest]::Create($uri)
        $WebRequest.Method = 'Post'
        $WebRequest.ContentType = 'application/json'
        $WebRequest.Headers.Add('X-API-Version:1.0')

        $byteArray = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $Webrequest.ContentLength = $byteArray.Length
        
        $dataStream = $Webrequest.GetRequestStream()            
        $dataStream.Write($byteArray, 0, $byteArray.Length)
        $dataStream.Close()

        # Get response stream
        $ResponseStream = $Webrequest.GetResponse().GetResponseStream()
    
        # Create a stream reader and read the stream returning the string value.
        $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
        $StreamReader.ReadToEnd()
    }
    catch
    {
        Write-Error "Failed: $($_.exception.innerexception.message)"
    }
}
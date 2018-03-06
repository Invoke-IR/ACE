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
    $ResultDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddThhmmssmsmsZ")

    # Create a list of strings to put scan results in
    $dataList = New-Object -TypeName System.Collections.Generic.List['string']

    $script = Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($ServerUri)$($ScriptUri)"

    # Download the script to execute from the server
    foreach($o in (Invoke-Expression $script))
    {
        if($o -ne $null)
        {
            $o.Add('ComputerName', $HostFQDN)
            $o.Add('SweepId', $SweepId)
            $o.Add('ScanId', $ScanId)
            $o.Add('ResultDate', $ResultDate)

            try
            {
                $message = $o | ConvertTo-JsonV2
                $dataList.Add($message)
            }
            catch
            {
                # We need to figure out what to do here
                # This is if ConvertTo-JsonV2 throws an error
                # Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
            }
        }
    }

    # Send 200 results at a time
    # This keeps us under the Kestrel request size limit of 30MB
    for($i = 0; $i -lt $dataList.Count; $i += 200)
    {
        $props = @{
            RoutingKey   = $RoutingKey
            ScanId       = $ScanId
            Data         = $dataList[$i..($i+199)]
        }

        # Submit the results to the server
        Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($ServerUri)/ace/result/$($SweepId)" -Body (ConvertTo-JsonV2 -InputObject $props) -Method Post
    }
}

function ConvertTo-JsonV2 
{
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable[]]
        $InputObject
    )

    Begin 
    {
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
        $Serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    }

    Process 
    {
        foreach($item in $InputObject)
        {
            $Serializer.Serialize($item)
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
        $Uri,

        [Parameter()]
        [string]
        $ApiKey,

        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint,

        [Parameter()]
        [ValidateSet('Delete','Get','Post','Put')]
        [string]
        $Method = 'Get',

        [Parameter()]
        [string]
        $ContentType = 'application/json',

        [Parameter()]
        [string]
        $Body
    )
    Try
    {
        # Create web request
        $WebRequest = [System.Net.WebRequest]::Create($Uri)
    
        $WebRequest.Headers.Add('X-API-Version:1.0')
        
        if($PSBoundParameters.ContainsKey('ApiKey'))
        {
            $webrequest.Headers.Add("X-ApiKey:$($ApiKey)")
        }

        $WebRequest.Method = $Method
        $WebRequest.ContentType = $ContentType

        # Set the callback to check for null certificate and thumbprint matching.
        $WebRequest.ServerCertificateValidationCallback = {
            
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            
            if ($certificate -eq $null)
            {
                $Host.UI.WriteWarningLine("Null certificate.")
                return $true
            }
    
            if ($certificate.Thumbprint -eq $Thumbprint)
            {
                return $true
            }
            else
            {
                $Host.UI.WriteWarningLine("Thumbprint mismatch. Certificate thumbprint $($certificate.Thumbprint)")
                $Host.UI.WriteWarningLine("   Expected thumbprint: $($Thumbprint)")
                $Host.UI.WriteWarningLine("   Received thumbprint: $($certificate.Thumbprint)")
            }
    
            return $false
        }

        if($PSBoundParameters.ContainsKey('Body'))
        {
            $byteArray = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $Webrequest.ContentLength = $byteArray.Length
            
            $dataStream = $Webrequest.GetRequestStream()            
            $dataStream.Write($byteArray, 0, $byteArray.Length)
            $dataStream.Close()
        }

        # Get response stream
        $ResponseStream = $webrequest.GetResponse().GetResponseStream()
    
        # Create a stream reader and read the stream returning the string value.
        $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
        $StreamReader.ReadToEnd()

        $StreamReader.Close()
        $ResponseStream.Close()
    }
    catch
    {
        Write-Error "Failed: $($_.exception.innerexception.message)"
    }
}
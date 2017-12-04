function Download-AceFile
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    try
    {
        $file = Get-Item -Path $Path -ErrorAction Stop
        
        $props = @{
            ComputerName = (Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"})
            Name = $file.Name
            FullPath = $file.FullName
            Content = ([System.IO.File]::ReadAllBytes($file.FullName))
        }

        Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/download/$($Id)" -Body (ConvertTo-JsonV2 -InputObject $props)
    }
    catch
    {
        # Send failure notification
        Write-Warning "Can't find file"
    }
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
            #Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
        }    
    }
}

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
function Start-AceScript
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [string]
        $SweepId,

        [Parameter(Mandatory = $true)]
        [string]
        $ScanId,

        [Parameter(Mandatory = $true)]
        [string]
        $RoutingKey,

        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint
    )

    $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
    $ResultDate = (Get-Date).ToString("yyyyMMddThhmmssmsmsZ")

    $dataList = New-Object -TypeName System.Collections.Generic.List['string']

    foreach($o in (Get-PSIPrefetch -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'Prefetch')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'Prefetch'
        RoutingKey   = $RoutingKey
        ResultDate   = $ResultDate
        ScanId       = $ScanId
        Data         = $dataList.ToArray()
    }

    $body = (ConvertTo-JsonV2 -InputObject $props)

    Write-Host $body

    #Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
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
            Write-Error $_
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
        Write-Host "URI: $($Uri)"

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

function Get-PSIPrefetch {
<#
    .SYNOPSIS

        Return prefetch file information.

        Author: Jared Atkinson, Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string]
        $Path,

        [switch]
        $ReturnHashtables
    )

    begin
    {
        if($PSBoundParameters.ContainsKey('Path'))
        {
            $props = @{FullName = $Path}
            $files = New-Object -TypeName psobject -Property $props
        }
        else
        {
            $files = Get-ChildItem -Path C:\Windows\Prefetch\* -Include *.pf
        }
    }

    process
    {
        foreach($file in $files)
        {
            $bytes = Get-Content -Path $file.FullName -Encoding Byte
        
            # Check for Prefetch file header 'SCCA'
            if([System.Text.Encoding]::ASCII.GetString($bytes[4..7]) -eq 'SCCA')
            {
                $Version = $bytes[0]
            
                switch($Version)
                {
                    0x11 # Windows XP
                    {
                        $AccessTimeBytes = $bytes[0x78..0x7F]
                        $RunCount = [BitConverter]::ToInt32($bytes, 0x90)
                    }
                    0x17 # Windows 7
                    {
                        $AccessTimeBytes = $bytes[0x80..0x87]
                        $RunCount = [BitConverter]::ToInt32($bytes, 0x98);
                    }
                    0x1A # Windows 8
                    {
                        $AccessTimeBytes = $bytes[0x80..0xBF]
                        $RunCount = [BitConverter]::ToInt32($bytes, 0xD0);
                    }
                }
            
                $Name = [Text.Encoding]::Unicode.GetString($bytes, 0x10, 0x3C).Split('\0')[0].TrimEnd("`0")
                $PathHash = [BitConverter]::ToString($bytes[0x4f..0x4c]).Replace("-","")
                $DeviceCount = [BitConverter]::ToInt32($bytes, 0x70)
                $DependencyString = [Text.Encoding]::Unicode.GetString($bytes, [BitConverter]::ToInt32($bytes, 0x64), [BitConverter]::ToInt32($bytes, 0x68)).Replace("`0",';').TrimEnd(';')
                $Dependencies = $DependencyString.Split(';')
                $Path = $Dependencies | Where-Object {$_ -like "*$($Name)"}
                $DependencyCount = $Dependencies.Length

                for($i = 0; $i -lt $AccessTimeBytes.Length; $i += 8)
                {
                    $Props = @{
                        Name = $Name
                        Path = $Path
                        PathHash = $PathHash
                        DependencyCount = $DependencyCount
                        PrefetchAccessTime = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($AccessTimeBytes, $i))
                        DeviceCount = $DeviceCount
                        RunCount = $RunCount
                        DependencyFiles = $DependencyString
                    }

                    if($ReturnHashtables) {
                        $Props
                    } else {
                        New-Object -TypeName psobject -Property $Props
                    }
                }
            }
        }
    }

    end
    {

    }
}
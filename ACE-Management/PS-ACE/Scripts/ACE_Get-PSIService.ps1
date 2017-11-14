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

    foreach($o in (Get-PSIService -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'Service')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'Service'
        RoutingKey   = $RoutingKey
        ResultDate   = $ResultDate
        ScanId       = $ScanId
        Data         = $dataList.ToArray()
    }

    $body = (ConvertTo-JsonV2 -InputObject $props)

    Write-Host $body

    Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
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

function Get-PSIService 
{
<#
    .SYNOPSIS

        Returns detailed service information.

        Author: Jared Atkinson
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    Begin
    {
        function Get-PathFromCommandLine
        {
            Param
            (
                [Parameter(Mandatory = $true)]
                [string]
                $CommandLine
            )

            if(Test-Path -Path $CommandLine -ErrorAction SilentlyContinue)
            {
                $CommandLine
            }
            else
            {
                switch -Regex ($CommandLine)
                {
                    '"\s'{ $CommandLine.Split('"')[1]; break}
                    '\s-'{ $CommandLine.Split(' ')[0]; break}
                    '\s/'{ $CommandLine.Split(' ')[0]; break}
                    '"'{ $CommandLine.Split('"')[1]; break}
                    default{ $CommandLine}    
                }
            }
        }

        # Thanks to https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
        function Get-DIGSFileHash
        {
            [CmdletBinding(DefaultParameterSetName = "Path")]
            param(
                [Parameter(Mandatory=$true, ParameterSetName="Path", Position = 0)]
                [System.String[]]
                $Path,

                [Parameter(Mandatory=$true, ParameterSetName="LiteralPath", ValueFromPipelineByPropertyName = $true)]
                [Alias("PSPath")]
                [System.String[]]
                $LiteralPath,
        
                [Parameter(Mandatory=$true, ParameterSetName="Stream")]
                [System.IO.Stream]
                $InputStream,

                [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160")]
                [System.String]
                $Algorithm="SHA256"
            )
    
            begin
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
            }
    
            process
            {
                if($PSCmdlet.ParameterSetName -eq "Stream")
                {
                    Get-DIGSStreamHash -InputStream $InputStream -RelatedPath $null -Hasher $hasher
                }
                else
                {
                    $pathsToProcess = @()
                    if($PSCmdlet.ParameterSetName  -eq "LiteralPath")
                    {
                        $pathsToProcess += Resolve-Path -LiteralPath $LiteralPath | Foreach-Object { $_.ProviderPath }
                    }
                    if($PSCmdlet.ParameterSetName -eq "Path")
                    {
                        $pathsToProcess += Resolve-Path $Path | Foreach-Object { $_.ProviderPath }
                    }

                    foreach($filePath in $pathsToProcess)
                    {
                        if(Test-Path -LiteralPath $filePath -PathType Container)
                        {
                            continue
                        }

                        try
                        {
                            # Read the file specified in $FilePath as a Byte array
                            [system.io.stream]$stream = [system.io.file]::OpenRead($filePath)
                            Get-DIGSStreamHash -InputStream $stream  -RelatedPath $filePath -Hasher $hasher
                        }
                        catch [Exception]
                        {
                            $errorMessage = 'FileReadError {0}:{1}' -f $FilePath, $_
                            Write-Error -Message $errorMessage -Category ReadError -ErrorId "FileReadError" -TargetObject $FilePath
                            return
                        }
                        finally
                        {
                            if($stream)
                            {
                                $stream.Close()
                            }
                        }                            
                    }
                }
            }
        }

        function Get-DIGSStreamHash
        {
            param(
                [System.IO.Stream]
                $InputStream,

                [System.String]
                $RelatedPath,

                [System.Security.Cryptography.HashAlgorithm]
                $Hasher)

            # Compute file-hash using the crypto object
            [Byte[]] $computedHash = $Hasher.ComputeHash($InputStream)
            [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

            if ($RelatedPath -eq $null)
            {
                $retVal = [PSCustomObject] @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }
                $retVal.psobject.TypeNames.Insert(0, "Microsoft.Powershell.Utility.FileHash")
                $retVal
            }
            else
            {
                $retVal = [PSCustomObject] @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                    Path = $RelatedPath
                }
                $retVal.psobject.TypeNames.Insert(0, "Microsoft.Powershell.Utility.FileHash")
                $retVal

            }
        }
    
        $hashcache = @{}
        $objList = New-Object -TypeName "System.Collections.Generic.List[Object]"
    }

    Process
    {
        foreach($service in (Get-WmiObject win32_service))
        {
            if($service.PathName -ne $null)
            {
                $path = Get-PathFromCommandLine -CommandLine $service.PathName
            }
            else
            {
                $path = $null
            }

            try
            {
                if($hashcache.ContainsKey($path))
                {
                    $md5 = $hashcache[$path].MD5
                    $sha256 = $hashcache[$path].SHA256
                }
                else
                {
                    $md5 = Get-DIGSFileHash -Path $path -Algorithm MD5 -ErrorAction Stop
                    $sha256 = Get-DIGSFileHash -Path $path -Algorithm SHA256 -ErrorAction Stop
                    $obj = @{
                        MD5 = $md5
                        SHA256 = $sha256
                    }
                    $hashcache.Add($path, $obj)
                }
            }
            catch
            {
                $md5 = $null
                $sha256 = $null
            }
        
            $Props = @{
                Name = $service.Name
                CommandLine = $service.PathName
                ExecutablePath = $path
                ServiceType = $service.ServiceType
                StartMode = $service.StartMode
                Caption = $service.Caption
                Description = $service.Description
                DisplayName = $service.DisplayName
                ProcessId = $service.ProcessId
                Started = $service.Started
                User = $service.StartName
                MD5Hash = $md5.Hash
                SHA256Hash = $sha256.Hash
            }

            if($ReturnHashtables) {
                $Props
            } else {
                New-Object -TypeName psobject -Property $Props
            }
        }
    }

    End
    {

    }
}

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
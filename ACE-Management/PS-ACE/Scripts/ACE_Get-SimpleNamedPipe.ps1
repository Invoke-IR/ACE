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

    foreach($o in (Get-SimpleNamedPipe -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'SimpleNamedPipe')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'SimpleNamedPipe'
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

function Get-SimpleNamedPipe { 
<#
    .SYNOPSIS

        Gets a list of open named pipes.

        Author: Greg Zakharov
        License: 
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.
#>
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    Begin 
    {
        $Mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? { 
            $_.ManifestModule.ScopeName.Equals('CommonLanguageRuntimeLibrary') 
        } 
     
        $SafeFindHandle = $Mscorlib.GetType('Microsoft.Win32.SafeHandles.SafeFindHandle') 
        $Win32Native = $Mscorlib.GetType('Microsoft.Win32.Win32Native') 
     
        $WIN32_FIND_DATA = $Win32Native.GetNestedType( 
            'WIN32_FIND_DATA', [Reflection.BindingFlags]32 
        ) 
        $FindFirstFile = $Win32Native.GetMethod( 
            'FindFirstFile', [Reflection.BindingFlags]40, 
            $null, @([String], $WIN32_FIND_DATA), $null 
        ) 
        $FindNextFile = $Win32Native.GetMethod('FindNextFile', [Reflection.BindingFlags]40, $null, @($SafeFindHandle, $WIN32_FIND_DATA), $null) 
     
        $Obj = $WIN32_FIND_DATA.GetConstructors()[0].Invoke($null)
        function Read-Field([String]$Field) { 
            return $WIN32_FIND_DATA.GetField($Field, [Reflection.BindingFlags]36).GetValue($Obj)
        } 
    } 

    Process 
    { 
        $Handle = $FindFirstFile.Invoke($null, @('\\.\pipe\*', $obj))

        
        $Output = @{
            Name = [string](Read-Field cFileName)
            Instances = [UInt32](Read-Field nFileSizeLow)
        }

        do {
            $Output = @{
                Name = [string](Read-Field cFileName)
                Instances = [UInt32](Read-Field nFileSizeLow)
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output
            }
        } while($FindNextFile.Invoke($null, @($Handle, $obj)))
     
        $Handle.Close() 
    } 

    End 
    {
    
    } 
}

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
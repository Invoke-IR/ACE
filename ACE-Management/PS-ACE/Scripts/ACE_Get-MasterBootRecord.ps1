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

    foreach($o in (Get-MasterBootRecord  -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'MasterBootRecord')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'MasterBootRecord'
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

function Get-MasterBootRecord {
<#
    .SYNOPSIS

        Returns detailed information about the master boot record

        Author: Jared Atkinson
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [String[]]
        $Path,

        [switch]
        $ReturnHashtables
    )
    
    begin
    {
        function Get-FileHandle
        {
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $true)]
                [string]
                $Path
            )
            
            #region Constants
        
            $GENERIC_READWRITE = 0x80000000
            $FILE_SHARE_READWRITE = 0x02 -bor 0x01
            $OPEN_EXISTING = 0x03
        
            #endregion

            #region Reflection
            $DynAssembly = New-Object System.Reflection.AssemblyName('Win32')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32', $False)

            $TypeBuilder = $ModuleBuilder.DefineType('Win32.Kernel32', 'Public, Class')
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
                @('kernel32.dll'),
                [Reflection.FieldInfo[]]@($SetLastError),
                @($True))

            # Define [Win32.Kernel32]::CreateFile
            $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CreateFile',
                'kernel32.dll',
                ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                [Reflection.CallingConventions]::Standard,
                [Microsoft.Win32.SafeHandles.SafeFileHandle],
                [Type[]]@([String], [Int32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Ansi)
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

            $Kernel32 = $TypeBuilder.CreateType()
            #endregion

            # Get handle to $FileToServe
            $DriveHandle = $Kernel32::CreateFile($Path, $GENERIC_READWRITE, $FILE_SHARE_READWRITE, 0, $OPEN_EXISTING, 0, 0)

            # Check that handle is valid
            if ($DriveHandle.IsInvalid) {
                Write-Error "Invalid handle to $($Path) returned from CreateFile" -ErrorAction Stop
            }
            else {
                $DriveHandle
            }
        }
               
        function Read-MbrBytes
        {
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $true)]
                [Microsoft.Win32.SafeHandles.SafeFileHandle]
                $Handle
            )

            try
            {
                # Create a FileStream to read from the handle
                $streamToRead = New-Object -TypeName System.IO.FileStream($Handle, [System.IO.FileAccess]::Read)
            
                # Set our position in the stream to $Offset
                $streamToRead.Position = 0x0
        
                # Create a buffer $Length bytes long
                $buffer = New-Object -TypeName Byte[](0x200)

                # Read $Length bytes
                $return = $streamToRead.Read($buffer, 0x0, 0x200)
            
                # Check return value
                if($return -ne 0x200)
                {
                    $return
                }

                $buffer
            }
            catch
            {
                Write-Error "Unable to read bytes from Drive" -ErrorAction Stop
            }
            finally
            {
                $streamToRead.Dispose()
            }
        }
        
        function Get-MD5Hash
        {
            param
            (
                [Parameter(Mandatory = $true)]
                [byte[]]
                $Bytes
            )
            
            begin
            {
                $sha1 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                $hashbytes = $sha1.ComputeHash($Bytes)
                $sb = New-Object -TypeName System.Text.StringBuilder
            }

            process
            {
                foreach($b in $hashbytes)
                {
                    $null = $sb.Append("{0:x}" -f $b)
                }

                $sb.ToString()
            }

            end
            {
                if($sha1.Dispose) {
                    $sha1.Dispose()
                }
            }
        }

        function Get-Partition
        {
            param
            (
                [Parameter(Mandatory = $true)]
                [byte[]]
                $Bytes,

                [Parameter(Mandatory = $true)]
                [int]
                $Offset,

                [switch]
                $ReturnHashtables
            )

            # Status (0x00 - Non-Bootable & 0x80 - Bootable)
            if($Bytes[0x00 + $Offset] -eq 0x80)
            {
                $Bootable = $true
            }
            else
            {
                $Bootable = $false
            }

            $props = @{
                Bootable = $Bootable
                PartitionType = $Bytes[0x04 + $Offset]
                RelativeStartSector = [System.BitConverter]::ToUInt32($Bytes, 0x08 + $Offset)
                TotalSectors = [System.BitConverter]::ToUInt32($Bytes, 0x0C + $Offset)
            }

            if($ReturnHashtables) {
                $props
            } else {
                New-Object -TypeName psobject -Property $props
            }
        }
    }

    process
    {
        if(-not($PSBoundParameters.ContainsKey('Path')))
        {
            $Disks = Get-WmiObject -Query "SELECT * FROM Win32_DiskDrive"
        }
        else
        {

        }

        $OS = (Get-WmiObject win32_Operatingsystem).Caption

        foreach($disk in $Disks)
        {
            $hDrive = Get-FileHandle -Path $disk.DeviceId

            if($hDrive) {
                $bytes = Read-MbrBytes -Handle $hDrive

                $CodeSection = $bytes[0x3E..0x1B7]

                $listPartitions = New-Object -TypeName System.Collections.Generic.List[HashTable]

                for($i = 0; $i -lt 4; $i++)
                {
                    if($ReturnHashtables) {
                        $partition = Get-Partition -Bytes $bytes -Offset (0x1BE + (0x10 * $i)) -ReturnHashtables
                    } else {
                        $partition = Get-Partition -Bytes $bytes -Offset (0x1BE + (0x10 * $i))
                    }

                    if($partition.TotalSectors -ne 0)
                    {
                        $listPartitions.Add($partition)
                    }
                }

                $Props = @{
                    OperatingSystem = $OS
                    DeviceId = $disk.DeviceId
                    Model = $disk.Model
                    Signature = Get-MD5Hash -Bytes $CodeSection
                    CodeSection = $CodeSection
                    DiskSignature = [System.BitConverter]::ToString($bytes[0x1B8..0x1BB]).Replace("-", "")
                    PartitionTable = $listPartitions.ToArray()
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

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
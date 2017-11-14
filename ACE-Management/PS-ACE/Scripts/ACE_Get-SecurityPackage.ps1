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

    foreach($o in (Get-SecurityPackage -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'SecruityPackage')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)
        
        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }
    
    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'SecurityPackage'
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

function Get-SecurityPackage
{
    param
    (
        [Parameter()]
        [switch]
        $ReturnHashtables
    )
    <#
    .SYNOPSIS

    Enumerates Security Service Providers (SSP) t

    .DESCRIPTION   

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE

    PS > Get-SecurityPackage

    Name         : Negotiate
    Comment      : Microsoft Package Negotiator
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, GSS_COMPATIBLE, LOGON, 
                   RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 9
    MaxToken     : 65791

    Name         : NegoExtender
    Comment      : NegoExtender Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, NEGOTIABLE, GSS_COMPATIBLE, 
                   LOGON, MUTUAL_AUTH, NEGO_EXTENDER, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 30
    MaxToken     : 12000

    Name         : Kerberos
    Comment      : Microsoft Kerberos V1.0
    Capabilities : INTEGRITY, PRIVACY, TOKEN_ONLY, DATAGRAM, CONNECTION, MULTI_REQUIRED, 
                   EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, 
                   GSS_COMPATIBLE, LOGON, MUTUAL_AUTH, DELEGATION, READONLY_WITH_CHECKSUM, 
                   RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 16
    MaxToken     : 65535

    Name         : NTLM
    Comment      : NTLM Security Package
    Capabilities : INTEGRITY, PRIVACY, TOKEN_ONLY, CONNECTION, MULTI_REQUIRED, IMPERSONATION, 
                   ACCEPT_WIN32_NAME, NEGOTIABLE, LOGON, RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 10
    MaxToken     : 2888

    Name         : TSSSP
    Comment      : TS Service Security Package
    Capabilities : CONNECTION, MULTI_REQUIRED, ACCEPT_WIN32_NAME, MUTUAL_AUTH, 
                   APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 22
    MaxToken     : 13000

    Name         : pku2u
    Comment      : PKU2U Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, GSS_COMPATIBLE, MUTUAL_AUTH, 
                   NEGOTIABLE2, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 31
    MaxToken     : 12000

    Name         : CloudAP
    Comment      : Cloud AP Security Package
    Capabilities : LOGON, NEGOTIABLE2
    Version      : 1
    RpcId        : 36
    MaxToken     : 0

    Name         : WDigest
    Comment      : Digest Authentication for Windows
    Capabilities : TOKEN_ONLY, IMPERSONATION, ACCEPT_WIN32_NAME, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 21
    MaxToken     : 4096

    Name         : Schannel
    Comment      : Schannel Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, 
                   APPCONTAINER_PASSTHROUGH
    Version      : 1
    RpcId        : 14
    MaxToken     : 24576

    Name         : Microsoft Unified Security Protocol Provider
    Comment      : Schannel Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, 
                   APPCONTAINER_PASSTHROUGH
    Version      : 1
    RpcId        : 14
    MaxToken     : 24576

    Name         : CREDSSP
    Comment      : Microsoft CredSSP Security Provider
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, IMPERSONATION, 
                   ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 65535
    MaxToken     : 90567
    #>

    $obj = EnumerateSecurityPackages

    if($ReturnHashtables)
    {
        foreach($o in $obj)
        {
            $props = @{
                Name = $o.Name
                Comment = $o.Comment
                Capabilities = $o.Capabilities
                Version = $o.Version
                RpcId = $o.RpcId
                MaxToken = $o.MaxToken
            }

            Write-Output $props
        }
    }
    else
    {
        Write-Output $obj
    }
}

#region PSReflect

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

$Module = New-InMemoryModule -ModuleName GetSecurityPackage

#region Enums
$SECPKG_FLAG = psenum $Module SECPKG_FLAG UInt32 @{
    INTEGRITY                = 0x1
    PRIVACY                  = 0x2
    TOKEN_ONLY               = 0x4
    DATAGRAM                 = 0x8
    CONNECTION               = 0x10
    MULTI_REQUIRED           = 0x20
    CLIENT_ONLY              = 0x40
    EXTENDED_ERROR           = 0x80
    IMPERSONATION            = 0x100
    ACCEPT_WIN32_NAME        = 0x200
    STREAM                   = 0x400
    NEGOTIABLE               = 0X800
    GSS_COMPATIBLE           = 0x1000
    LOGON                    = 0x2000
    ASCII_BUFFERS            = 0x4000
    FRAGMENT                 = 0x8000
    MUTUAL_AUTH              = 0x10000
    DELEGATION               = 0x20000
    READONLY_WITH_CHECKSUM   = 0x40000
    RESTRICTED_TOKENS        = 0x80000
    NEGO_EXTENDER            = 0x00100000
    NEGOTIABLE2              = 0x00200000
    APPCONTAINER_PASSTHROUGH = 0x00400000
    APPCONTAINER_CHECKS      = 0x00800000

    #SECPKG_CALLFLAGS_APPCONTAINER = 0x00000001
    #SECPKG_CALLFLAGS_AUTHCAPABLE = 0x00000002
    #SECPKG_CALLFLAGS_FORCE_SUPPLIED = 0x00000004
} -Bitfield
#endregion Enums

#region Structs
$SecPkgInfo = struct $Module SecPkgInfo @{
    Capabilities = field 0 $SECPKG_FLAG
    Version = field 1 UInt16
    RPCID = field 2 UInt16
    MaxToken = field 3 UInt32
    Name = field 4 IntPtr
    Comment = field 5 IntPtr
}
#endregion Structs

#region Function Definitions
$FunctionDefinitions = @(
    (func secur32 DeleteSecurityPackage ([UInt32]) @(
        [string] #_In_ LPTSTR pszPackageName
    ) -EntryPoint DeleteSecurityPackage),

    (func secur32 EnumerateSecurityPackages ([UInt32]) @(
        [UInt32].MakeByRefType(), #_In_ PULONG      pcPackages
        [IntPtr].MakeByRefType()  #_In_ PSecPkgInfo *ppPackageInfo
    ) -EntryPoint EnumerateSecurityPackages),

    (func secur32 FreeContextBuffer ([UInt32]) @(
          [IntPtr] #_In_ PVOID pvContextBuffer
    ) -EntryPoint FreeContextBuffer)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace GetSecurityPackage
$Secur32 = $Types['secur32']
#endregion Function Definitions

function DeleteSecurityPackage
{
    <#
    .SYNOPSIS

    Deletes a security support provider from the list of providers supported by Microsoft Negotiate.

    .PARAMETER PackageName

    The name of the security provider to delete.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    (func secur32 DeleteSecurityPackage ([UInt32]) @(
        [string] #_In_ LPTSTR pszPackageName
    ) -EntryPoint DeleteSecurityPackage)

    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/dd401610(v=vs.85).aspx
    
    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $PackageName
    )

    $SUCCESS = $Secur32::DeleteSecurityPackages($PackageName)

    if($SUCCESS -eq 0)
    {
        throw "DeleteSecurityPackage Error: $($SUCCESS)"
    }
}

function EnumerateSecurityPackages
{
    <#
    .SYNOPSIS

    The EnumerateSecurityPackages function returns an array of SecPkgInfo structures that provide information about the security packages available to the client.

    .DESCRIPTION

    The caller can use the Name member of a SecPkgInfo structure to specify a security package in a call to the AcquireCredentialsHandle (General) function.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: FreeContextBuffer (function), SecPkgInfo (Structure), SECPKG_FLAG (Enumeration)
    Optional Dependencies: None

    (func secur32 EnumerateSecurityPackages ([UInt32]) @(
        [UInt32].MakeByRefType(), #_In_ PULONG      pcPackages
        [IntPtr].MakeByRefType()  #_In_ PSecPkgInfo *ppPackageInfo
    ) -EntryPoint EnumerateSecurityPackages)

    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa375397(v=vs.85).aspx

    .EXAMPLE

    PS > EnumerateSecurityPackages

    Name         : Negotiate
    Comment      : Microsoft Package Negotiator
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, GSS_COMPATIBLE, LOGON, 
                   RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 9
    MaxToken     : 65791

    Name         : NegoExtender
    Comment      : NegoExtender Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, NEGOTIABLE, GSS_COMPATIBLE, 
                   LOGON, MUTUAL_AUTH, NEGO_EXTENDER, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 30
    MaxToken     : 12000

    Name         : Kerberos
    Comment      : Microsoft Kerberos V1.0
    Capabilities : INTEGRITY, PRIVACY, TOKEN_ONLY, DATAGRAM, CONNECTION, MULTI_REQUIRED, 
                   EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, 
                   GSS_COMPATIBLE, LOGON, MUTUAL_AUTH, DELEGATION, READONLY_WITH_CHECKSUM, 
                   RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 16
    MaxToken     : 65535

    Name         : NTLM
    Comment      : NTLM Security Package
    Capabilities : INTEGRITY, PRIVACY, TOKEN_ONLY, CONNECTION, MULTI_REQUIRED, IMPERSONATION, 
                   ACCEPT_WIN32_NAME, NEGOTIABLE, LOGON, RESTRICTED_TOKENS, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 10
    MaxToken     : 2888

    Name         : TSSSP
    Comment      : TS Service Security Package
    Capabilities : CONNECTION, MULTI_REQUIRED, ACCEPT_WIN32_NAME, MUTUAL_AUTH, 
                   APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 22
    MaxToken     : 13000

    Name         : pku2u
    Comment      : PKU2U Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, GSS_COMPATIBLE, MUTUAL_AUTH, 
                   NEGOTIABLE2, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 31
    MaxToken     : 12000

    Name         : CloudAP
    Comment      : Cloud AP Security Package
    Capabilities : LOGON, NEGOTIABLE2
    Version      : 1
    RpcId        : 36
    MaxToken     : 0

    Name         : WDigest
    Comment      : Digest Authentication for Windows
    Capabilities : TOKEN_ONLY, IMPERSONATION, ACCEPT_WIN32_NAME, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 21
    MaxToken     : 4096

    Name         : Schannel
    Comment      : Schannel Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, 
                   APPCONTAINER_PASSTHROUGH
    Version      : 1
    RpcId        : 14
    MaxToken     : 24576

    Name         : Microsoft Unified Security Protocol Provider
    Comment      : Schannel Security Package
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, 
                   IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, 
                   APPCONTAINER_PASSTHROUGH
    Version      : 1
    RpcId        : 14
    MaxToken     : 24576

    Name         : CREDSSP
    Comment      : Microsoft CredSSP Security Provider
    Capabilities : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, IMPERSONATION, 
                   ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_CHECKS
    Version      : 1
    RpcId        : 65535
    MaxToken     : 90567
    #>

    $PackageCount = 0
    $PackageInfo = [IntPtr]::Zero

    $SUCCESS = $Secur32::EnumerateSecurityPackages([ref]$PackageCount, [ref]$PackageInfo)

    if($SUCCESS -ne 0)
    {
        throw "EnumerateSecurityPackages Error: $($SUCCESS)"
    }

    for($i = 0; $i -lt $PackageCount; $i++)
    {
        $PackagePtr = [IntPtr]($PackageInfo.ToInt64() + ($SecPkgInfo::GetSize() * $i))

        $Package = $PackagePtr -as $SecPkgInfo
        
        $obj = New-Object -TypeName psobject
        $obj | Add-Member -MemberType NoteProperty -Name Name -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Package.Name))
        $obj | Add-Member -MemberType NoteProperty -Name Comment -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Package.Comment))
        $obj | Add-Member -MemberType NoteProperty -Name Capabilities -Value $Package.Capabilities
        $obj | Add-Member -MemberType NoteProperty -Name Version -Value $Package.Version
        $obj | Add-Member -MemberType NoteProperty -Name RpcId -Value $Package.RPCID
        $obj | Add-Member -MemberType NoteProperty -Name MaxToken -Value $Package.MaxToken

        Write-Output $obj
    }

    FreeContextBuffer -Buffer $PackageInfo
}

function FreeContextBuffer
{
    <#
    .SYNOPSIS

    The FreeContextBuffer function enables callers of security package functions to free memory buffers allocated by the security package.

    .DESCRIPTION

    Memory buffers are typically allocated by the InitializeSecurityContext (General) and AcceptSecurityContext (General) functions.
    
    The FreeContextBuffer function can free any memory allocated by a security package.

    .PARAMETER Buffer

    A pointer to memory to be freed.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    (func secur32 FreeContextBuffer ([UInt32]) @(
          [IntPtr] #_In_ PVOID pvContextBuffer
    ) -EntryPoint FreeContextBuffer)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa375416(v=vs.85).aspx

    .EXAMPLE

    PS > $PackageCount = 0
    PS > $PackageInfo = [IntPtr]::Zero

    PS > $SUCCESS = $Secur32::EnumerateSecurityPackages([ref]$PackageCount, [ref]$PackageInfo)

    #
    # Do Stuff ...
    #

    PS > FreeContextBuffer -Buffer $PackageInfo
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Buffer
    )

    $SUCCESS = $Secur32::FreeContextBuffer($Buffer)

    if($SUCCESS -ne 0)
    {
        throw "FreeContextBuffer Error: $($SUCCESS)"
    }
}

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
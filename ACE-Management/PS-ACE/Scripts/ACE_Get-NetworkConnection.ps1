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

    foreach($o in (Get-NetworkConnection -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'NetworkConnection')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'NetworkConnection'
        RoutingKey   = $RoutingKey
        ResultDate   = $ResultDate
        ScanId       = $ScanId
        Data         = $dataList.ToArray()
    }

    $body = (ConvertTo-JsonV2 -InputObject $props)

    Write-Output $body

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

function Get-NetworkConnection {
    <#
    .SYNOPSIS

    Returns current TCP and UDP connections.

    .NOTES

    Author: Lee Christensen (@tifkin_)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    [CmdletBinding()]
    param 
    (
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashtables
    )

    $Tcp4Connections = Get-Tcp4Connections @PSBoundParameters
    $Tcp6Connections = Get-Tcp6Connections @PSBoundParameters
    $Udp4Connections = Get-Udp4Connections @PSBoundParameters
    $Udp6Connections = Get-Udp6Connections @PSBoundParameters

    $Tcp4Connections
    $Tcp6Connections
    $Udp4Connections
    $Udp6Connections
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

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
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

#region Windows API Definitions
$Mod = New-InMemoryModule -ModuleName NetworkConnection

#region Enums
$TCP_TABLE_CLASS = psenum $Mod TCP_TABLE_CLASS UInt16 @{
    TCP_TABLE_BASIC_LISTENER = 0
    TCP_TABLE_BASIC_CONNECTIONS = 1
    TCP_TABLE_BASIC_ALL = 2
    TCP_TABLE_OWNER_PID_LISTENER = 3
    TCP_TABLE_OWNER_PID_CONNECTIONS = 4
    TCP_TABLE_OWNER_PID_ALL = 5
    TCP_TABLE_OWNER_MODULE_LISTENER = 6
    TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
    TCP_TABLE_OWNER_MODULE_ALL = 8
}

$TCP_STATE = psenum $Mod TCP_STATE UInt16 @{
    CLOSED = 1
    LISTENING = 2
    SYN_SENT = 3
    SYN_RECEIVED = 4
    ESTABLISHED = 5
    FIN_WAIT1 = 6
    FIN_WAIT2 = 7
    CLOSE_WAIT = 8
    CLOSING = 9
    LAST_ACK = 10
    TIME_WAIT = 11
    DELETE_TCB = 12
}

$UDP_TABLE_CLASS = psenum $Mod UDP_TABLE_CLASS UInt16 @{
    UDP_TABLE_BASIC = 0
    UDP_TABLE_OWNER_PID = 1
    UDP_TABLE_OWNER_MODULE = 2
}

$TAG_INFO_LEVEL = psenum $Mod TAG_INFO_LEVEL UInt16 @{
    eTagInfoLevelNameFromTag = 1
    eTagInfoLevelNamesReferencingModule = 2
    eTagInfoLevelNameTagMapping = 3
    eTagInfoLevelMax = 4
}

$SC_SERVICE_TAG_QUERY_TYPE = psenum $Mod SC_SERVICE_TAG_QUERY_TYPE UInt16 @{
    ServiceNameFromTagInformation = 1
    ServiceNamesReferencingModuleInformation = 2
    ServiceNameTagMappingInformation = 3
}
#endregion Enums

#region Structs

$MIB_UDPROW_OWNER_MODULE = struct $Mod MIB_UDPROW_OWNER_MODULE @{
    LocalAddr        = field 0 UInt32 0
    LocalPort        = field 1 UInt32 4
    OwningPid        = field 2 UInt32 8
    CreateTimestamp  = field 3 UInt64 16
    SpecificPortBind = field 4 UInt32 24  # Union
    Flags            = field 5 UInt32 24
    OwningModuleInfo = field 6 UInt64[] -MarshalAs @('ByValArray', 16) 32
} -ExplicitLayout

$MIB_UDP6ROW_OWNER_MODULE = struct $Mod MIB_UDP6ROW_OWNER_MODULE @{
    LocalAddr        = field 0 Byte[] -MarshalAs @('ByValArray', 16) 0
    LocalScopeId   = field 1 UInt32 16
    LocalPort      = field 2 UInt32 20
    OwningPid      = field 3 UInt32 24
    CreateTimestamp  = field 4 UInt64 32
    SpecificPortBind = field 5 UInt32 40  # Union
    Flags            = field 6 UInt32 40
    OwningModuleInfo = field 7 UInt64[] -MarshalAs @('ByValArray', 16) 48
} -ExplicitLayout


$MIB_UDPTABLE_OWNER_MODULE = struct $Mod MIB_UDPTABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_UDPROW_OWNER_MODULE
}

$MIB_UDP6TABLE_OWNER_MODULE = struct $Mod MIB_UDP6TABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_UDPROW_OWNER_MODULE
}

$MIB_TCPROW_OWNER_MODULE = struct $Mod MIB_TCPROW_OWNER_MODULE @{
    State           = field 0 $TCP_STATE
    LocalAddr       = field 1 UInt32
    LocalPort       = field 2 UInt32
    RemoteAddr      = field 3 UInt32
    RemotePort      = field 4 UInt32
    OwningPid       = field 5 UInt32
    CreateTimestamp = field 6 UInt64
    OwningModuleInfo = field 7 UInt64[] -MarshalAs @('ByValArray', 16)
}

$MIB_TCP6ROW_OWNER_MODULE = struct $Mod MIB_TCP6ROW_OWNER_MODULE @{
    LocalAddr        = field 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId     = field 1 UInt32
    LocalPort        = field 2 UInt32
    RemoteAddr       = field 3 Byte[] -MarshalAs @('ByValArray', 16)
    RemoteScopeId    = field 4 UInt32
    RemotePort       = field 5 UInt32
    State            = field 6 $TCP_STATE
    OwningPid        = field 7 UInt32
    CreateTimestamp  = field 8 UInt64
    OwningModuleInfo = field 9 UInt64[] -MarshalAs @('ByValArray', 16)
}

$MIB_TCPTABLE_OWNER_MODULE = struct $Mod MIB_TCPTABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_TCPROW_OWNER_MODULE
}

$MIB_TCP6TABLE_OWNER_MODULE = struct $Mod MIB_TCP6TABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_TCP6ROW_OWNER_MODULE
}

$SC_SERVICE_TAG_QUERY = struct $Mod SC_SERVICE_TAG_QUERY @{
    ProcessId = field 0 UInt32
    ServiceTag = field 1 UInt32
    Unknown = field 2 UInt32
    Buffer = field 3 IntPtr
}

#endregion Structs

#region FunctionDefinitions
$FunctionDefinitions = @(
    (func iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]))
    (func iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]))
    (func advapi32 I_QueryTagInformation ([UInt32]) @([IntPtr], $SC_SERVICE_TAG_QUERY_TYPE, $SC_SERVICE_TAG_QUERY.MakeByRefType()))
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'NetworkConnection'
$IPHelperAPI = $Types['iphlpapi']
$Advapi32 = $Types['advapi32']

#endregion FunctionDefinitions

#region Helper Functions

function Get-ServiceNameFromTag($ProcessId, $ServiceTag)
{
    $NTVersion = [System.Environment]::OSVersion.Version

    if($NTVersion.Major -ge 6 -and $NTVersion.Minor -ge 1)
    {
        # Based off of https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
        $ServiceTagQuery = [Activator]::CreateInstance($SC_SERVICE_TAG_QUERY)   # New-Object doesn't work on PSv2 for some reason.  Thanks @mattifestation! 
        $ServiceTagQuery.ProcessId = $ProcessId
        $ServiceTagQuery.ServiceTag = $ServiceTag
    
        $Res = $Advapi32::I_QueryTagInformation([IntPtr]::Zero, $SC_SERVICE_TAG_QUERY_TYPE::ServiceNameFromTagInformation, [Ref] $ServiceTagQuery)
        
        if($Res -eq 0)
        {
            $ServiceStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ServiceTagQuery.Buffer)
            $ServiceStr
        }
        else {
            #"Error: $Res"
        }
    }
}

function Get-Tcp4Connections
{
    Param
    (
        # Attempt to resolve the hostnames of each IP address
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashTables
    )

    $AF_INET = 2
    $TableBufferSize = 0
    $null = $IPHelperAPI::GetExtendedTcpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)
    
    try
    {
        $Ret = $IPHelperAPI::GetExtendedTcpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0);
        if ($Ret -ne 0)
        {
            Write-Error "Failed to get TCP connection information. GetExtendedTcpTable's return code: $Ret"
            return
        }
        
        $OwnerModuleTable  = $TableBuffer -as $MIB_TCPTABLE_OWNER_MODULE
        $RowPtr = [IntPtr]($TableBuffer.ToInt64() + [Runtime.InteropServices.Marshal]::OffsetOf($MIB_TCPTABLE_OWNER_MODULE, "Table").ToInt64())
        
        for($i=0; $i -lt $OwnerModuleTable.NumEntries; $i++)
        {
            $TcpRow = $RowPtr -as $MIB_TCPROW_OWNER_MODULE

            # Get the properties we want
            $LocalAddr = [System.Net.IPAddress]$TcpRow.LocalAddr
            $PortBytes = [System.BitConverter]::GetBytes($TcpRow.LocalPort)
            $LocalPort = $PortBytes[0]*256 + $PortBytes[1]

            $RemoteAddr = [System.Net.IPAddress]$TcpRow.RemoteAddr
            $PortBytes = [System.BitConverter]::GetBytes($TcpRow.RemotePort)
            $RemotePort = $PortBytes[0]*256 + $PortBytes[1]

            $ServiceTag = $TcpRow.OwningModuleInfo[0]                

            $RemoteHostname = $null
            if($ResolveHostnames) {
                try {
                    $RemoteHostname = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                }
                catch {
                    # Couldn't resolve the host name, so keep the IP
                }
            }

            $Output = @{
                LocalAddress = [string]$LocalAddr
                LocalPort = $LocalPort
                RemoteAddress = [string]$RemoteAddr
                RemoteHostname = $RemoteHostname
                RemotePort = $RemotePort
                #Process = Get-Process -Id $TcpRow.OwningPid -ErrorAction SilentlyContinue
                Process = (Get-Process -Id $TcpRow.OwningPid -ErrorAction SilentlyContinue).Name
                ProcessId = $TcpRow.OwningPid
                Protocol = "TCP"
                State = $TcpRow.State.ToString()
                Service = [string](Get-ServiceNameFromTag -ProcessId $TcpRow.OwningPid -ServiceTag $ServiceTag)
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output 
            }

            # Move to the next row in the TCP table
            $RowPtr = [IntPtr]($RowPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf($TcpRow))
        }
    }
    catch
    {
        Write-Error $_
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TableBuffer)
    }
}

function Get-Tcp6Connections
{
    Param
    (
        # Attempt to resolve the hostnames of each IP address
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashTables
    )

    $AF_INET6 = 23
    $TableBufferSize = 0
        
    $null = $IPHelperAPI::GetExtendedTcpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET6, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)
        
    try
    {
        $Ret = $IPHelperAPI::GetExtendedTcpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET6, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0);
            
        if($Ret -eq 50)
        {
            # IPv6 is not supported
            return
        }
        elseif ($Ret -ne 0)
        {
            Write-Error "Failed to get TCP connection information. GetExtendedTcpTable's return code: $Ret"
            return
        }
        
        $OwnerModuleTable  = $TableBuffer -as $MIB_TCP6TABLE_OWNER_MODULE
        $RowPtr = [IntPtr]($TableBuffer.ToInt64() + [Runtime.InteropServices.Marshal]::OffsetOf($MIB_TCPTABLE_OWNER_MODULE, "Table").ToInt64())

        for($i=0; $i -lt $OwnerModuleTable.NumEntries; $i++)
        {
            $TcpRow = $RowPtr -as $MIB_TCP6ROW_OWNER_MODULE
            
            # Get the properties we want
            $LocalAddr = [System.Net.IPAddress]$TcpRow.LocalAddr
            $PortBytes = [System.BitConverter]::GetBytes($TcpRow.LocalPort)
            $LocalPort = $PortBytes[0]*256 + $PortBytes[1]
            
            $RemoteAddr = [System.Net.IPAddress]$TcpRow.RemoteAddr
            $PortBytes = [System.BitConverter]::GetBytes($TcpRow.RemotePort)
            $RemotePort = $PortBytes[0]*256 + $PortBytes[1]

            $ServiceTag = $TcpRow.OwningModuleInfo[0]

            $RemoteHostname = $null;
            if($ResolveHostnames) {
                try {
                    $RemoteHostname = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                }
                catch {
                    # Couldn't resolve the host name, so keep the IP
                }
            }

            $Output = @{
                LocalAddress = [string]$LocalAddr
                LocalPort = $LocalPort
                RemoteAddress = [string]$RemoteAddr
                RemoteHostname = $RemoteHostname
                RemotePort = $RemotePort
                Process = (Get-Process -Id $TcpRow.OwningPid -ErrorAction SilentlyContinue).Name
                ProcessId = $TcpRow.OwningPid
                Protocol = "TCP"
                State = $TcpRow.State.ToString()
                Service = [string](Get-ServiceNameFromTag -ProcessId $TcpRow.OwningPid -ServiceTag $ServiceTag)
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output 
            }

            # Move to the next row in the TCP table
            $RowPtr = [IntPtr]($RowPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf($TcpRow))
        }
    }
    catch
    {
        Write-Error $_
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TableBuffer)
    }
}

function Get-Udp4Connections
{
    Param
    (
        # Attempt to resolve the hostnames of each IP address
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashTables
    )

    $AF_INET = 2
    $TableBufferSize = 0
    $null = $IPHelperAPI::GetExtendedUdpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)

    try
    {
        $Ret = $IPHelperAPI::GetExtendedUdpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0);
        if ($Ret -ne 0)
        {
            Write-Error "Failed to get UDP connection information. GetExtendedUdpTable's return code: $Ret"
            return
        }
        
        $OwnerModuleTable  = $TableBuffer -as $MIB_UDPTABLE_OWNER_MODULE
        $RowPtr = [IntPtr]($TableBuffer.ToInt64() + [Runtime.InteropServices.Marshal]::OffsetOf($MIB_UDPTABLE_OWNER_MODULE, "Table").ToInt64())

        for($i=0; $i -lt $OwnerModuleTable.NumEntries; $i++)
        {
            $UdpRow = $RowPtr -as $MIB_UDPROW_OWNER_MODULE

            # Get the properties we want
            $LocalAddr = [System.Net.IPAddress]$UdpRow.LocalAddr
            $PortBytes = [System.BitConverter]::GetBytes($UdpRow.LocalPort)
            $LocalPort = $PortBytes[0]*256 + $PortBytes[1]
            $ServiceTag = $UdpRow.OwningModuleInfo[0]

            $Output = @{
                LocalAddress = [string]$LocalAddr
                LocalPort = $LocalPort
                Process = (Get-Process -Id $UdpRow.OwningPid -ErrorAction SilentlyContinue).Name
                ProcessId = $UdpRow.OwningPid
                Protocol = "UDP"
                Service = [string](Get-ServiceNameFromTag -ProcessId $UdpRow.OwningPid -ServiceTag $ServiceTag)
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output 
            }

            # Move to the next row in the UDP table
            $RowPtr = [IntPtr]($RowPtr.ToInt64() + ([Runtime.InteropServices.Marshal]::SizeOf($UdpRow)))
        }
    }
    catch
    {
        Write-Error $_
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TableBuffer)
    }
}

function Get-Udp6Connections
{
    Param
    (
        # Attempt to resolve the hostnames of each IP address
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashTables
    )

    $AF_INET6 = 23
    $TableBufferSize = 0
    $null = $IPHelperAPI::GetExtendedUdpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET6, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)

    try
    {
        $Ret = $IPHelperAPI::GetExtendedUdpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET6, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0);
        if($Ret -eq 50) # ERROR_NOT_SUPPORTED
        {
            # IPv6 is not supported
            return
        }
        elseif ($Ret -ne 0)
        {
            Write-Error "Failed to get TCP connection information. GetExtendedTcpTable's return code: $Ret"
            return
        }
        
        $OwnerModuleTable  = $TableBuffer -as $MIB_UDP6TABLE_OWNER_MODULE
        $RowPtr = [IntPtr]($TableBuffer.ToInt64() + [Runtime.InteropServices.Marshal]::OffsetOf($MIB_UDPTABLE_OWNER_MODULE, "Table").ToInt64())
  
        for($i=0; $i -lt $OwnerModuleTable.NumEntries; $i++)
        {
            $UdpRow = $RowPtr -as $MIB_UDP6ROW_OWNER_MODULE

            $LocalAddr = [System.Net.IPAddress]$UdpRow.LocalAddr
            $PortBytes = [System.BitConverter]::GetBytes($UdpRow.LocalPort)
            $LocalPort = $PortBytes[0]*256 + $PortBytes[1]
            $ServiceTag = $UdpRow.OwningModuleInfo[0]

            if($ResolveHostnames) {
                try {
                    $RemoteIP = [System.Net.Dns]::GetHostEntry($LocalAddr).HostName
                }
                catch {

                }
            }

            $Output = @{
                LocalAddress = [string]$LocalAddr
                LocalPort = $LocalPort
                Process = (Get-Process -Id $UdpRow.OwningPid -ErrorAction SilentlyContinue).Name
                ProcessId = $UdpRow.OwningPid
                Protocol = "UDP"
                Service = [string](Get-ServiceNameFromTag -ProcessId $UdpRow.OwningPid -ServiceTag $ServiceTag)
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output 
            }

            # Move to the next row in the UDP table
            $RowPtr = [IntPtr]($RowPtr.ToInt64() + ([Runtime.InteropServices.Marshal]::SizeOf($UdpRow)))
        }
    }
    catch
    {
        Write-Error $_
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TableBuffer)
    }
}

#endregion Helper Functions

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
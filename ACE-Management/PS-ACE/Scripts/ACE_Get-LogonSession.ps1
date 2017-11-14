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

    foreach($o in (Get-LogonSession))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'LogonSession')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'LogonSession'
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

function Get-LogonSession
{
    <#

    .SYNOPSIS

    .DESCRIPTION

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: 
    Required Dependencies: PSReflect, LsaEnumerateLogonSessions (Function), LsaFreeReturnBuffer (Function), LsaGetLogonSessionData (Function) LsaNtStatusToWinError (Function), SECURITY_LOGON_SESSION_DATA (Structure), LUID (Structure), LSA_UNICODE_STRING (Structure), LSA_LAST_INTER_LOGON_INFO (Structure), SecurityEntity (Enumeration), SECURITY_LOGON_TYPE (Enumeration)
    Optional Dependencies: None

    .LINK

    .EXAMPLE

    Get-LogonSession

    FailedAttemptCountSinceLastSuccessfulLogon : 0
    DnsDomainName                              : HUNT.LOCAL
    KickOffTime                                : 1/1/1601 1:00:00 AM
    PasswordCanChange                          : 5/20/2017 9:51:20 PM
    Upn                                        : Administrator@HUNT.LOCAL
    UserName                                   : Administrator
    Session                                    : 1
    LogoffTime                                 : 1/1/1601 1:00:00 AM
    LastFailedLogon                            : 1/1/1601 1:00:00 AM
    LogonServer                                : DC
    Sid                                        : S-1-5-21-3250051078-751264820-3215766868-500
    LogonScript                                : 
    UserFlags                                  : 49444
    ProfilePath                                : 
    PasswordMustChange                         : 6/30/2017 9:51:20 PM
    LogonId                                    : 325349
    LogonTime                                  : 5/20/2017 9:47:34 AM
    PasswordLastSet                            : 5/19/2017 9:51:20 PM
    LogonDomain                                : 
    HomeDirectory                              : 
    LogonType                                  : Interactive
    AuthenticationPackage                      : Kerberos
    LastSuccessfulLogon                        : 1/1/1601 1:00:00 AM
    HomeDirectoryDrive                         : 

    #>

    [CmdletBinding()]
    param
    (

    )

    $LogonSessions = LsaEnumerateLogonSessions
    $Sessions = LsaGetLogonSessionData -LuidPtr $LogonSessions.SessionListPointer -SessionCount $LogonSessions.SessionCount

    Write-Output $Sessions
}

#region PSReflect

#Requires -Version 2

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

.PARAMETER CharSet

Dictates which character set marshaled strings should use.

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
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
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

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        }
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

$Module = New-InMemoryModule -ModuleName GetLogonSession

#region Enums
$SECURITY_LOGON_TYPE = psenum $Module SECURITY_LOGON_TYPE UInt32 @{
    Interactive             = 2
    Network                 = 3
    Batch                   = 4
    Service                 = 5
    Proxy                   = 6
    Unlock                  = 7
    NetworkCleartext        = 8
    NewCredentials          = 9
    RemoteInteractive       = 10
    CachedInteractive       = 11
    CachedRemoteInteractive = 12
    CachedUnlock            = 13
}

$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeCreateTokenPrivilege          = 1
    SeAssignPrimaryTokenPrivilege   = 2
    SeLockMemoryPrivilege           = 3
    SeIncreaseQuotaPrivilege        = 4
    SeUnsolicitedInputPrivilege     = 5
    SeMachineAccountPrivilege       = 6
    SeTcbPrivilege                  = 7
    SeSecurityPrivilege             = 8
    SeTakeOwnershipPrivilege        = 9
    SeLoadDriverPrivilege           = 10
    SeSystemProfilePrivilege        = 11
    SeSystemtimePrivilege           = 12
    SeProfileSingleProcessPrivilege = 13
    SeIncreaseBasePriorityPrivilege = 14
    SeCreatePagefilePrivilege       = 15
    SeCreatePermanentPrivilege      = 16
    SeBackupPrivilege               = 17
    SeRestorePrivilege              = 18
    SeShutdownPrivilege             = 19
    SeDebugPrivilege                = 20
    SeAuditPrivilege                = 21
    SeSystemEnvironmentPrivilege    = 22
    SeChangeNotifyPrivilege         = 23
    SeRemoteShutdownPrivilege       = 24
    SeUndockPrivilege               = 25
    SeSyncAgentPrivilege            = 26
    SeEnableDelegationPrivilege     = 27
    SeManageVolumePrivilege         = 28
    SeImpersonatePrivilege          = 29
    SeCreateGlobalPrivilege         = 30
    SeTrustedCredManAccessPrivilege = 31
    SeRelabelPrivilege              = 32
    SeIncreaseWorkingSetPrivilege   = 33
    SeTimeZonePrivilege             = 34
    SeCreateSymbolicLinkPrivilege   = 35
}
#endregion Enums

#region Structures
$LSA_LAST_INTER_LOGON_INFO = struct $Module LSA_LAST_INTER_LOGON_INFO @{
    LastSuccessfulLogon                        = field 0 Int64
    LastFailedLogon                            = field 1 Int64
    FailedAttemptCountSinceLastSuccessfulLogon = field 2 UInt64
}

$LUID = struct $Module LUID @{
    LowPart  = field 0 $SecurityEntity
    HighPart = field 1 Int32
}

$LSA_UNICODE_STRING = struct $Module LSA_UNICODE_STRING @{
    Length        = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer        = field 2 IntPtr
}

$SECURITY_LOGON_SESSION_DATA = struct $Module SECURITY_LOGON_SESSION_DATA @{
    Size                  = field 0 UInt32
    LogonId               = field 1 $LUID
    Username              = field 2 $LSA_UNICODE_STRING
    LogonDomain           = field 3 $LSA_UNICODE_STRING
    AuthenticationPackage = field 4 $LSA_UNICODE_STRING
    LogonType             = field 5 UInt32
    Session               = field 6 UInt32
    PSiD                  = field 7 IntPtr
    LogonTime             = field 8 UInt64
    LogonServer           = field 9 $LSA_UNICODE_STRING
    DnsDomainName         = field 10 $LSA_UNICODE_STRING
    Upn                   = field 11 $LSA_UNICODE_STRING
    UserFlags             = field 12 UInt64
    LastLogonInfo         = field 13 $LSA_LAST_INTER_LOGON_INFO
    LogonScript           = field 14 $LSA_UNICODE_STRING
    ProfilePath           = field 15 $LSA_UNICODE_STRING
    HomeDirectory         = field 16 $LSA_UNICODE_STRING
    HomeDirectoryDrive    = field 17 $LSA_UNICODE_STRING
    LogoffTime            = field 18 Int64
    KickOffTime           = field 19 Int64
    PasswordLastSet       = field 20 Int64
    PasswordCanChange     = field 21 Int64
    PasswordMustChange    = field 22 Int64
}
#endregion Structures

#region FunctionDefinitions
$FunctionDefinitions = @(
    (func secur32 LsaEnumerateLogonSessions ([UInt32]) @(
        [UInt64].MakeByRefType(), #_Out_ PULONG LogonSessionCount,
        [IntPtr].MakeByRefType()  #_Out_ PLUID  *LogonSessionList
    ) -EntryPoint LsaEnumerateLogonSessions),

    (func secur32 LsaFreeReturnBuffer ([UInt32]) @(
        [IntPtr] #_In_ PVOID Buffer
    ) -EntryPoint LsaFreeReturnBuffer),

    (func secur32 LsaGetLogonSessionData ([UInt32]) @(
        [IntPtr],                #_In_  PLUID                        LogonId,
        [IntPtr].MakeByRefType() #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
    ) -EntryPoint LsaGetLogonSessionData),

    (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
        [UInt32] #_In_ NTSTATUS Status
    ) -EntryPoint LsaNtStatusToWinError)
)
#endregion FunctionDefinitions

#region Windows API Functions
function LsaEnumerateLogonSessions
{
    <#
    .SYNOPSIS

    The LsaEnumerateLogonSessions function retrieves the set of existing logon session identifiers (LUIDs) and the number of sessions.

    .DESCRIPTION

    To retrieve information about the logon sessions returned by LsaEnumerateLogonSessions, call the LsaGetLogonSessionData function.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, LsaNtStatusToWinError (Function)
    Optional Dependencies: None

    (func secur32 LsaEnumerateLogonSessions ([UInt32]) @(
        [UInt64].MakeByRefType(), #_Out_ PULONG LogonSessionCount,
        [IntPtr].MakeByRefType()  #_Out_ PLUID  *LogonSessionList
    ) -EntryPoint LsaEnumerateLogonSessions)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378275(v=vs.85).aspx

    .EXAMPLE

    LsaEnumerateLogonSessions
    8
    2390553591808

    .EXAMPLE

    $SessionCount, $LogonSessionListPtr = LsaEnumerateLogonSessions
    #>

    $LogonSessionCount = [UInt64]0
    $LogonSessionList = [IntPtr]::Zero

    $SUCCESS = $Secur32::LsaEnumerateLogonSessions([ref]$LogonSessionCount, [ref]$LogonSessionList)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaEnumerateLogonSessions Error: $($LastError.Message)"
    }

    $obj = New-Object -TypeName psobject

    $obj | Add-Member -MemberType NoteProperty -Name SessionCount -Value $LogonSessionCount
    $obj | Add-Member -MemberType NoteProperty -Name SessionListPointer -Value $LogonSessionList
    
    Write-Output $obj
}

function LsaFreeReturnBuffer
{
    <#
    .SYNOPSIS

    The LsaFreeReturnBuffer function frees the memory used by a buffer previously allocated by the LSA.

    .DESCRIPTION

    Some of the LSA authentication functions allocate memory buffers to hold returned information, for example, LsaLogonUser and LsaCallAuthenticationPackage. Your application should call LsaFreeReturnBuffer to free these buffers when they are no longer needed.

    .PARAMETER Buffer

    Pointer to the buffer to be freed.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, LsaNtStatusToWinError (Function)
    Optional Dependencies: None

    (func secur32 LsaFreeReturnBuffer ([UInt32]) @(
        [IntPtr] #_In_ PVOID Buffer
    ) -EntryPoint LsaFreeReturnBuffer)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378279(v=vs.85).aspx

    .EXAMPLE

    LsaFreeReturnBuffer -Buffer $Buffer
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Buffer
    )

    $SUCCESS = $Secur32::LsaFreeReturnBuffer($Buffer)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaFreeReturnBuffer Error: $($LastError.Message)"
    }
}

function LsaGetLogonSessionData
{
    <#
    .SYNOPSIS

    The LsaGetLogonSessionData function retrieves information about a specified logon session.

    .DESCRIPTION

    .Parameter LuidPtr

    .Parameter SessionCount

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, LsaFreeReturnBuffer (Function), LsaNtStatusToWinError (Function), SECURITY_LOGON_SESSION_DATA (Structure), LUID (Structure), LSA_UNICODE_STRING (Structure), LSA_LAST_INTER_LOGON_INFO (Structure), SecurityEntity (Enumeration), SECURITY_LOGON_TYPE (Enumeration)
    Optional Dependencies: None

    (func secur32 LsaGetLogonSessionData ([UInt32]) @(
        [IntPtr],                #_In_  PLUID                        LogonId,
        [IntPtr].MakeByRefType() #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
    ) -EntryPoint LsaGetLogonSessionData)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378290(v=vs.85).aspx

    .EXAMPLE

    $SessionCount, $LogonSessionListPtr = LsaEnumerateLogonSessions
    LsaGetLogonSessionData -LuidPtr $LogonSessionListPtr -SessionCount $SessionCount
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LuidPtr,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $SessionCount
    )

    $CurrentLuidPtr = $LuidPtr

    for($i = 0; $i -lt $SessionCount; $i++)
    {
        $sessionDataPtr = [IntPtr]::Zero
        $SUCCESS = $Secur32::LsaGetLogonSessionData($CurrentLuidPtr, [ref]$sessionDataPtr)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaGetLogonSessionData Error: $($LastError.Message)"
        }

        try
        {
            $sessionData = $sessionDataPtr -as $SECURITY_LOGON_SESSION_DATA

            $props = @{
                LogonId = $sessionData.LogonId.LowPart
                UserName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Username.Buffer, $sessionData.Username.Length / 2)
                LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonDomain.Buffer, $sessionData.LognDomain.Length / 2)
                AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.AuthenticationPackage.Buffer, $sessionData.AuthenticationPackage.Length / 2)
                LogonType = ($sessionData.LogonType -as $SECURITY_LOGON_TYPE).ToString()
                Session = $sessionData.Session
                Sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($sessionData.PSiD)).ToString()
                LogonTime = [datetime]::FromFileTime($sessionData.LogonTime)
                LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonServer.Buffer, $sessionData.LogonServer.Length / 2)
                DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.DnsDomainName.Buffer, $sessionData.DnsDomainName.Length / 2)
                Upn =  [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Upn.Buffer, $sessionData.Upn.Length / 2)
                UserFlags = $sessionData.UserFlags
                LastSuccessfulLogon = $sessionData.LastLogonInfo.LastSuccessfulLogon
                LastFailedLogon = $sessionData.LastLogonInfo.LastFailedLogon
                FailedAttemptCountSinceLastSuccessfulLogon = $sessionData.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon
                LogonScript = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonScript.Buffer, $sessionData.LogonScript.Length / 2)
                ProfilePath = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.ProfilePath.Buffer, $sessionData.ProfilePath.Length / 2)
                HomeDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectory.Buffer, $sessionData.HomeDirectory.Length / 2)
                HomeDirectoryDrive = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectoryDrive.Buffer, $sessionData.HomeDirectoryDrive.Length / 2)
                LogoffTime = $sessionData.LogoffTime
                KickOffTime = $sessionData.KickOffTime
                PasswordLastSet = [datetime]::FromFileTime($sessionData.PasswordLastSet)
                PasswordCanChange = [datetime]::FromFileTime($sessionData.PasswordCanChange)
                PasswordMustChange = $sessionData.PasswordMustChange
            }
             
            Write-Output $props       
            #$obj = New-Object -TypeName psobject -Property $props

            #Write-Output $obj
        }
        catch
        {

        }

        LsaFreeReturnBuffer -Buffer $sessionDataPtr
        $CurrentLuidPtr = [IntPtr]($CurrentLuidPtr.ToInt64() + $LUID::GetSize())
    }
}

function LsaNtStatusToWinError
{
    <#
    .SYNOPSIS

    The LsaNtStatusToWinError function converts an NTSTATUS code returned by an LSA function to a Windows error code.

    .PARAMETER NtStatus

    An NTSTATUS code returned by an LSA function call. This value will be converted to a System error code.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
        [UInt32] #_In_ NTSTATUS Status
    ) -EntryPoint LsaNtStatusToWinError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms721800(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $NtStatus
    )

    $STATUS = $Advapi32::LsaNtStatusToWinError($NtStatus)

    Write-Output $STATUS
}
#endregion Windows API Functions

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'GetLogonSession'
$Advapi32 = $Types['advapi32']
$Secur32 = $Types['secur32']

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
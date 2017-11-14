#requires -version 2.0

#region Helper functions
function Invoke-WebRequest2 {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param
    (
    [Parameter(
            Position=0,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [ValidateSet('Delete','Get','Head','Options','Patch','Post','Put')]
    [string]
    $Method,
    
    [Parameter(Position=1,
            Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [System.Uri]
    $Uri,

    [Parameter(Position=2,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [string]
    $UserAgent,

    [Parameter(Position=3,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [string]
    $ContentType,

    [Parameter(Position=4,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [System.Collections.Hashtable]
    $Headers = @{},

    [Parameter(ParameterSetName='UploadString',
            Position=5,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [string]
    $Body,

    [Parameter(ParameterSetName='UploadByte',
            Position=5,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [byte[]]
    $Byte,

    [Parameter(Position=6,
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
    [System.Management.Automation.PSCredential]
    $Credential
    )
    Write-Verbose 'Sending request'
    $WebRequest = New-Object System.Net.WebClient

    if($Credential) {
        $WebRequest.Credentials = $Credential.GetNetworkCredential()
    }

    if($UserAgent) {
        Write-Verbose 'Adding user agent'
        $WebRequest.Headers.Add('User-Agent',$UserAgent)
    }

    if($ContentType) {
        Write-Verbose 'Adding content type'
        $WebRequest.Headers.Add('Content-Type',$ContentType)
    }
    
    foreach($Key in $Headers.Keys) {
        $WebRequest.Headers.Add($Key, $Headers["$Key"])
    }
    
    if($Body) {
        Write-Verbose "Uri: $($Uri)"
        Write-Verbose "Method: $($Method)"
        Write-Verbose "Body: $($Body)"
        $WebRequest.UploadString($Uri, $Method, $Body)
    } elseif($Byte) {
        $WebRequest.UploadData($Uri, $Method, $Byte)
    } else {
        $WebRequest.DownloadString($Uri)
    }
}
#endregion Helper functions


#region PSInvestigate cmdlets
function Get-PSICachedDnsEntry {
<#
    .SYNOPSIS

        Gets cached DNS entries

        Author: Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

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

        ForEach ($Assembly in $LoadedAssemblies) {
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
            [String]
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
                ForEach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        [void] $Method.DefineParameter($i, 'Out', $Null)
                    }

                    $i++
                }

                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                    $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                    [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                    [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

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

            ForEach ($Key in $TypeHash.Keys)
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

        ForEach ($Key in $EnumElements.Keys)
        {
            # Apply the specified enum type to each element
            $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
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
        ForEach ($Field in $StructFields.Keys)
        {
            $Index = $StructFields[$Field]['Position']
            $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
        }

        ForEach ($Field in $Fields)
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

    #endregion

    #region Win32 API Definitions
    $Mod = New-InMemoryModule -ModuleName Win322

    # https://msdn.microsoft.com/en-us/library/windows/desktop/cc982162(v=vs.85).aspx
    $DNS_RECORD_TYPE = psenum $Mod DNS_RECORD_TYPE UInt16 @{
        DNS_TYPE_A = 0x1
        DNS_TYPE_NS = 0x2
        DNS_TYPE_MD = 0x3
        DNS_TYPE_MF = 0x4
        DNS_TYPE_CNAME = 0x5
        DNS_TYPE_SOA = 0x6
        DNS_TYPE_MB = 0x7
        DNS_TYPE_MG = 0x8
        DNS_TYPE_MR = 0x9
        DNS_TYPE_NULL = 0xA
        DNS_TYPE_WKS = 0xB
        DNS_TYPE_PTR = 0xC
        DNS_TYPE_HINFO = 0xD
        DNS_TYPE_MINFO = 0xE
        DNS_TYPE_MX = 0xF
        DNS_TYPE_TEXT = 0x10
        DNS_TYPE_TXT = 0x10
        DNS_TYPE_RP = 0x11
        DNS_TYPE_AFSDB = 0x12
        DNS_TYPE_X25 = 0x13
        DNS_TYPE_ISDN = 0x14
        DNS_TYPE_RT = 0x15
        DNS_TYPE_NSAP = 0x16
        DNS_TYPE_NSAPPTR = 0x17
        DNS_TYPE_SIG = 0x18
        DNS_TYPE_KEY = 0x19
        DNS_TYPE_PX = 0x1A
        DNS_TYPE_GPOS = 0x1B
        DNS_TYPE_AAAA = 0x1C
        DNS_TYPE_LOC = 0x1D
        DNS_TYPE_NXT = 0x1E
        DNS_TYPE_EID = 0x1F
        DNS_TYPE_NIMLOC = 0x20
        DNS_TYPE_SRV = 0x21
        DNS_TYPE_ATMA = 0x22
        DNS_TYPE_NAPTR = 0x23
        DNS_TYPE_KX = 0x24
        DNS_TYPE_CERT = 0x25
        DNS_TYPE_A6 = 0x26
        DNS_TYPE_DNAME = 0x27
        DNS_TYPE_SINK = 0x28
        DNS_TYPE_OPT = 0x29
        DNS_TYPE_DS = 0x2B
        DNS_TYPE_RRSIG = 0x2E
        DNS_TYPE_NSEC = 0x2F
        DNS_TYPE_DNSKEY = 0x30
        DNS_TYPE_DHCID = 0x31
        DNS_TYPE_UINFO = 0x64
        DNS_TYPE_UID = 0x65
        DNS_TYPE_GID = 0x66
        DNS_TYPE_UNSPEC = 0x67
        DNS_TYPE_ADDRS = 0xF8
        DNS_TYPE_TKEY = 0xF9
        DNS_TYPE_TSIG = 0xFA
        DNS_TYPE_IXFR = 0xFB
        DNS_TYPE_AFXR = 0xFC
        DNS_TYPE_MAILB = 0xFD
        DNS_TYPE_MAILA = 0xFE
        DNS_TYPE_ALL = 0xFF
        DNS_TYPE_ANY = 0xFF
        DNS_TYPE_WINS = 0xFF01
        DNS_TYPE_WINSR = 0xFF02
    }

    $DNS_CACHE_ENTRY = struct $Mod DNS_CACHE_ENTRY @{
        Next = field 0 IntPtr                         # PSReflect doesn't support self referencing structures, so have to use IntPtr
        Name = field 1 String -MarshalAs @('LPWStr')
        Type = field 2 $DNS_RECORD_TYPE
        DataLength = field 3 UInt16
        Flags = field 4 UInt32
    }

    $FunctionDefinitions = @(
        (func dnsapi DnsGetCacheDataTable ([Int]) @($DNS_CACHE_ENTRY.MakeByRefType()))
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $DnsApi = $Types['dnsapi']
    #endregion
 
    $DnsEntry = [Activator]::CreateInstance($DNS_CACHE_ENTRY)

    $Res = $DnsApi::DnsGetCacheDataTable([ref]$DnsEntry)

    if($Res -lt 0)
    {
        Write-Error "Failed to obtain reference to DNS cache table"
    }

    $DnsEntry = $DnsEntry.Next -as $DNS_CACHE_ENTRY

    while($DnsEntry)
    {
        $Output = @{
            Name = $DnsEntry.Name
            Type = $DnsEntry.Type
            Flags = $DnsEntry.Flags
            DateLength = $DnsEntry.DataLength
            ComputerName = $HostFQDN
        }

        if($ReturnHashtables) {
            $Output
        } else {
            New-Object PSObject -Property $Output | ConvertTo-Json -Compress
        }

        $DnsEntry = $DnsEntry.Next -as $DNS_CACHE_ENTRY
    }
}
function Get-PSILoadedModuleHashes {
<#
    .SYNOPSIS

        Returns hashes of all loaded .exe's and .dll's loaded by processes

        Author: Lee Christensen (@tifkin_)
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
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
        $TimeCreated = [DateTime]::Now

        # Thanks to https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
        function Get-DIGSFileHash
        {
            [CmdletBinding(DefaultParameterSetName = "Path")]
            param
            (
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
            param
            (
                [System.IO.Stream]
                $InputStream,

                [System.String]
                $RelatedPath,

                [System.Security.Cryptography.HashAlgorithm]
                $Hasher
            )

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
 
        $FileHashCache = @{}

        function Add-DIGSModuleHash
        {
            param
            (
                [string]
                $File,

                [System.Diagnostics.Process]
                $Process
            )

            if($FileHashCache[$File])
            {
                $FileHashCache[$File].Processes += $Process.Name.ToLower()
            }
            else
            {
                $FileHashCache[$File] = New-Object PSObject -Property @{
                    Processes = @($Process.Name.ToLower())
                    MD5 = $null
                    SHA256 = $null
                }

                if($File -and (Test-Path $File))
                {
                    #$FileHashCache[$File].MD5 = (Get-DIGSFileHash -Path $File -Algorithm MD5).Hash
                    $FileHashCache[$File].SHA256 = (Get-DIGSFileHash -Path $File -Algorithm SHA256).Hash
                }
            }
        }
    }
    
    Process
    {
        $Processes = Get-Process

        foreach($Process in $Processes)
        {
            if($Process.Modules) {
                foreach($Module in $Process.Modules)
                {
                    Add-DIGSModuleHash -File ($Module.FileName.ToLower()) -Process $Process
                }
            }
        }
    }

    End
    {
        foreach($Key in $FileHashCache.Keys)
        {
            $Output = @{
                Path = $Key
                SHA256Hash = $FileHashCache[$Key].SHA256
                Processes = ($FileHashCache[$Key].Processes | sort -Unique) -join ','
                ComputerName = $HostFQDN
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output
            }
        }
    }
}
function Get-PSIMasterBootRecord {
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
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
         
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
                    ComputerName = $HostFQDN
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
function Get-PSINetworkConnection {
<#
    .SYNOPSIS

        Returns current TCP and UDP connections.

        Author: Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param (
        [switch]
        $ResolveHostnames,

        [switch]
        $ReturnHashtables
    )

    $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

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

    #endregion

    #region Windows API Definitions
    $Mod = New-InMemoryModule -ModuleName Win32

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

    #endregion

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

    #endregion

    #region Functions
    $FunctionDefinitions = @(
        (func iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]))
        (func iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]))
        (func advapi32 I_QueryTagInformation ([UInt32]) @([IntPtr], $SC_SERVICE_TAG_QUERY_TYPE, $SC_SERVICE_TAG_QUERY.MakeByRefType()))
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $IPHelperAPI = $Types['iphlpapi']
    $Advapi32 = $Types['advapi32']

    #endregion
    #endregion # Win32 Defintions..

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

    function Get-Tcp4Connections {
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
                    ComputerName = $HostFQDN
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

    function Get-Tcp6Connections {
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
                    ComputerName = $HostFQDN
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

    function Get-Udp4Connections {
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
                    ComputerName = $HostFQDN
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

    function Get-Udp6Connections {
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
                    ComputerName = $HostFQDN
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

    function Invoke-NetStat
    {
        Param
        (
            # Attempt to resolve the hostnames of each IP address
            [switch]
            $ResolveHostnames,

            [switch]
            $ReturnHashTables
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

    Invoke-NetStat @PSBoundParameters
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
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

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
                        ComputerName = $HostFQDN
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
function Get-PSIProcess {
<#
    .SYNOPSIS

        Returns detailed information about the current running processes.

        Author: Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    # TODO: Optimize this cmdlet...

    begin
    {
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

        # Thanks to https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
        function Get-DIGSFileHash
        {
            [CmdletBinding(DefaultParameterSetName = "Path")]
            param
            (
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
            param
            (
                [System.IO.Stream]
                $InputStream,

                [System.String]
                $RelatedPath,

                [System.Security.Cryptography.HashAlgorithm]
                $Hasher
            )

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
 
        $FileHashCache = @{}
        $Processes = Get-WmiObject -Class Win32_Process

        function Get-DIGSCachedFileHash
        {
            param
            (
                [string]
                $File
            )

            if($FileHashCache[$File])
            {
                $FileHashCache[$File]
            }
            else
            {
                if($File -and (Test-Path $File))
                {
                    $ModuleMD5 = (Get-DIGSFileHash -Path $File -Algorithm MD5).Hash
                    $ModuleSHA256 = (Get-DIGSFileHash -Path $File -Algorithm SHA256).Hash

                    $FileHashCache[$File] = New-Object PSObject -Property @{
                        MD5 = $ModuleMD5
                        SHA256 = $ModuleSHA256
                    }

                    $FileHashCache[$File]
                }
            }
        }
    }

    process
    {
        foreach($Process in $Processes)
        {
            $Proc = Get-Process -Id $Process.ProcessId -ErrorAction SilentlyContinue
            $Path = $Proc.Path
            $LoadedModules = $null
            $Owner = $null
            $OwnerStr = $null

            if($Proc)
            {
                #$PE = Get-PE -ModuleBaseAddress $Proc.MainModule.BaseAddress -ProcessID $Process.ProcessId
                $Proc.Modules | ForEach-Object {
                    if($_) 
                    {
                        $ModuleHash = Get-DIGSCachedFileHash -File $_.FileName

                        $_ | Add-Member NoteProperty -Name "MD5Hash" -Value $ModuleHash.MD5
                        $_ | Add-Member NoteProperty -Name "SHA256Hash" -Value $ModuleHash.SHA256
                    }
                }
                $LoadedModules = $Proc.Modules
            }

            # Get file information
            $FileHash = $null
            if($Path -ne $null -and (Test-Path $Path)) {
                # TODO: Add error handling here in case we can't read the file (wonky exe permissions)

                $FileHash = Get-DIGSCachedFileHash -File $Path

                $File = (Get-ChildItem $Path)
                $FileSize = $File.Length
                $FileCreationTime = $File.CreationTimeUtc
                $FileLastAccessTime = $File.LastAccessTimeUtc
                $FileLastWriteTime = $File.LastWriteTimeUtc
                $FileExtension = $File.Extension
                $ProcessId = $Process.ProcessId
            } else {
                if($Proc.Id -ne 0 -and $Proc.Id -ne 4)
                {
                    #Write-Warning "Could not find executable path. PSProcessName: $($Proc.Name) PSPid: $($Proc.Id) WMIProcName: $($Process.Name) WMIPid: $($Process.ProcessId)"
                }
                $Path = ''
            }
        
            # Get the process owner
            $NTVersion = [System.Environment]::OSVersion.Version
            try {
                if($NTVersion.Major -ge 6)
                {
                    $Owner = $Process.GetOwner()
                    if($Owner -and ($Owner.Domain -or $Owner.User)) {
                        $OwnerStr = "$($Owner.Domain)\$($Owner.User)"
                    }
        
                    $OwnerObj = $Process.GetOwnerSid()
                    if($OwnerObj)
                    {
                        $OwnerSid = $OwnerObj.Sid
                    }
                }
            } catch {}

            $LoadedModuleList = $LoadedModules | sort ModuleName | select -ExpandProperty ModuleName
            $ParentProcess = Get-Process -Id $Process.ProcessId -ErrorAction SilentlyContinue
        
            $ErrorActionPreference = 'Stop'
            $Output = @{
                Name = $Process.Name
                Path = [string]$Process.Path
                CommandLine = $Process.CommandLine
                MD5Hash = $FileHash.MD5
                SHA256Hash = $FileHash.SHA256
                FileSize = $FileSize
                FileCreationTime = $FileCreationTime
                FileLastAccessTime = $FileLastAccessTime
                FileLastWriteTime = $FileLastWriteTime
                FileExtension = $FileExtension
                Owner = $OwnerStr
                OwnerSid = $OwnerSid
                ParentProcessId = $Process.ParentProcessID
                ParentProcessName = $ParentProcess.Name
                ProcessId = $ProcessId
                ## PE = $PE
                #LoadedModules = $LoadedModules | select *
                LoadedModulesList = ($LoadedModuleList -join ";").ToLower()
                ComputerName = $HostFQDN
            }

            try {
                $null = ConvertTo-JsonV2 $Output
            } catch {
                Write-Error $_
            }

            if($ReturnHashtables) {
                $Output
            } else {
                 New-Object PSObject -Property $Output
            }
        }
    }

    end
    {

    }
}
function Get-PSIScheduledTask {
<#
    .SYNOPSIS

        Returns detailed information about scheduled tasks.

        Author: Lee Christensen (@tifkin_), Jared Atkinson
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    begin
    {
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

        # Based on Get-ScheduledTask in the Windows 7 Resource Kit PowerShell Pack
        function Get-DIGSScheduledTaskData
        {
        <#
        .Synopsis
            Gets tasks scheduled on the computer
        .Description
            Gets scheduled tasks that are registered on a computer
        .Example
            Get-ScheduleTask -Recurse
        #>
        param(
        # The name or name pattern of the scheduled task
        [Parameter()]
        $Name = "*",
    
        # The folder the scheduled task is in
        [Parameter()]
        [String[]]
        $Folder = "",
    
        # If this is set, hidden tasks will also be shown.  
        # By default, only tasks that are not marked by Task Scheduler as hidden are shown.
        [Switch]
        $Hidden,    
    
        # The name of the computer to connect to.
        $ComputerName,
    
        # The credential used to connect
        [Management.Automation.PSCredential]
        $Credential,
    
        # If set, will get tasks recursively beneath the specified folder
        [switch]
        $Recurse
        )
    
        process {
            $scheduler = New-Object -ComObject Schedule.Service
            if ($Credential) { 
                $NetworkCredential = $Credential.GetNetworkCredential()
                $scheduler.Connect($ComputerName, 
                    $NetworkCredential.UserName, 
                    $NetworkCredential.Domain, 
                    $NetworkCredential.Password)            
            } else {
                $scheduler.Connect($ComputerName)        
            }    
                
            $taskFolder = $scheduler.GetFolder($folder)
            $taskFolder.GetTasks($Hidden -as [bool]) | Where-Object {
                $_.Name -like $name
            }
            if ($Recurse) {
                $taskFolder.GetFolders(0) | ForEach-Object {
                    $psBoundParameters.Folder = $_.Path
                    Get-DIGSScheduledTaskData @psBoundParameters
                }
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

        function Get-ClassID
        {
            param($ClassId)
  
            $Value = Get-ItemProperty "HKLM:\Software\Classes\CLSID\$($ClassId)\InprocServer32" -Name "(Default)" -ErrorAction SilentlyContinue
            if($Value) {
                $Value.'(Default)'
            } else {
                ''
            }
        }  
    }

    process
    {
        $Tasks = Get-DIGSScheduledTaskData -Recurse

        foreach($Task in $Tasks)
        {
            $ActionComClassId = $null
            $ActionComDll = $null
            $ActionComDllMD5 = $null
            $ActionComDllSHA256 = $null
            $ActionComData = $null
            $ActionExecCommand = $null
            $ActionExecCommandMD5 = $null
            $ActionExecCommandSHA256 = $null
            $ActionExecArguments = $null
            $ActionExecWorkingDirectory = $null
                
            $Xml = [Xml]$Task.Xml
    
            $ActionCom = $Xml.Task.Actions.ComHandler
            $ActionComDll = if($ActionCom.ClassId) { Get-ClassID ($ActionCom.ClassId)} else { $null }
        
            if($ActionComDll)
            {
                $ActionComDllMD5 =  (Get-DIGSFileHash -Path $ActionComDll -Algorithm MD5).Hash
                $ActionComDllSHA256 = (Get-DIGSFileHash -Path $ActionComDll -Algorithm SHA256).Hash
            }
            $ActionComData = if($ActionCom.Data) { $ActionCom.Data.InnerXml} else {$null}

            $ActionExec = $Xml.Task.Actions.Exec
            if($ActionExec.Command)
            {
                $ActionExecPath = [System.Environment]::ExpandEnvironmentVariables($ActionExec.Command)
            
                $CleanedPath = $ActionExecPath.Replace("`"", "")
                if(Test-Path $CleanedPath -ErrorAction SilentlyContinue)
                {
                    $ActionExecCommandMD5 = (Get-DIGSFileHash -Path $CleanedPath -Algorithm MD5).Hash
                    $ActionExecCommandSHA256 = (Get-DIGSFileHash -Path $CleanedPath -Algorithm SHA256).Hash
                }
            }

            $Output = @{
                Name = $Task.Name
                Path = $Task.Path
                Enabled = $Task.Enabled
                LastRunTime = $Task.LastRunTime
                LastTaskResult = $Task.LastTaskResult
                NumberOfMissedRuns = $Task.NumberOfMissedRuns
                NextRunTime = $Task.NextRunTime
                Xml = $Task.Xml
                ActionComClassId = $ActionCom.ClassId
                ActionComDll = $ActionComDll
                ActionComDllMD5 = $ActionComDllMd5
                ActionComDllSHA256 = $ActionComDllSHA256
                ActionComData = $ActionComData
                ActionExecCommand = $ActionExec.Command
                ActionExecCommandMD5 = $ActionExecCommandMD5
                ActionExecCommandSHA256 = $ActionExecCommandSHA256
                ActionExecArguments = $ActionExec.Arguments
                ActionExecWorkingDirectory = $ActionExec.WorkingDirectory
                ComputerName = $HostFQDN
            }

            if($ReturnHashtables) {
                $Output
            } else {
                New-Object PSObject -Property $Output
            }
        }
    }

    end
    {

    }
}
function Get-PSIService {
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
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

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
                ComputerName = $HostFQDN
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
function Get-PSISimpleNamedPipe { 
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
        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

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
            ComputerName = $HostFQDN
        }

        do {
            $Output = @{
                Name = [string](Read-Field cFileName)
                Instances = [UInt32](Read-Field nFileSizeLow)
                ComputerName = $HostFQDN
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
function Get-PSIWindowsSecurityEvent {
<#
    .SYNOPSIS

        Returns detailed Security Event information

        Author: Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

#>
    Param
    (
        [Parameter(Mandatory=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [Parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=1)]
        $EndTime = [DateTime]::Now,

        [switch]
        $ReturnHashtables
    )

    Begin
    {
        <# *** TODO ***
        - service added/deleted/started
        - Process logging... Maybe only log interesting processes that are executed instead of grabbing all processes?
        - Scheduled Task creations/deletions. Runs? (Applications Services Logs\Microsoft\Windows\TaskScheduler)
        - Remote Desktop Connections (Applications Services Logs\Microsoft\Windows\TerminalServices-RemoteConnectionManager\Operational - EID 1149).  Note this does not indicate a login. It only indicates a connection
        - Remote Desktop Logons/Disconnections (Applications Services Logs\Microsoft\Windows\TerminalServices-LocalSessionManager\Operational - EID 21,24).  This isn't very chatty, so you could probably pull them all.
        - Symantec Enpoint Protection Client log
        - BITS Transfers (Applications Services Logs\Microsoft\Windows\Bits-Client  EID 59).  Historically used to exfil data/persistence
        #>

        $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}

        $XPathFilter = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
        </Select>

        <!-- RDP logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ] 
                    and 
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4634)
                    and 
                    TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
            and
            *[EventData[Data[@Name='LogonType']='10']]
            and
            (
                *[EventData[Data[5]='10']]
                or
                *[EventData[Data[@Name='AuthenticationPackageName']='Negotiate']]
            )
        </Select>

        <!-- Local user created or deleted -->
        <Select Path="Security">
            *[
                System[
                    (EventID=4726 or EventID=4720)
                    and 
                    TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
        </Select>

        <!-- Local admins changed -->
        <Select Path="Security">
            *[
                System[
                    (EventID=4732 or EventID=4733)
                    and 
                    TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName']='Administrators']]
        </Select>

        <!-- Event log cleared -->
        <Select Path="Security">
            *[
                System[
                    (EventID=1102)
                    and
                    TimeCreated[
					    @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
				    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0') 
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
  
        function Convert-SidToName {
        <#
            .SYNOPSIS
    
                Converts a security identifier (SID) to a group/user name. Graciously taken from @harmj0y's PowerView project.

            .PARAMETER SID
    
                The SID to convert.

            .EXAMPLE

                PS C:\> Convert-SidToName S-1-5-21-2620891829-2411261497-1773853088-1105
        #>
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
                [String]
                $SID
            )

            process {
                try {
                    $SID2 = $SID.trim('*')

                    # try to resolve any built-in SIDs first
                    #   from https://support.microsoft.com/en-us/kb/243330
                    Switch ($SID2)
                    {
                        'S-1-0'         { 'Null Authority' }
                        'S-1-0-0'       { 'Nobody' }
                        'S-1-1'         { 'World Authority' }
                        'S-1-1-0'       { 'Everyone' }
                        'S-1-2'         { 'Local Authority' }
                        'S-1-2-0'       { 'Local' }
                        'S-1-2-1'       { 'Console Logon ' }
                        'S-1-3'         { 'Creator Authority' }
                        'S-1-3-0'       { 'Creator Owner' }
                        'S-1-3-1'       { 'Creator Group' }
                        'S-1-3-2'       { 'Creator Owner Server' }
                        'S-1-3-3'       { 'Creator Group Server' }
                        'S-1-3-4'       { 'Owner Rights' }
                        'S-1-4'         { 'Non-unique Authority' }
                        'S-1-5'         { 'NT Authority' }
                        'S-1-5-1'       { 'Dialup' }
                        'S-1-5-2'       { 'Network' }
                        'S-1-5-3'       { 'Batch' }
                        'S-1-5-4'       { 'Interactive' }
                        'S-1-5-6'       { 'Service' }
                        'S-1-5-7'       { 'Anonymous' }
                        'S-1-5-8'       { 'Proxy' }
                        'S-1-5-9'       { 'Enterprise Domain Controllers' }
                        'S-1-5-10'      { 'Principal Self' }
                        'S-1-5-11'      { 'Authenticated Users' }
                        'S-1-5-12'      { 'Restricted Code' }
                        'S-1-5-13'      { 'Terminal Server Users' }
                        'S-1-5-14'      { 'Remote Interactive Logon' }
                        'S-1-5-15'      { 'This Organization ' }
                        'S-1-5-17'      { 'This Organization ' }
                        'S-1-5-18'      { 'Local System' }
                        'S-1-5-19'      { 'NT Authority' }
                        'S-1-5-20'      { 'NT Authority' }
                        'S-1-5-80-0'    { 'All Services ' }
                        'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                        'S-1-5-32-545'  { 'BUILTIN\Users' }
                        'S-1-5-32-546'  { 'BUILTIN\Guests' }
                        'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                        'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                        'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                        'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                        'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                        'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                        'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                        'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                        'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                        'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                        'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                        'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                        'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                        'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                        'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                        'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                        'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                        'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                        'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                        'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                        'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                        'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                        'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                        'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                        Default { 
                            $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                            $Obj.Translate( [System.Security.Principal.NTAccount]).Value
                        }
                    }
                }
                catch {
                    # Write-Warning "Invalid SID: $SID"
                    $SID
                }
            }
        }
    }

    Process
    {
        Get-WinEvent -FilterXPath $XPathFilter -LogName Security -MaxEvents 3000 | ForEach-Object {
            $Event = $null
            $Properties = $null
            $Output = $null

            $Event = $_
            $Properties = $Event.Properties
            switch($Event.Id)
            {
                # Event log cleared
                1102
                {
                    $Output = @{
                        TimeCreated       = $Event.TimeCreated
                        EventId           = $Event.Id
                        SubjectUserSid    = $Properties[0].Value.ToString()
                        SubjectUserName   = $Properties[1].Value
                        SubjectDomainName = $Properties[2].Value
                        SubjectLogonId    = $Properties[3].Value
                        ComputerName      = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'LogClearedEvent')
                    }

                    break
                }

                # Logon event
                4624 
                {
                    $Output = @{
                        TimeCreated               = $Event.TimeCreated
                        EventId                   = $Event.Id
                        SubjectUserSid            = $Properties[0].Value.ToString()
                        SubjectUserName           = $Properties[1].Value
                        SubjectDomainName         = $Properties[2].Value
                        SubjectLogonId            = $Properties[3].Value
                        TargetUserSid             = $Properties[4].Value.ToString()
                        TargetUserName            = $Properties[5].Value
                        TargetDomainName          = $Properties[6].Value
                        TargetLogonId             = $Properties[7].Value
                        LogonType                 = $Properties[8].Value
                        LogonProcessName          = $Properties[9].Value
                        AuthenticationPackageName = $Properties[10].Value
                        WorkstationName           = $Properties[11].Value
                        LogonGuid                 = $Properties[12].Value
                        TransmittedServices       = $Properties[13].Value
                        LmPackageName             = $Properties[14].Value
                        KeyLength                 = $Properties[15].Value
                        ProcessId                 = $Properties[16].Value
                        ProcessName               = $Properties[17].Value
                        IpAddress                 = $Properties[18].Value
                        IpPort                    = $Properties[19].Value
                        ImpersonationLevel        = $Properties[20].Value
                        RestrictedAdminMode       = $Properties[21].Value
                        TargetOutboundUserName    = $Properties[22].Value
                        TargetOutboundDomainName  = $Properties[23].Value
                        VirtualAccount            = $Properties[24].Value
                        TargetLinkedLogonId       = $Properties[25].Value
                        ElevatedToken             = $Properties[26].Value
                        ComputerName              = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'LogonEvent')
                    }

                    break
                }

                # RDP Logoff event
                4634 
                {
                    $Output = @{
                        TimeCreated      = $Event.TimeCreated
                        EventId          = $Event.Id
                        TargetUserSid    = $Properties[0].Value.ToString()
                        TargetUserName   = $Properties[1].Value
                        TargetDomainName = $Properties[2].Value
                        TargetLogonId    = $Properties[3].Value
                        LogonType        = $Properties[4].Value.ToString()
                        ComputerName     = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'LogoffEvent')
                    }

                    break
                }

                # Logon with explicit credential
                4648 
                {
                    # Skip computer logons for now
                    # TODO: Can this be used for silver ticket detection?
                    if(!($Properties[5].Value.EndsWith('$') -and $Properties[11].Value -match 'taskhost\.exe'))
                    {
                        $Output = @{
                            TimeCreated       = $Event.TimeCreated
                            EventId           = $Event.Id
                            SubjectUserSid    = $Properties[0].Value.ToString()
                            SubjectUserName   = $Properties[1].Value
                            SubjectDomainName = $Properties[2].Value
                            SubjectLogonId    = $Properties[3].Value
                            LogonGuid         = $Properties[4].Value.ToString()
                            TargetUserName    = $Properties[5].Value
                            TargetDomainName  = $Properties[6].Value
                            TargetLogonGuid   = $Properties[7].Value
                            TargetServerName  = $Properties[8].Value
                            TargetInfo        = $Properties[9].Value
                            ProcessId         = $Properties[10].Value
                            ProcessName       = $Properties[11].Value
                            IpAddress         = $Properties[12].Value
                            IpPort            = $Properties[13].Value
                            ComputerName      = $HostFQDN
                        }

                        if(-not $ReturnHashtables) {
                            $Output = New-Object PSObject -Property $Output
                            $Output.PSObject.TypeNames.Insert(0, 'ExplicitCredentialLogonEvent')
                        }

                        break
                    }
                }

                # New local account
                4720
                {
                    $Output = @{
                        TimeCreated         = $Event.TimeCreated
                        EventId             = $Event.Id
                        TargetUserName      = $Properties[0].Value
                        TargetDomainName    = $Properties[1].Value
                        TargetSid           = $Properties[2].Value.ToString()
                        SubjectUserSid      = $Properties[3].Value.ToString()
                        SubjectUserName     = $Properties[4].Value
                        SubjectDomainName   = $Properties[5].Value
                        SubjectLogonId      = $Properties[6].Value
                        PrivilegeList       = $Properties[7].Value
                        SamAccountName      = $Properties[8].Value
                        DisplayName         = $Properties[9].Value
                        UserPrincipalName   = $Properties[10].Value
                        HomeDirectory       = $Properties[11].Value
                        HomePath            = $Properties[12].Value
                        ScriptPath          = $Properties[13].Value
                        ProfilePath         = $Properties[14].Value
                        UserWorkstations    = $Properties[15].Value
                        PasswordLastSet     = $Properties[16].Value
                        AccountExpires      = $Properties[17].Value
                        PrimaryGroupId      = $Properties[18].Value
                        AllowedToDelegateTo = $Properties[19].Value
                        OldUacValue         = $Properties[20].Value
                        NewUacValue         = $Properties[21].Value
                        UserAccountControl  = $Properties[22].Value
                        UserParameters      = $Properties[23].Value
                        SidHistory          = $Properties[24].Value
                        LogonHours          = $Properties[25].Value
                        ComputerName        = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'LocalAccountCreatedEvent')
                    }

                    break
                }

                # Local account deleted
                4726
                {
                    $Output = @{
                        TimeCreated      = $Event.TimeCreated
                        EventId          = $Event.Id
                        TargetUserName    = $Properties[0].Value
                        TargetDomainName  = $Properties[1].Value
                        TargetSid         = $Properties[2].Value.ToString()
                        SubjectUserSid    = $Properties[3].Value.ToString()
                        SubjectUserName   = $Properties[4].Value
                        SubjectDomainName = $Properties[5].Value
                        SubjectLogonId    = $Properties[6].Value
                        PrivilegeList     = $Properties[7].Value
                        ComputerName      = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'LocalAccountDeletedEvent')
                    }

                    break
                }

                # Local admins changed
                { @(4732,4733) -contains $_ }
                {
                    $MemberName = $Properties[0].Value
                    if($MemberName -eq '-' -and ($Properties[1].Value.ToString()) -match '^S-\d-(\d+-){1,14}\d+$')
                    {
                        $MemberName = Convert-SidToName ($Properties[1].Value.ToString())
                    }

                    if($_ -eq 4732) { $Action = 'AddToGroup' } else {$Action = 'DeleteFromGroup'}
                    
                    $Output = @{
                        TimeCreated       = $Event.TimeCreated
                        EventId           = $Event.Id
                        MemberName        = $MemberName
                        MemberSid         = $Properties[1].Value.ToString()
                        TargetUserName    = $Properties[2].Value
                        TargetDomainName  = $Properties[3].Value
                        TargetSid         = $Properties[4].Value.ToString()
                        SubjectUserSid    = $Properties[5].Value.ToString()
                        SubjectUserName   = $Properties[6].Value
                        SubjectDomainName = $Properties[7].Value
                        SubjectLogonId    = $Properties[8].Value
                        PrivilegeList     = $Properties[9].Value
                        Action            = $Action
                        ComputerName      = $HostFQDN
                    }

                    if(-not $ReturnHashtables) {
                        $Output = New-Object PSObject -Property $Output
                        $Output.PSObject.TypeNames.Insert(0, 'SecurityGroupChanged')
                    }

                    break
                }

                default
                {
                    Write-Error "No handler exists for EID $($Event.Id)"
                }

            }
            $Output
        }
    }
}
#endregion PSInvestigate cmdlets


function Start-PSIScan {
    [CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true)]
    [string]
    $ComputerName,

    [Parameter(Mandatory=$true)]
    [string]
    $Uri,

    [Parameter(Mandatory=$true)]
    [Guid]
    $ResultId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('CachedDns','LoadedModule','MasterBootRecord','NetworkConnection','Prefetch','FullProcess','ScheduledTask','FullService','SimpleNamedPipe','SecurityEvent')]
    [string[]]
    $ScanType
    )

    Begin {
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
        $Serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer

        $ErrorList = New-Object 'System.Collections.Generic.Dictionary[string,string]'

        $Output = @{
            computerName = $ComputerName
            scanType = $null
            resultId = $ResultId
            resultDate = $null
            data = $null
        }
    }

    Process {
        switch($ScanType) {
            'CachedDns' {
                try {
                    $Output.scanType = 'CachedDns'
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSICachedDnsEntry -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $_
                    $ErrorList.Add('CachedDns', $_)
                    Write-Error "Cached Dns scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'SimpleNamedPipe' {
                try {
                    $Output.scanType = 'SimpleNamedPipe'
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSISimpleNamedPipe -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('SimplePipeList', $_)
                    Write-Error "Simple Pipe List scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'MasterBootRecord' {
                try {
                    $Output.scanType = 'MasterBootRecord'
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIMasterBootRecord -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('MasterBootRecord', $_)
                    Write-Error "Master boot record scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'NetworkConnection' {
                try {
                    $Output.scanType = 'NetworkConnection'
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSINetworkConnection -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('NetworkConnection', $_)
                    Write-Error "Network Connection scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'LoadedModule' {
                try {
                    $Output.scanType = 'LoadedModule'
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSILoadedModuleHashes -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri $Uri -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('LoadedModules', $_)
                    Write-Error "Loaded Module scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }
        <#
            'Prefetch' {
                try {
                    $Output.scanType = "Prefetch"
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIPrefetch -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri $Uri -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                } catch {
                    #$ErrorList.Add('Prefetech', $_)
                    Write-Error "Prefetch scan failed on $ComputerName", $_
                }
            }
        #>

            'FullProcess' {
                try {
                    $Output.scanType = "FullProcess"
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIProcess -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri $Uri -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('FullProcess', $_)
                    Write-Error "Full Process scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'ScheduledTask' {
                try {
                    $Output.scanType = "ScheduledTask"
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIScheduledTask -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('ScheduledTask', $_)
                    Write-Error "Scheduled Task scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'FullService' {
                try {
                    $Output.scanType = "FullService"
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIService -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('FullService', $_)
                    Write-Error "Full Service scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }

            'SecurityEvent' {
                try {
                    $Output.scanType = "SecurityEvent"
                    $Output.resultDate = [DateTime]::UtcNow
                    $Output.data = Get-PSIWindowsSecurityEvent -ReturnHashtables
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/success/$($ResultId)"
                } catch {
                    $ErrorList.Add('SecurityEvent', $_)
                    Write-Error "Windows Security Event scan failed on $ComputerName", $_
                    Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/scan/failed/$($ResultId)"
                }
            }
        } #End Switch block
    } # End Process block

    End {
        
        $Output.scanType = 'Error'
        $Output.resultDate = [DateTime]::UtcNow
        #$Output.data = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        #Invoke-WebRequest2 -Method Post -Uri "$($Uri)/ace/result/$($ResultId)" -Body $Serializer.Serialize($Output) -ContentType 'application/json'
    }
}
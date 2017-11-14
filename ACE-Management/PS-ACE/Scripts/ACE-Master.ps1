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
        $Thumbprint,

        [Parameter()]
        [ValidateSet('All','AccessToken','ArpCache','AtomTable','FullProcess','FullService','InjectedThread','KerberosTicket','LogonSession','MasterBootRecord','NetworkConnection','RegistryAutoRun','ScheduledTask','SecurityPackage','SimpleNamedPipe','WmiEventSubscription')]
        [string[]]
        $ScanType = 'All'

    )

    $HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
    $ResultDate = (Get-Date).ToString("yyyyMMddThhmmssmsmsZ")

    $scans = New-Object -TypeName System.Collections.Generic.List['Hashtable']
    
    if($ScanType -contains 'All' -or $ScanType -contains 'AccessToken')
    {
        $scans.Add(@{Function = 'Get-AccessToken'; RoutingKey = 'siem'; ScanType = 'AccessToken'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'ArpCache')
    {
        $scans.Add(@{Function = 'Get-ArpCache -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'ArpCache'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'AtomTable')
    {
        $scans.Add(@{Function = 'Get-AtomTable -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'AtomTable'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'FullProcess')
    {
        $scans.Add(@{Function = 'Get-PSIProcess -ReturnHashtables'; RoutingKey = 'hash.siem'; ScanType = 'FullProcess'})
    }    
    if($ScanType -contains 'All' -or $ScanType -contains 'FullService')
    {
        $scans.Add(@{Function = 'Get-PSIService -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'FullService'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'InjectedThread')
    {    
        $scans.Add(@{Function = 'Get-InjectedThread'; RoutingKey = 'siem'; ScanType = 'InjectedThread'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'KerberosTicket')
    {
        $scans.Add(@{Function = 'Get-KerberosTicketCache'; RoutingKey = 'siem'; ScanType = 'KerberosTicket'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'LogonSession')
    {
        $scans.Add(@{Function = 'Get-LogonSession -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'LogonSession'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'MasterBootRecord')
    {
        $scans.Add(@{Function = 'Get-MasterBootRecord -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'MasterBootRecord'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'NetworkConnection')
    {
        $scans.Add(@{Function = 'Get-NetworkConnection -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'NetworkConnection'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'RegistryAutoRun')
    {
        $scans.Add(@{Function = 'Get-RegistryAutoRun'; RoutingKey = 'siem'; ScanType = 'RegistryAutoRun'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'ScheduledTask')
    {    
        $scans.Add(@{Function = 'Get-PSIScheduledTask -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'ScheduledTask'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'SecurityPackage')
    {
        $scans.Add(@{Function = 'Get-SecurityPackage -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'SecurityPackage'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'SimpleNamedPipe')
    {
        $scans.Add(@{Function = 'Get-SimpleNamedPipe -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'SimpleNamedPipe'})
    }
    if($ScanType -contains 'All' -or $ScanType -contains 'WmiEventSubscription')
    {
        $scans.Add(@{Function = 'Get-WmiEventSubscription -ReturnHashtables'; RoutingKey = 'siem'; ScanType = 'WmiEventSubscription'})
    }

    foreach($scan in $scans)
    {
        $dataList = New-Object -TypeName System.Collections.Generic.List['string']

        Write-Host -NoNewline -ForegroundColor Yellow -Object '[!] '
        Write-Host "[$($HostFQDN)] $($scan.ScanType)"

        foreach($o in (Invoke-Expression $scan.Function))
        {
            $o.Add('ComputerName', $HostFQDN)
            $o.Add('ScanType', $scan.ScanType)
            $o.Add('SweepId', $SweepId)
            $o.Add('ScanId', $ScanId)
            $o.Add('ResultDate', $ResultDate)

            $message = ConvertTo-JsonV2 -InputObject $o
            $dataList.Add($message)
        }

        $props = @{
            ComputerName = $HostFQDN
            ScanType     = $scan.ScanType
            RoutingKey   = $scan.RoutingKey
            ResultDate   = $ResultDate
            ScanId       = $ScanId
            Data         = $dataList.ToArray()
        }

        $body = (ConvertTo-JsonV2 -InputObject $props)
        
        #Write-Output $body
        Invoke-AceWebRequest -Thumbprint $Thumbprint -Uri "$($Uri)/ace/result/$($SweepId)" -Body $body
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

#region Collection Functions
function Get-AccessToken
{
    param
    (
        [Parameter()]
        [System.Diagnostics.Process[]]
        $Process
    )

    begin
    {
        <#
        try
        {
            Get-System
        }
        catch
        {
            Write-Error "Unable to Impersonate NT AUTHORITY\SYSTEM token"
        }
        #>

        if(-not ($PSBoundParameters.ContainsKey('Process')))
        {
            $Process = Get-Process
        }
    }

    process
    {
        foreach($proc in $Process)
        {
            if($proc.Id -ne 0 -and $proc.Id -ne 4 -and $proc.Id -ne $PID)
            {
                $ProcessGuid = [Guid]::NewGuid()

                try
                {
                    $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION
                }
                catch
                {
                    if($_.Exception.Message -ne "OpenProcess Error: The parameter is incorrect")
                    {
                        Write-Warning "Process Handle: $($proc.Id)"
                        Write-Warning $_.Exception.Message
                    }
                }

                try
                {
                    $hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
                }
                catch
                {
                    #Write-Warning "Process Token Handle: $($proc.Id)"
                    #Write-Warning $_.Exception.Message
                }

                try
                {
                    $TokenUser = GetTokenInformation -TokenInformationClass TokenUser -TokenHandle $hToken
                    $TokenGroup = GetTokenInformation -TokenInformationClass TokenGroups -TokenHandle $hToken
                    $TokenOwner = GetTokenInformation -TokenInformationClass TokenOwner -TokenHandle $hToken
                    $TokenIntegrityLevel = GetTokenInformation -TokenInformationClass TokenIntegrityLevel -TokenHandle $hToken
                    $TokenType = GetTokenInformation -TokenInformationClass TokenType -TokenHandle $hToken
                    $TokenSessionId = GetTokenInformation -TokenInformationClass TokenSessionId -TokenHandle $hToken
                    $TokenOrigin = GetTokenInformation -TokenInformationClass TokenOrigin -TokenHandle $hToken
                    $TokenPrivileges = (GetTokenInformation -TokenInformationClass TokenPrivileges -TokenHandle $hToken | Where-Object {$_.Attributes -like "*ENABLED*"} | select -ExpandProperty Privilege) -join ";"
                    $TokenElevation = GetTokenInformation -TokenInformationClass TokenElevation -TokenHandle $hToken
                    $TokenElevationType = GetTokenInformation -TokenInformationClass TokenElevationType -TokenHandle $hToken

                    $props = @{
                        ProcessGuid = $ProcessGuid
                        ProcessName = $proc.Name
                        ProcessId = $proc.Id
                        ThreadId = 0
                        UserSid = $TokenUser.Sid.ToString()
                        UserName = $TokenUser.Name.Value
                        OwnerSid = $TokenOwner.Sid.ToString()
                        OwnerName = $TokenOwner.Name.Value
                        #Groups = $TokenGroup
                        IntegrityLevel = $TokenIntegrityLevel.ToString()
                        Type = $TokenType.ToString()
                        ImpersonationLevel = 'None'
                        SessionId = $TokenSessionId -as ([Int32])
                        Origin = $TokenOrigin -as ([Int32])
                        Privileges = $TokenPrivileges
                        IsElevated = $TokenElevation -as ([bool])
                        ElevationType = $TokenElevationType.ToString()
                    }

                    Write-Output $props

                    CloseHandle -Handle $hProcess
                    CloseHandle -Handle $hToken
                }
                catch
                {
                    #Write-Warning "Process Token Query: $($proc.Id)"
                    #Write-Warning $_.Exception.Message
                }

                foreach($thread in $proc.Threads)
                {
                    try
                    {
                        $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_QUERY_LIMITED_INFORMATION

                        try
                        {
                            $hToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY

                            $TokenUser = GetTokenInformation -TokenInformationClass TokenUser -TokenHandle $hToken
                            $TokenGroup = GetTokenInformation -TokenInformationClass TokenGroups -TokenHandle $hToken
                            $TokenOwner = GetTokenInformation -TokenInformationClass TokenOwner -TokenHandle $hToken
                            $TokenIntegrityLevel = GetTokenInformation -TokenInformationClass TokenIntegrityLevel -TokenHandle $hToken
                            $TokenType = GetTokenInformation -TokenInformationClass TokenType -TokenHandle $hToken
                            if($TokenType -eq 'TokenImpersonation')
                            {
                                $TokenImpersonationLevel = GetTokenInformation -TokenInformationClass TokenImpersonationLevel -TokenHandle $hToken
                            }
                            else
                            {
                                $TokenImpersonationLevel = 'None'
                            }
                            $TokenSessionId = GetTokenInformation -TokenInformationClass TokenSessionId -TokenHandle $hToken
                            $TokenOrigin = GetTokenInformation -TokenInformationClass TokenOrigin -TokenHandle $hToken
                            $TokenPrivileges = (GetTokenInformation -TokenInformationClass TokenPrivileges -TokenHandle $hToken | Where-Object {$_.Attributes -like "*ENABLED*"} | select -ExpandProperty Privilege) -join ";"
                            $TokenElevation = GetTokenInformation -TokenInformationClass TokenElevation -TokenHandle $hToken
                            $TokenElevationType = GetTokenInformation -TokenInformationClass TokenElevationType -TokenHandle $hToken
                        
                            $props = @{
                                ProcessGuid = $ProcessGuid
                                ProcessName = $proc.Name
                                ProcessId = $proc.Id
                                ThreadId = $thread.Id
                                UserSid = $TokenUser.Sid.ToString()
                                UserName = $TokenUser.Name.Value
                                OwnerSid = $TokenOwner.Sid.ToString()
                                OwnerName = $TokenOwner.Name.Value
                                #Groups = $TokenGroup
                                IntegrityLevel = $TokenIntegrityLevel.ToString()
                                Type = $TokenType.ToString()
                                ImpersonationLevel = $TokenImpersonationLevel.ToString()
                                SessionId = $TokenSessionId -as ([Int32])
                                Origin = $TokenOrigin -as ([Int32])
                                Privileges = $TokenPrivileges
                                IsElevated = $TokenElevation -as ([bool])
                                ElevationType = $TokenElevationType.ToString()
                            }

                            Write-Output $props    

                            CloseHandle -Handle $hThread
                            CloseHandle -Handle $hToken
                        }
                        catch
                        {
                            if($_.Exception.Message -ne 'OpenThreadToken Error: An attempt was made to reference a token that does not exist')
                            {
                                #Write-Warning "Thread Token Handle"
                                #Write-Warning $_.Exception.Message
                            }
                        }
                    }
                    catch
                    {
                        #Write-Warning "Thread Handle: [Proc] $($proc.Id) [THREAD] $($thread.Id)"
                        #Write-Warning $_.Exception.Message
                    }
                }
            }
        }
    }

    end
    {
        RevertToSelf
    }
}

function Get-ArpCache
{
    <#
    .SYNOPSIS

    Gets the contents of the ARP Cache.

    .DESCRIPTION
    
    The Get-ArpCache function retreives the contents of the system's ARP Cache. The ARP Cache contains cached mappings from IPv4 Addresses to their Physical Address (MAC Address).

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE

    Get-ArpCache

    AdapterIndex       : 1
    PhysicalAddress    : 00-00-00-00-00-00
    IpAddress          : 224.0.0.22
    Type               : STATIC
    AdapterServiceName : e1iexpress
    AdapterMacAddress  : 00:0C:29:3A:DF:39
    AdapterType        : Ethernet 802.3
    AdapterName        : Intel(R) 82574L Gigabit Network Connection
    AdapterSpeed       : 1000000000

    AdapterIndex       : 1
    PhysicalAddress    : 00-00-00-00-00-00
    IpAddress          : 224.0.0.252
    Type               : STATIC
    AdapterServiceName : e1iexpress
    AdapterMacAddress  : 00:0C:29:3A:DF:39
    AdapterType        : Ethernet 802.3
    AdapterName        : Intel(R) 82574L Gigabit Network Connection
    AdapterSpeed       : 1000000000

    AdapterIndex       : 1
    PhysicalAddress    : 00-00-00-00-00-00
    IpAddress          : 239.255.255.250
    Type               : STATIC
    AdapterServiceName : e1iexpress
    AdapterMacAddress  : 00:0C:29:3A:DF:39
    AdapterType        : Ethernet 802.3
    AdapterName        : Intel(R) 82574L Gigabit Network Connection
    AdapterSpeed       : 1000000000
    #>

    param
    (
        [Parameter()]
        [switch]
        $ReturnHashtables
    )

    $Entries = GetIpNetTable
    
    foreach($Entry in $Entries)
    {
        $Adapter = Get-WmiObject -Class win32_networkadapter -Filter "DeviceID = $($Entry.AdapterIndex)"
        
        $Entry.Add('AdapterServiceName', $Adapter.ServiceName)
        $Entry.Add('AdapterMacAddress', $Adapter.MACAddress)
        $Entry.Add('AdapterType', $Adapter.AdapterType)
        $Entry.Add('AdapterName', $Adapter.Name)
        $Entry.Add('AdapterSpeed', $Adapter.Speed)
        
        if($ReturnHashtables)
        {
            Write-Output $Entry
        }
        else
        {
            New-Object -TypeName psobject -Property $Entry
        }
    }
}

function Get-AtomTable
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [UInt16]
        $AtomIndex,

        [Parameter()]
        [switch]
        $ReturnHashtables
    )

    if($PSBoundParameters.ContainsKey('AtomIndex'))
    {
        GlobalGetAtomName -AtomIndex $AtomIndex
    }
    else
    {
        $atomList = New-Object -TypeName System.Collections.Generic.List['string']

        for($i = 0xC000; $i -lt [UInt16]::MaxValue; $i++)
        {
            try
            {
                $atomname = GlobalGetAtomName -AtomIndex $i -ErrorAction Stop
            
                $props = @{
                    Index = $i
                    Name = $atomname.ToString()
                }

                if($ReturnHashtables)
                {
                    Write-Output $props
                }
                else
                {
                    New-Object -TypeName psobject -Property $props
                }
            }
            catch
            {

            }
        }
    }
}

function Get-InjectedThread
{
    <# 
    
    .SYNOPSIS 
    
    Looks for threads that were created as a result of code injection.
    
    .DESCRIPTION
    
    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution. Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.
    
    Common memory injection techniques that *can* be caught using this method include:
    - Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Reflective DLL Injection
    - Process Hollowing

    NOTE: Nothing in security is a silver bullet. An attacker could modify their tactics to avoid detection using this methodology.
    
    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .EXAMPLE 
    
    PS > Get-InjectedThread 

    ProcessName               : ThreadStart.exe
    ProcessId                 : 7784
    Path                      : C:\Users\tester\Desktop\ThreadStart.exe
    KernelPath                : C:\Users\tester\Desktop\ThreadStart.exe
    CommandLine               : "C:\Users\tester\Desktop\ThreadStart.exe"
    PathMismatch              : False
    ThreadId                  : 14512
    AllocatedMemoryProtection : PAGE_EXECUTE_READWRITE
    MemoryProtection          : PAGE_EXECUTE_READWRITE
    MemoryState               : MEM_COMMIT
    MemoryType                : MEM_PRIVATE
    BasePriority              : 8
    IsUniqueThreadToken       : False
    Integrity                 : MEDIUM_MANDATORY_LEVEL
    Privilege                 : SeChangeNotifyPrivilege
    LogonId                   : 999
    SecurityIdentifier        : S-1-5-21-386661145-2656271985-3844047388-1001
    UserName                  : DESKTOP-HMTGQ0R\SYSTEM
    LogonSessionStartTime     : 3/15/2017 5:45:38 PM
    LogonType                 : System
    AuthenticationPackage     : NTLM
    BaseAddress               : 4390912
    Size                      : 4096
    Bytes                     : {144, 195, 0, 0...}
    
    #>

    [CmdletBinding()]
    param
    (

    )

    $hSnapshot = CreateToolhelp32Snapshot -ProcessId 0 -Flags 4

    $Thread = Thread32First -SnapshotHandle $hSnapshot
    
    do
    {
        $proc = Get-Process -Id $Thread.th32OwnerProcessId -ErrorAction SilentlyContinue
        
        if($Thread.th32OwnerProcessId -ne 0 -and $Thread.th32OwnerProcessId -ne 4)
        {       
            try
            {
                $hThread = OpenThread -ThreadId $Thread.th32ThreadID -DesiredAccess THREAD_QUERY_INFORMATION
            
                if($hThread -ne 0)
                {
                    $BaseAddress = NtQueryInformationThread -ThreadHandle $hThread -ThreadInformationClass ThreadQuerySetWin32StartAddress
                    $hProcess = OpenProcess -ProcessId $Thread.th32OwnerProcessID -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION -InheritHandle $false
                
                    if($hProcess -ne 0)
                    {
                        $memory_basic_info = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $BaseAddress
                        $AllocatedMemoryProtection = $memory_basic_info.AllocationProtect -as $MEMORY_PROTECTION
                        $MemoryProtection = $memory_basic_info.Protect -as $MEMORY_PROTECTION
                        $MemoryState = $memory_basic_info.State -as $MEMORY_STATE
                        $MemoryType = $memory_basic_info.Type -as $MEMORY_TYPE

                        if($MemoryState -eq $MEMORY_STATE::MEM_COMMIT -and $MemoryType -ne $MEMORY_TYPE::MEM_IMAGE)
                        {   
                            $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size 100
                            $proc = Get-WmiObject Win32_Process -Filter "ProcessId = '$($Thread.th32OwnerProcessID)'"
                            $KernelPath = QueryFullProcessImageName -ProcessHandle $hProcess
                            $PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()
                            
                            # check if thread has unique token
                            try
                            {
                                $hThreadToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY
                                
                                $TokenUser = GetTokenInformation -TokenInformationClass TokenUser -TokenHandle $hThreadToken
                                $TokenOwner = GetTokenInformation -TokenInformationClass TokenOwner -TokenHandle $hThreadToken
                                $TokenIntegrityLevel = GetTokenInformation -TokenInformationClass TokenIntegrityLevel -TokenHandle $hThreadToken
                                $TokenType = GetTokenInformation -TokenInformationClass TokenType -TokenHandle $hThreadToken
                                if($TokenType -eq 'TokenImpersonation')
                                {
                                    $TokenImpersonationLevel = GetTokenInformation -TokenInformationClass TokenImpersonationLevel -TokenHandle $hThreadToken
                                }
                                else
                                {
                                    $TokenImpersonationLevel = 'None'
                                }
                                $TokenSessionId = GetTokenInformation -TokenInformationClass TokenSessionId -TokenHandle $hThreadToken
                                $TokenOrigin = GetTokenInformation -TokenInformationClass TokenOrigin -TokenHandle $hThreadToken
                                $TokenPrivileges = (GetTokenInformation -TokenInformationClass TokenPrivileges -TokenHandle $hThreadToken | Where-Object {$_.Attributes -like "*ENABLED*"} | select -ExpandProperty Privilege) -join ";"
                                $TokenElevation = GetTokenInformation -TokenInformationClass TokenElevation -TokenHandle $hThreadToken
                                $TokenElevationType = GetTokenInformation -TokenInformationClass TokenElevationType -TokenHandle $hThreadToken
                            }
                            catch
                            {
                                $hProcessToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
                                
                                $TokenUser = GetTokenInformation -TokenInformationClass TokenUser -TokenHandle $hProcessToken
                                $TokenOwner = GetTokenInformation -TokenInformationClass TokenOwner -TokenHandle $hProcessToken
                                $TokenIntegrityLevel = GetTokenInformation -TokenInformationClass TokenIntegrityLevel -TokenHandle $hProcessToken
                                $TokenType = GetTokenInformation -TokenInformationClass TokenType -TokenHandle $hProcessToken
                                $TokenImpersonationLevel = 'None'
                                $TokenSessionId = GetTokenInformation -TokenInformationClass TokenSessionId -TokenHandle $hProcessToken
                                $TokenOrigin = GetTokenInformation -TokenInformationClass TokenOrigin -TokenHandle $hProcessToken
                                $TokenPrivileges = (GetTokenInformation -TokenInformationClass TokenPrivileges -TokenHandle $hProcessToken | Where-Object {$_.Attributes -like "*ENABLED*"} | select -ExpandProperty Privilege) -join ";"
                                $TokenElevation = GetTokenInformation -TokenInformationClass TokenElevation -TokenHandle $hProcessToken
                                $TokenElevationType = GetTokenInformation -TokenInformationClass TokenElevationType -TokenHandle $hProcessToken
                            }

                            $props = @{
                                ProcessName = [string]$proc.Name
                                ProcessId = $proc.ProcessId
                                Path = [string]$proc.Path
                                KernelPath = [string]$KernelPath
                                CommandLine = [string]$proc.CommandLine
                                PathMismatch = [string]$PathMismatch
                                ThreadId = $Thread.th32ThreadId
                                AllocatedMemoryProtection = [string]$AllocatedMemoryProtection
                                MemoryProtection = [string]$MemoryProtection
                                MemoryState = [string]$MemoryState
                                MemoryType = [string]$MemoryType
                                BasePriority = $Thread.tpBasePri
                                BaseAddress = [string]$BaseAddress
                                Size = $memory_basic_info.RegionSize
                                TokenUserSid = $TokenUser.Sid.ToString()
                                TokenUserName = $TokenUser.Name.Value
                                TokenOwnerSid = $TokenOwner.Sid.ToString()
                                TokenOwnerName = $TokenOwner.Name.Value
                                TokenIntegrity = $TokenIntegrityLevel.ToString()
                                TokenType = $TokenType.ToString()
                                TokenImpersonationLevel = $TokenImpersonationLevel.ToString()
                                TokenSessionId = $TokenSessionId -as ([Int32])
                                TokenOrigin = $TokenOrigin -as ([Int32])
                                TokenPrivilege = $TokenPrivileges
                                TokenElevation = $TokenElevation -as ([bool])
                                TokenElevationType = $TokenElevationType.ToString()
                            }
                        
                            Write-Output $props
                        }
                        CloseHandle($hProcess)
                    }
                }
                CloseHandle($hThread)
            }
            catch
            {

            }
        }
    } while($Kernel32::Thread32Next($hSnapshot, [ref]$Thread))
    CloseHandle($hSnapshot)
}

function Get-KerberosTicketCache
{
    <#
    .SYNOPSIS

    
    .DESCRIPTION


    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE
    
    #>
    
    [CmdletBinding()]
    param
    (

    )
    
    try
    {
        # We need a Handle to LSA to list Kerberos tickets
        # If we want to look at tickets from a session other than our own
        # Then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
        $hLsa = LsaRegisterLogonProcess
    }
    catch
    {
        # If the original call fails then it is likely we don't have SeTcbPrivilege
        # To get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
        Get-System
            
        # We should now have the proper privileges to get a Handle to LSA
        $hLsa = LsaRegisterLogonProcess

        # We don't need our NT AUTHORITY\SYSTEM Token anymore
        # So we can revert to our original token
        RevertToSelf
    }

    # Enumerate all Logon Sessions
    # We need the sessions' LogonIds to enumerate it
    $Sessions = Get-LogonSession

    foreach($Session in $Sessions)
    {
        try
        {
            # Get the tickets from the LSA provider
            $ticket = LsaCallAuthenticationPackage -LsaHandle $hLsa -AuthenticationPackageName MICROSOFT_KERBEROS_NAME_A -LogonId $Session.LogonId 
            
            if($ticket -ne $null)
            {
                # Add properties from the Logon Session to the ticket
                foreach($t in $ticket)
                {
                    $t.Add('SessionLogonId', $Session.LogonId)
                    $t.Add('SessionUserName', $Session.UserName)
                    $t.Add('SessionLogonDomain', $Session.LogonDomain)
                    $t.Add('SessionAuthenticationPackage', $Session.AuthenticationPackage)
                    $t.Add('SessionSid', $Session.Sid.ToString())
                    $t.Add('SessionLogonType', $Session.LogonType)
                    $t.Add('SessionUserPrincipalName', $Session.Upn)
                }


                # Output the ticket
                Write-Output $ticket
            }
        }
        catch
        {

        }
    }

    # Cleanup our LSA Handle
    LsaDeregisterLogonProcess -LsaHandle $hLsa
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
        [Parameter()]
        [switch]
        $ReturnHashtables
    )

    $LogonSessions = LsaEnumerateLogonSessions

    try
    {
        $Sessions = LsaGetLogonSessionData -LuidPtr $LogonSessions.SessionListPointer -SessionCount $LogonSessions.SessionCount
    }
    catch
    {
        
    }

    if($ReturnHashtables)
    {
        Write-Output $Sessions
    }
    else
    {
        foreach($session in $Sessions)
        {
            New-Object -TypeName psobject -Property $session
        }
    }
}

function Get-MasterBootRecord
{
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

function Get-NetworkConnection 
{
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

function Get-PSIProcess
{
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

function Get-PSIScheduledTask 
{
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

function Get-RegistryAutoRun
{
    param
    (
        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Logon,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $BootExecute,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $PrintMonitors,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $NetworkProviders,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $LSAProviders,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $ImageHijacks,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $AppInit,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $KnownDLLs,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Winlogon
    )

    $UserSIDS = (Get-ChildItem -Path Registry::HKU | Where-Object { $_.PSChildName -notmatch 'S-1-5-18|S-1-5-19|S-1-5-20|\.DEFAULT|^.*_Classes$' }).PSChildName

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['Logon'])
    {
        $Category = 'Logon'

        $RunKeyPaths = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )

        $KeyList = New-Object -TypeName System.Collections.Generic.List['string']

        foreach ($RunKey in $RunKeyPaths) { $KeyList.Add("HKLM:\$($RunKey)") }
        foreach ($SID in $UserSIDS) { foreach ($RunKey in $RunKeyPaths) { $KeyList.Add("Registry::HKU\$($SID)\$($RunKey)") } }  

        foreach($result in (Get-RegistryValue -Key $KeyList.ToArray()))
        {
            New-AutoRunEntry -Path $result.Path -Name $result.Name -ImagePath $result.Value -Category $Category
        }

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd' -Value StartupPrograms | New-AutoRunEntry -Category $Category
        Get-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Value VmApplet,Userinit,Shell,TaskMan,AppSetup | New-AutoRunEntry -Category $Category
        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot' -Value AlternateShell | New-AutoRunEntry -Category $Category
        Get-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Value IconServiceLib | New-AutoRunEntry -Category $Category

        $GPExtensionKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'
        Get-ChildItem -Path $GPExtensionKey |
            foreach { Get-RegistryValue -Key "$($GPExtensionKey)\$($_.PSChildName)" -Value DllName | New-AutoRunEntry -Name $_.PSChildName -Category $Category }

        <#
        $null, 'Wow6432Node\' | ForEach-Object {
            $InstalledComponents = "SOFTWARE\$($_)Microsoft\Active Setup\Installed Components"
            Get-RegistryValue -Key "HKLM:\$($InstalledComponents)" -Value StubPath | 
            ForEach-Object {
                $AutoRunEntry = $_ | Get-CSRegistryValue -ValueName '' -ValueType REG_SZ @Timeout
                if ($AutoRunEntry.ValueContent) { $AutoRunEntryName = $AutoRunEntry.ValueContent } else { $AutoRunEntryName = 'n/a' }

                $_ | New-AutoRunsEntry -SubKey $InstalledComponents -AutoRunEntry $AutoRunEntryName -Category $Category
            }
        }
        #>
    }
    
    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['BootExecute'])
    {
        $Category = 'BootExecute'

        $SessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        foreach ($result in (Get-RegistryValue -Key $SessionManager -Value BootExecute,SetupExecute,Execute,S0InitialCommand))
        {
            foreach ($val in $result.Value)
            {
                New-AutoRunEntry -Path $SessionManager -Name $result.Name -ImagePath $val -Category $Category
            }
        }

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control' -Value ServiceControlManagerExtension | New-AutoRunEntry -Category $Category
    }

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['PrintMonitors'])
    {
        $Category = 'PrintMonitors'

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -Value Driver | New-AutoRunEntry -Category $Category
    }

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['NetworkProviders'])
    {
        $Category = 'NetworkProviders'

        $Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
        $NetworkOrder = Get-RegistryValue -Key $Path -Value ProviderOrder
        
        if ($NetworkOrder.Value)
        {
            foreach($val in ($NetworkOrder.Value.Split(',')))
            {
                New-AutoRunEntry -Path $Path -Name ProviderOrder -ImagePath $val -Category $Category
            }
        }
    }

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['LSAProviders'])
    {
        $Category = 'LSAProviders'

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' | New-AutoRunEntry -Category $Category
        
        $Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach($result in (Get-RegistryValue -Key $Path -Value 'Authentication Packages','Notification Packages')) 
        {
            foreach($val in $result.Value)
            {
                New-AutoRunEntry -Path $Path -Name $result.Name -ImagePath $val -Category $Category
            }
        }

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -Value 'Security Packages' | New-AutoRunEntry -Category $Category
    }
    
    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['ImageHijacks']) {
        $Category = 'ImageHijacks'

        $CommonKeys = @(
            'SOFTWARE\Classes\htmlfile\shell\open\command',
            'SOFTWARE\Classes\htafile\shell\open\command',
            'SOFTWARE\Classes\batfile\shell\open\command',
            'SOFTWARE\Classes\comfile\shell\open\command',
            'SOFTWARE\Classes\piffile\shell\open\command',
            'SOFTWARE\Classes\exefile\shell\open\command'
        )

        foreach ($CommonKey in $CommonKeys) {
            Get-RegistryValue -Key "HKLM:\$($CommonKey)" -Value '' | New-AutoRunsEntry -AutoRunEntry $CommonKey.Split('\')[2] -Category $Category

            # Iterate over each local user hive
            foreach ($SID in $HKUSIDs) {
                Get-CSRegistryValue -Hive HKU -SubKey "$SID\$CommonKey" -ValueName '' @CommonArgs @Timeout |
                    New-AutoRunsEntry -AutoRunEntry $CommonKey.Split('\')[2] -Category $Category
            }
        }

        Get-RegistryValue -Key HKLM:\SOFTWARE\Classes\exefile\shell\open\command -Value IsolatedCommand | New-AutoRunEntry -Category $Category

        <#
        $null, 'Wow6432Node\' | ForEach-Object {
            Get-RegistryValue -Key "HKLM:\SOFTWARE\$($_)Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Value Debugger | 
                ForEach-Object {
                    $_ | New-AutoRunsEntry -AutoRunEntry $_.SubKey.Substring($_.SubKey.LastIndexOf('\') + 1) -Category $Category
                }

            Get-RegistryValue -Key "HKLM:\SOFTWARE\$($_)Microsoft\Command Processor" -ValueName Autorun | New-AutoRunsEntry -Category $Category
        }

        $Class_exe = Get-CSRegistryValue -Hive HKLM -SubKey 'HKLM:\SOFTWARE\Classes\.exe' -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

        if ($Class_exe.ValueContent) {
            $OpenCommand = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\$($Class_exe.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

            if ($OpenCommand.ValueContent) {
                $OpenCommand | New-AutoRunsEntry -Hive $Class_exe.Hive -SubKey $Class_exe.SubKey -AutoRunEntry $Class_exe.ValueContent -Category $Category
            }
        }

        $Class_cmd = Get-CSRegistryValue -Hive HKLM -SubKey 'SOFTWARE\Classes\.cmd' -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

        if ($Class_cmd.ValueContent) {
            $OpenCommand = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\$($Class_cmd.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

            if ($OpenCommand.ValueContent) {
                $OpenCommand | New-AutoRunsEntry -Hive $Class_cmd.Hive -SubKey $Class_cmd.SubKey -AutoRunEntry $Class_cmd.ValueContent -Category $Category
            }
        }

        foreach ($SID in $HKUSIDs) {
            Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Microsoft\Command Processor" -ValueName 'Autorun' @CommonArgs @Timeout |
                New-AutoRunsEntry -Category $Category

            $Class_exe = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\.exe" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

            if ($Class_exe.ValueContent) {
                $OpenCommand = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\$($Class_exe.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

                if ($OpenCommand.ValueContent) {
                    $OpenCommand | New-AutoRunsEntry -Hive $Class_exe.Hive -SubKey $Class_exe.SubKey -AutoRunEntry $Class_exe.ValueContent -Category $Category
                }
            }

            $Class_cmd = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\.cmd" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

            if ($Class_cmd.ValueContent) {
                $OpenCommand = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\$($Class_cmd.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout

                if ($OpenCommand.ValueContent) {
                    $OpenCommand | New-AutoRunsEntry -Hive $Class_cmd.Hive -SubKey $Class_cmd.SubKey -AutoRunEntry $Class_cmd.ValueContent -Category $Category
                }
            }
        }
        #>
    }

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['AppInit']) 
    {
        $Category = 'AppInit'

        $null,'Wow6432Node\' | ForEach-Object {
            Get-RegistryValue -Key "HKLM:\SOFTWARE\$($_)Microsoft\Windows NT\CurrentVersion\Windows" -Value 'AppInit_DLLs' | New-AutoRunEntry -Category $Category
            Get-RegistryValue -Key "HKLM:\SOFTWARE\$($_)Microsoft\Command Processor" -Value 'Autorun' | New-AutoRunEntry -Category $Category
        }

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' | New-AutoRunEntry -Category $Category
    }

    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['KnownDLLs']) 
    {
        $Category = 'KnownDLLs'

        Get-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' | New-AutoRunEntry -Category $Category
    }

    <#
    if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['Winlogon']) {
        $Category = 'Winlogon'

        $CmdLine = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\Setup' -ValueName 'CmdLine' @CommonArgs @Timeout

        if ($CmdLine -and $CmdLine.ValueContent) {
            $CmdLine | New-AutoRunsEntry -Category $Category
        }

        'Credential Providers', 'Credential Provider Filters', 'PLAP Providers' |
            ForEach-Object { Get-CSRegistryKey -Hive HKLM -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\$_" @CommonArgs @Timeout } | ForEach-Object {
                $LastBSIndex = $_.SubKey.LastIndexOf('\')
                $ParentKey = $_.SubKey.Substring(0, $LastBSIndex)
                $Guid = $_.SubKey.Substring($LastBSIndex + 1)

                if ($Guid -as [Guid]) {
                    $AutoRunEntry = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\CLSID\$Guid" -ValueName '' -ValueType REG_SZ @CommonArgs @Timeout
                    $InprocServer32 = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\CLSID\$Guid\InprocServer32" -ValueName '' -ValueType REG_EXPAND_SZ @CommonArgs @Timeout

                    New-AutoRunsEntry $_.Hive $ParentKey $AutoRunEntry.ValueContent $InprocServer32.ValueContent $Category $_.PSComputerName
                }
            }

        $BootVer = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\BootVerificationProgram' -ValueName 'ImagePath' @CommonArgs @Timeout

        if ($BootVer) {
            $BootVer | New-AutoRunsEntry -Hive $BootVer.Hive -SubKey "$($BootVer.SubKey)\ImagePath"
        }

        foreach ($SID in $HKUSIDs) {
            $Scrnsave = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName 'Scrnsave.exe' @CommonArgs @Timeout
            if ($Scrnsave) { $Scrnsave | New-AutoRunsEntry }

            $Scrnsave = Get-CSRegistryValue -Hive HKU -SubKey "$SID\Control Panel\Desktop" -ValueName 'Scrnsave.exe' @CommonArgs @Timeout
            if ($Scrnsave) { $Scrnsave | New-AutoRunsEntry }
        }
    }
    #>
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

function Get-SimpleNamedPipe
{ 
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

function Get-WmiEventSubscription
{
    foreach($o in (Get-WmiObject -Namespace root\subscription -Class __EventConsumer))
    {
        $Sid = New-Object System.Security.Principal.SecurityIdentifier(@($o.CreatorSID,$null))
        $UserName = $Sid.Translate([System.Security.Principal.NTAccount])
        
        switch($o.__CLASS)
        {
            ActiveScriptEventConsumer
            {
                $props = @{
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    KillTimeout = $o.KillTimeout
                    MachineName = $o.MachineName
                    MaximumQueueSize = $o.MaximumQueueSize
                    Name = $o.Name
                    ScriptFilename = $o.ScriptFilename
                    ScriptingEngine = $o.ScriptingEngine
                    ScriptText = $o.ScriptText
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
            CommandLineEventConsumer
            {
                $props = @{
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    MachineName = $o.MachineName
                    MaximumQueueSize = $o.MaximumQueueSize
                    CommandLineTemplate = $o.CommandLineTemplate
                    CreateNewConsole = $o.CreateNewConsole
                    CreateNewProcessGroup = $o.CreateNewProcessGroup
                    CreateSeparateWowVdm = $o.CreateSeparateWowVdm
                    CreateSharedWowVdm = $o.CreateSharedWowVdm
                    DesktopName = $o.DesktopName
                    ExecutablePath = $o.ExecutablePath
                    FillAttributes = $o.FillAttributes
                    ForceOffFeedback = $o.ForceOffFeedback
                    ForceOnFeedback = $o.ForceOnFeedback
                    KillTimeout = $o.KillTimeout
                    Name = $o.Name
                    Priority = $o.Priority
                    RunInteractively = $o.RunInteractively
                    ShowWindowCommand = $o.ShowWindowCommand
                    UseDefaultErrorMode = $o.UseDefaultErrorMode
                    WindowTitle = $o.WindowTitle
                    WorkingDirectory = $o.WorkingDirectory
                    XCoordinate = $o.XCoordinate
                    XNumCharacters = $o.XNumCharacters
                    XSize = $o.XSize
                    YCoordinate = $o.YCoordinate
                    YNumCharacters = $o.YNumCharacters
                    YSize = $o.YSize
                    FillAttribute = $o.FillAttribute
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
            LogFileEventConsumer
            {
                $props = @{
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    MachineName = $o.MachineName
                    MaximumQueueSize = $o.MaximumQueueSize
                    Filename = $o.Filename
                    IsUnicode = $o.IsUnicode
                    MaximumFileSize = $o.MaximumFileSize
                    Name = $o.Name
                    Text = $o.Text
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
            NtEventLogEventConsumer
            {
                $props = @{
                    Category = $o.Category
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    EventId = $o.EventID
                    EventType = $o.EventType
                    InsertionStringTemplates = $o.InsertionStringTemplates
                    MachineName = $o.MachineName
                    MaximumQueueSize = $o.MaximumQueueSize
                    Name = $o.Name
                    NameOfRawDataProperty = $o.NameOfRawDataProperty
                    NameOfUserSidProperty = $o.NameOfUserSIDProperty
                    NumberOfInsertionStrings = $o.NumberOfInsertionStrings
                    SourceName = $o.SourceName
                    UncServerName = $o.UNCServerName
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
            SMTPEventConsumer
            {
                $props = @{
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    MachineName = $o.MachineName
                    MaximumQueueSize = $o.MaximumQueueSize
                    BccLine = $o.BccLine
                    CcLine = $o.CcLine
                    FromLine = $o.FromLine
                    HeaderFields = $o.HeaderFields
                    Message = $o.Message
                    Name = $o.Name
                    ReplyToLine = $o.ReplyToLine
                    SMTPServer = $o.SMTPServer
                    Subject = $o.Subject
                    ToLine = $o.ToLine
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
            default
            {
                $props = @{
                    CreatorSid = $Sid.Value
                    CreatorUserName = $UserName
                    Name = $o.Name
                    Class = $o.ClassPath.ClassName
                    ClassPath = $o.ClassPath.Path
                }
            }
        }
        Write-Output $props
    }
}
#endregion Collection Functions

#region Helper Functions
function Get-System
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
        
    .LINK

    .EXAMPLE
    #>

    # Get a Process object for the winlogon process
    # The System.Diagnostics.Process class has a handle property that we can use
    # We know winlogon will be available and is running as NT AUTHORITY\SYSTEM
    $winlogons = Get-Process -Name winlogon

    try
    {
        $proc = $winlogons[0]
    }
    catch
    {
        $proc = $winlogons
    }

    # Open winlogon's Token with TOKEN_DUPLICATE Acess
    # This allows us to make a copy of the token with DuplicateToken
    $hToken = OpenProcessToken -ProcessHandle $proc.Handle -DesiredAccess TOKEN_DUPLICATE
    
    # Make a copy of the NT AUTHORITY\SYSTEM Token
    $hDupToken = DuplicateToken -TokenHandle $hToken
    
    # Apply our Duplicated Token to our Thread
    ImpersonateLoggedOnUser -TokenHandle $hDupToken
    
    # Clean up the handles we created
    CloseHandle -Handle $hToken
    CloseHandle -Handle $hDupToken

    if(-not [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')
    {
        throw "Unable to Impersonate System Token"
    }
}

function Get-RegistryValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $Key,

        [Parameter()]
        [string[]]
        $Value
    )

    foreach($k in $key)
    {
        try
        {
            foreach($val in ((Get-ItemProperty -Path $k -ErrorAction Stop).PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch 'PS(Path|Drive|Provider|ParentPath|ChildName)|\(default\)' }))
            {
                if($PSBoundParameters.ContainsKey('Value'))
                {
                    if($Value -contains $val.Name)
                    {
                        $props = @{
                            Path = $k
                            Name = $val.Name
                            Value = $val.Value
                        }

                        New-Object -TypeName psobject -Property $props
                    }
                }
                else
                {
                    $props = @{
                        Path = $k
                        Name = $val.Name
                        Value = $val.Value
                    }

                    New-Object -TypeName psobject -Property $props
                }
            }
        }
        catch
        {

        }
    }
}

function New-AutoRunEntry
{
    param
    (
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Path,
    
        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Name,

        [Parameter(Position = 2, ValueFromPipelineByPropertyName = $true)]
        [Alias('Value')]
        [string]
        $ImagePath,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Category
    )

    process
    {
        if($ImagePath -ne $null)
        {
            @{
                Path = $Path
                Name = $Name
                ImagePath = $ImagePath
                Type = $Category
            }
        }
    }
}
#endregion Helper Functions

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

$Module = New-InMemoryModule -ModuleName ACE

#region Enums
$KERB_PROTOCOL_MESSAGE_TYPE = psenum $Module KERB_PROTOCOL_MESSAGE_TYPE UInt32 @{ 
    KerbDebugRequestMessage                  = 0
    KerbQueryTicketCacheMessage              = 1
    KerbChangeMachinePasswordMessage         = 2
    KerbVerifyPacMessage                     = 3
    KerbRetrieveTicketMessage                = 4
    KerbUpdateAddressesMessage               = 5
    KerbPurgeTicketCacheMessage              = 6
    KerbChangePasswordMessage                = 7
    KerbRetrieveEncodedTicketMessage         = 8
    KerbDecryptDataMessage                   = 9
    KerbAddBindingCacheEntryMessage          = 10
    KerbSetPasswordMessage                   = 11
    KerbSetPasswordExMessage                 = 12
    KerbVerifyCredentialsMessage             = 13
    KerbQueryTicketCacheExMessage            = 14
    KerbPurgeTicketCacheExMessage            = 15
    KerbRefreshSmartcardCredentialsMessage   = 16
    KerbAddExtraCredentialsMessage           = 17
    KerbQuerySupplementalCredentialsMessage  = 18
    KerbTransferCredentialsMessage           = 19
    KerbQueryTicketCacheEx2Message           = 20
    KerbSubmitTicketMessage                  = 21
    KerbAddExtraCredentialsExMessage         = 22
    KerbQueryKdcProxyCacheMessage            = 23
    KerbPurgeKdcProxyCacheMessage            = 24
    KerbQueryTicketCacheEx3Message           = 25
    KerbCleanupMachinePkinitCredsMessage     = 26
    KerbAddBindingCacheEntryExMessage        = 27
    KerbQueryBindingCacheMessage             = 28
    KerbPurgeBindingCacheMessage             = 29
    KerbQueryDomainExtendedPoliciesMessage   = 30
    KerbQueryS4U2ProxyCacheMessage           = 31
}

$KERB_CACHE_OPTIONS = psenum $Module KERB_CACHE_OPTIONS UInt64 @{
    KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1
    KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2
    KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4
    KERB_RETRIEVE_TICKET_AS_KERB_CRED   = 0x8
    KERB_RETRIEVE_TICKET_WITH_SEC_CRED  = 0x10 
    KERB_RETRIEVE_TICKET_CACHE_TICKET   = 0x20
    KERB_RETRIEVE_TICKET_MAX_LIFETIME   = 0x40
} -Bitfield

$KERB_ENCRYPTION_TYPE = psenum $Module KERB_ENCRYPTION_TYPE UInt32 @{
        reserved0                         = 0
        des_cbc_crc                       = 1
        des_cbc_md4                       = 2
        des_cbc_md5                       = 3
        reserved1                         = 4
        des3_cbc_md5                      = 5
        reserved2                         = 6
        des3_cbc_sha1                     = 7
        dsaWithSHA1_CmsOID                = 9
        md5WithRSAEncryption_CmsOID       = 10
        sha1WithRSAEncryption_CmsOID      = 11
        rc2CBC_EnvOID                     = 12
        rsaEncryption_EnvOID              = 13
        rsaES_OAEP_ENV_OID                = 14
        des_ede3_cbc_Env_OID              = 15
        des3_cbc_sha1_kd                  = 16
        aes128_cts_hmac_sha1_96           = 17
        aes256_cts_hmac_sha1_96           = 18
        aes128_cts_hmac_sha256_128        = 19
        aes256_cts_hmac_sha384_192        = 20
        rc4_hmac                          = 23
        rc4_hmac_exp                      = 24
        camellia128_cts_cmac              = 25
        camellia256_cts_cmac              = 26
        subkey_keymaterial                = 65
}

$KERB_TICKET_FLAGS = psenum $Module KERB_TICKET_FLAGS UInt32 @{
    reserved          = 2147483648
    forwardable       = 0x40000000
    forwarded         = 0x20000000
    proxiable         = 0x10000000
    proxy             = 0x08000000
    may_postdate      = 0x04000000
    postdated         = 0x02000000
    invalid           = 0x01000000
    renewable         = 0x00800000
    initial           = 0x00400000
    pre_authent       = 0x00200000
    hw_authent        = 0x00100000
    ok_as_delegate    = 0x00040000
    name_canonicalize = 0x00010000
    cname_in_pa_data  = 0x00040000
    enc_pa_rep        = 0x00010000
    reserved1         = 0x00000001
} -Bitfield

$LuidAttributes = psenum $Module LuidAttributes UInt32 @{
    DISABLED                        = 0x00000000
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED            = 0x00000002
    SE_PRIVILEGE_REMOVED            = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS    = 2147483648
} -Bitfield

$MEMORY_PROTECTION = psenum $Module MEMORY_PROTECTION UInt32 @{
    PAGE_NOACCESS          = 0x00000001
    PAGE_READONLY          = 0x00000002
    PAGE_READWRITE         = 0x00000004
    PAGE_WRITECOPY         = 0x00000008
    PAGE_EXECUTE           = 0x00000010
    PAGE_EXECUTE_READ      = 0x00000020
    PAGE_EXECUTE_READWRITE = 0x00000040
    PAGE_EXECUTE_WRITECOPY = 0x00000080
    PAGE_GUARD             = 0x00000100
    PAGE_NOCACHE           = 0x00000200
    PAGE_WRITECOMBINE      = 0x00000400
    PAGE_TARGETS_NO_UPDATE = 0x40000000
} -Bitfield

$MEMORY_STATE = psenum $Module MEMORY_STATE UInt32 @{
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE    = 0x10000
} -Bitfield

$MEMORY_TYPE = psenum $Module MEMORY_TYPE UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED  = 0x40000
    MEM_IMAGE   = 0x1000000
} -Bitfield

$MIB_IPNET_TYPE = psenum $Module MIB_IPNET_TYPE UInt32 @{
    OTHER   = 1
    INVALID = 2
    DYNAMIC = 3
    STATIC  = 4
}

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SC_SERVICE_TAG_QUERY_TYPE = psenum $Module SC_SERVICE_TAG_QUERY_TYPE UInt16 @{
    ServiceNameFromTagInformation = 1
    ServiceNamesReferencingModuleInformation = 2
    ServiceNameTagMappingInformation = 3
}

$SE_GROUP = psenum $Module SE_GROUP UInt32 @{
    DISABLED           = 0x00000000
    MANDATORY          = 0x00000001
    ENABLED_BY_DEFAULT = 0x00000002
    ENABLED            = 0x00000004
    OWNER              = 0x00000008
    USE_FOR_DENY_ONLY  = 0x00000010
    INTEGRITY          = 0x00000020
    INTEGRITY_ENABLED  = 0x00000040
    RESOURCE           = 0x20000000
    LOGON_ID           = 3221225472
} -Bitfield

$SE_PRIVILEGE = psenum $Module SE_PRIVILEGE UInt32 @{
    DISABLED           = 0x00000000
    ENABLED_BY_DEFAULT = 0x00000001
    ENABLED            = 0x00000002
    REMOVED            = 0x00000004
    USED_FOR_ACCESS    = 2147483648
} -Bitfield

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

$SECURITY_IMPERSONATION_LEVEL = psenum $Module SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous      = 0
    SecurityIdentification = 1
    SecurityImpersonation  = 2
    SecurityDelegation     = 3
}

$SECURITY_LOGON_TYPE = psenum $Module SECURITY_LOGON_TYPE UInt32 @{
    Interactive = 2
    Network     = 3
    Batch       = 4
    Service     = 5
    Proxy       = 6
    Unlock      = 7
    NetworkCleartext = 8
    NewCredentials = 9
    RemoteInteractive = 10
    CachedInteractive = 11
    CachedRemoteInteractive = 12
    CachedUnlock = 13
}

$TAG_INFO_LEVEL = psenum $Module TAG_INFO_LEVEL UInt16 @{
    eTagInfoLevelNameFromTag = 1
    eTagInfoLevelNamesReferencingModule = 2
    eTagInfoLevelNameTagMapping = 3
    eTagInfoLevelMax = 4
}

$TCP_STATE = psenum $Module TCP_STATE UInt16 @{
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

$TCP_TABLE_CLASS = psenum $Module TCP_TABLE_CLASS UInt16 @{
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

$TH32CS = psenum $Module TH32CS UInt32 @{
    SNAPHEAPLIST = 0x00000001
    SNAPPROCESS  = 0x00000002
    SNAPTHREAD   = 0x00000004
    SNAPMODULE   = 0x00000008
    SNAPALL      = 0x0000000F
    SNAPMODULE32 = 0x00000010
    INHERIT      = 2147483648
} -Bitfield

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$THREADINFOCLASS = psenum $Module THREADINFOCLASS UInt32 @{
	ThreadBasicInformation          = 0x00
	ThreadTimes                     = 0x01
	ThreadPriority                  = 0x02
	ThreadBasePriority              = 0x03
	ThreadAffinityMask              = 0x04
	ThreadImpersonationToken        = 0x05
	ThreadDescriptorTableEntry      = 0x06
	ThreadEnableAlignmentFaultFixup = 0x07
	ThreadEventPair_Reusable        = 0x08
	ThreadQuerySetWin32StartAddress = 0x09
	ThreadZeroTlsCell               = 0x0A
	ThreadPerformanceCount          = 0x0B
	ThreadAmILastThread             = 0x0C
	ThreadIdealProcessor            = 0x0D
	ThreadPriorityBoost             = 0x0E
	ThreadSetTlsArrayAddress        = 0x0F
	ThreadIsIoPending               = 0x10
	MaxThreadInfoClass              = 0x11
}

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TOKEN_ELEVATION_TYPE = psenum $Module TOKEN_ELEVATION_TYPE UInt32 @{ 
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull    = 2
    TokenElevationTypeLimited = 3
}

$TOKEN_INFORMATION_CLASS = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
    TokenUser                            = 1
    TokenGroups                          = 2
    TokenPrivileges                      = 3
    TokenOwner                           = 4
    TokenPrimaryGroup                    = 5
    TokenDefaultDacl                     = 6
    TokenSource                          = 7
    TokenType                            = 8
    TokenImpersonationLevel              = 9
    TokenStatistics                      = 10
    TokenRestrictedSids                  = 11
    TokenSessionId                       = 12
    TokenGroupsAndPrivileges             = 13
    TokenSessionReference                = 14
    TokenSandBoxInert                    = 15
    TokenAuditPolicy                     = 16
    TokenOrigin                          = 17
    TokenElevationType                   = 18
    TokenLinkedToken                     = 19
    TokenElevation                       = 20
    TokenHasRestrictions                 = 21
    TokenAccessInformation               = 22
    TokenVirtualizationAllowed           = 23
    TokenVirtualizationEnabled           = 24
    TokenIntegrityLevel                  = 25
    TokenUIAccess                        = 26
    TokenMandatoryPolicy                 = 27
    TokenLogonSid                        = 28
    TokenIsAppContainer                  = 29
    TokenCapabilities                    = 30
    TokenAppContainerSid                 = 31
    TokenAppContainerNumber              = 32
    TokenUserClaimAttributes             = 33
    TokenDeviceClaimAttributes           = 34
    TokenRestrictedUserClaimAttributes   = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups                    = 37
    TokenRestrictedDeviceGroups          = 38
    TokenSecurityAttributes              = 39
    TokenIsRestricted                    = 40
    MaxTokenInfoClass                    = 41
}

$TOKENMANDATORYPOLICY = psenum $Module TOKENMANDATORYPOLICY UInt32 @{
    OFF                    = 0x0
    NO_WRITE_UP            = 0x1
    POLICY_NEW_PROCESS_MIN = 0x2
    POLICY_VALID_MASK      = 0x3
}

$TOKEN_TYPE = psenum $Module TOKEN_TYPE UInt32 @{
    TokenPrimary       = 1
    TokenImpersonation = 2
}

$UDP_TABLE_CLASS = psenum $Module UDP_TABLE_CLASS UInt16 @{
    UDP_TABLE_BASIC = 0
    UDP_TABLE_OWNER_PID = 1
    UDP_TABLE_OWNER_MODULE = 2
}
#endregion Enums

#region Structs
$ACL = struct $Module ACL @{
    AclRevision = field 0 Byte
    Sbz1        = field 1 Byte
    AclSize     = field 2 UInt16
    AceCount    = field 3 UInt16
    Sbz2        = field 4 UInt16
}

$LUID = struct $Module LUID @{
    LowPart  = field 0 UInt32
    HighPart = field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LUID_AND_ATTRIBUTES @{
    Luid       = field 0 $LUID
    Attributes = field 1 $SE_PRIVILEGE
}

$LSA_LAST_INTER_LOGON_INFO = struct $Module LSA_LAST_INTER_LOGON_INFO @{
    LastSuccessfulLogon                        = field 0 Int64
    LastFailedLogon                            = field 1 Int64
    FailedAttemptCountSinceLastSuccessfulLogon = field 2 UInt64
}

$LSA_STRING = struct $Module LSA_STRING @{
    Length = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer = field 2 IntPtr
}

$LSA_UNICODE_STRING = struct $Module LSA_UNICODE_STRING @{
    Length        = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer        = field 2 IntPtr
}

$MEMORY_BASIC_INFORMATION = struct $Module MEMORY_BASIC_INFORMATION @{
    BaseAddress       = field 0 UIntPtr
    AllocationBase    = field 1 UIntPtr
    AllocationProtect = field 2 $MEMORY_PROTECTION
    RegionSize        = field 3 UIntPtr
    State             = field 4 $MEMORY_STATE
    Protect           = field 5 $MEMORY_PROTECTION
    Type              = field 6 $MEMORY_TYPE
}

$MIB_IPNETROW = struct $Module MIB_IPNETROW @{
    dwIndex = field 0 UInt32
    dwPhysAddrLen = field 1 UInt32
    bPhysAddr = field 2 byte[] -MarshalAs @('ByValArray', 6)
    dwAddr = field 3 UInt32
    dwType = field 4 UInt32
}

$MIB_UDPROW_OWNER_MODULE = struct $Module MIB_UDPROW_OWNER_MODULE @{
    LocalAddr        = field 0 UInt32 0
    LocalPort        = field 1 UInt32 4
    OwningPid        = field 2 UInt32 8
    CreateTimestamp  = field 3 UInt64 16
    SpecificPortBind = field 4 UInt32 24  # Union
    Flags            = field 5 UInt32 24
    OwningModuleInfo = field 6 UInt64[] -MarshalAs @('ByValArray', 16) 32
} -ExplicitLayout

$MIB_UDP6ROW_OWNER_MODULE = struct $Module MIB_UDP6ROW_OWNER_MODULE @{
    LocalAddr        = field 0 Byte[] -MarshalAs @('ByValArray', 16) 0
    LocalScopeId   = field 1 UInt32 16
    LocalPort      = field 2 UInt32 20
    OwningPid      = field 3 UInt32 24
    CreateTimestamp  = field 4 UInt64 32
    SpecificPortBind = field 5 UInt32 40  # Union
    Flags            = field 6 UInt32 40
    OwningModuleInfo = field 7 UInt64[] -MarshalAs @('ByValArray', 16) 48
} -ExplicitLayout

$MIB_UDPTABLE_OWNER_MODULE = struct $Module MIB_UDPTABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_UDPROW_OWNER_MODULE
}

$MIB_UDP6TABLE_OWNER_MODULE = struct $Module MIB_UDP6TABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_UDPROW_OWNER_MODULE
}

$MIB_TCPROW_OWNER_MODULE = struct $Module MIB_TCPROW_OWNER_MODULE @{
    State           = field 0 $TCP_STATE
    LocalAddr       = field 1 UInt32
    LocalPort       = field 2 UInt32
    RemoteAddr      = field 3 UInt32
    RemotePort      = field 4 UInt32
    OwningPid       = field 5 UInt32
    CreateTimestamp = field 6 UInt64
    OwningModuleInfo = field 7 UInt64[] -MarshalAs @('ByValArray', 16)
}

$MIB_TCP6ROW_OWNER_MODULE = struct $Module MIB_TCP6ROW_OWNER_MODULE @{
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

$MIB_TCPTABLE_OWNER_MODULE = struct $Module MIB_TCPTABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_TCPROW_OWNER_MODULE
}

$MIB_TCP6TABLE_OWNER_MODULE = struct $Module MIB_TCP6TABLE_OWNER_MODULE @{
    NumEntries = field 0 UInt32
    Table      = field 1 $MIB_TCP6ROW_OWNER_MODULE
}

$KERB_CRYPTO_KEY = struct $Module KERB_CRYPTO_KEY @{
    KeyType = field 0 Int32
    Length = field 1 Int32
    Value = field 2 IntPtr
}

$KERB_EXTERNAL_NAME = struct $Module KERB_EXTERNAL_NAME @{
    NameType = field 0 Int16
    NameCount = field 1 UInt16
    Names = field 2 $LSA_UNICODE_STRING
}

$KERB_EXTERNAL_TICKET = struct $Module KERB_EXTERNAL_TICKET @{
    ServiceName = field 0 IntPtr
    TargetName = field 1 IntPtr
    ClientName = field 2 IntPtr
    DomainName = field 3 $LSA_UNICODE_STRING
    TargetDomainName = field 4 $LSA_UNICODE_STRING
    AltTargetDomainName = field 5 $LSA_UNICODE_STRING
    SessionKey = field 6 $KERB_CRYPTO_KEY
    TicketFlags = field 7 UInt32
    Flags = field 8 UInt32
    KeyExpirationTime = field 9 Int64
    StartTime = field 10 Int64
    EndTime = field 11 Int64
    RenewUntil = field 12 Int64
    TimeSkew = field 13 Int64
    EncodedTicketSize = field 14 Int32
    EncodedTicket = field 15 IntPtr
}

$KERB_TICKET_CACHE_INFO = struct $Module KERB_TICKET_CACHE_INFO @{
    ServerName = field 0 $LSA_UNICODE_STRING
    RealmName = field 1 $LSA_UNICODE_STRING
    StartTime = field 2 Int64
    EndTime = field 3 Int64
    RenewTime = field 4 Int64
    EncryptionType = field 5 Int32
    TicketFlags = field 6 UInt32
}

$KERB_QUERY_TKT_CACHE_REQUEST = struct $Module KERB_QUERY_TKT_CACHE_REQUEST @{
    MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
    LogonId = field 1 $LUID
}

$KERB_QUERY_TKT_CACHE_RESPONSE = struct $Module KERB_QUERY_TKT_CACHE_RESPONSE @{
    MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
    CountOfTickets = field 1 UInt32
    Tickets = field 2 $KERB_TICKET_CACHE_INFO.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$SecHandle = struct $Module SecHandle @{
    dwLower = field 0 IntPtr       
    dwUpper = field 1 IntPtr
}

$KERB_RETRIEVE_TKT_REQUEST = struct $Module KERB_RETRIEVE_TKT_REQUEST @{
    MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
    LogonId = field 1 $LUID
    TargetName = field 2 $LSA_UNICODE_STRING
    TicketFlags = field 3 UInt64
    CacheOptions = field 4 $KERB_CACHE_OPTIONS
    EncryptionType = field 5 Int64
    CredentialsHandle = field 6 $SecHandle
}

$KERB_RETRIEVE_TKT_RESPONSE = struct $Module KERB_RETRIEVE_TKT_RESPONSE @{
    Ticket = field 0 $KERB_EXTERNAL_TICKET
}

$SC_SERVICE_TAG_QUERY = struct $Module SC_SERVICE_TAG_QUERY @{
    ProcessId = field 0 UInt32
    ServiceTag = field 1 UInt32
    Unknown = field 2 UInt32
    Buffer = field 3 IntPtr
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

$SecPkgInfo = struct $Module SecPkgInfo @{
    Capabilities = field 0 $SECPKG_FLAG
    Version = field 1 UInt16
    RPCID = field 2 UInt16
    MaxToken = field 3 UInt32
    Name = field 4 IntPtr
    Comment = field 5 IntPtr
}

$SID_AND_ATTRIBUTES = struct $Module SID_AND_ATTRIBUTES @{
    Sid        = field 0 IntPtr
    Attributes = field 1 $SE_GROUP
} -PackingSize Size8

$THREADENTRY32 = struct $Module THREADENTRY32 @{
    dwSize             = field 0 UInt32
    cntUsage           = field 1 UInt32
    th32ThreadID       = field 2 UInt32
    th32OwnerProcessID = field 3 UInt32
    tpBasePri          = field 4 UInt32
    tpDeltaPri         = field 5 UInt32
    dwFlags            = field 6 UInt32
}

$TOKEN_APPCONTAINER_INFORMATION = struct $Module TOKEN_APPCONSTAINER_INFORMATION @{
    TokenAppContainer = field 0 IntPtr
}

$TOKEN_DEFAULT_DACL = struct $Module TOKEN_DEFAULT_DACL @{
    DefaultDacl = field 0 $ACL
}

$TOKEN_ELEVATION = struct $Module TOKEN_ELEVATION @{
    TokenIsElevated = field 0 UInt32
}

$TOKEN_GROUPS = struct $Module TOKEN_GROUPS @{
    GroupCount = field 0 UInt32
    Groups     = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs ('ByValArray', 50)
}

$TOKEN_GROUPS_AND_PRIVILEGES = struct $Module TOKEN_GROUPS_AND_PRIVILEGES @{
    SidCount            = field 0 UInt32
    SidLength           = field 1 UInt32
    Sids                = field 2 IntPtr
    RestrictedSidCount  = field 3 UInt32
    RestrictedSidLength = field 4 UInt32
    RestrictedSids      = field 5 IntPtr
    PrivilegeCount      = field 6 UInt32
    PrivilegeLength     = field 7 UInt32
    Privileges          = field 8 IntPtr
    AuthenticationId    = field 9 $LUID
}

$TOKEN_LINKED_TOKEN = struct $Module TOKEN_LINKED_TOKEN @{
    LinkedToken = field 0 IntPtr
}

$TOKEN_MANDATORY_LABEL = struct $Module TOKEN_MANDATORY_LABEL @{
    Label = field 0 $SID_AND_ATTRIBUTES
}

$TOKEN_MANDATORY_POLICY = struct $Module TOKEN_MANDATORY_POLICY @{
    Policy = field 0 $TOKENMANDATORYPOLICY
}

$TOKEN_OWNER = struct $Module TOKEN_OWNER @{
    Owner = field 0 IntPtr
}

$TOKEN_PRIVILEGES = struct $Module TOKEN_PRIVILEGES @{
    PrivilegeCount = field 0 UInt32
    Privileges     = field 1  $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_SOURCE = struct $Module TOKEN_SOURCE @{
    SourceName       = field 0 string
    SourceIdentifier = field 1 $LUID
}

$TOKEN_STATISTICS = struct $Module TOKEN_STATISTICS @{
    TokenId            = field 0 $LUID
    AuthenticationId   = field 1 $LUID
    ExpirationTime     = field 2 UInt64
    TokenType          = field 3 $TOKEN_TYPE
    ImpersonationLevel = field 4 $SECURITY_IMPERSONATION_LEVEL
    DynamicCharged     = field 5 UInt32
    DynamicAvailable   = field 6 UInt32
    GroupCount         = field 7 UInt32
    PrivilegeCount     = field 8 UInt32
    ModifiedId         = field 9 $LUID
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User = field 0 $SID_AND_ATTRIBUTES
}
#endregion Structs

#region Function Definitions
$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr] #_In_ HANDLE hObject
    ) -EntryPoint CloseHandle -SetLastError),
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr],                #_In_  PSID   Sid
        [IntPtr].MakeByRefType() #_Out_ LPTSTR *StringSid
    ) -EntryPoint ConvertSidToStringSid -SetLastError),
    (func kernel32 CreateToolhelp32Snapshot ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwFlags
        [UInt32]  #_In_ DWORD th32ProcessID
    ) -EntryPoint CreateToolhelp32Snapshot -SetLastError),
    (func advapi32 DuplicateToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE                       ExistingTokenHandle,
        [UInt32],                #_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        [IntPtr].MakeByRefType() #_Out_ PHANDLE                      DuplicateTokenHandle
    ) -EntryPoint DuplicateToken -SetLastError),
    (func secur32 EnumerateSecurityPackages ([UInt32]) @(
        [UInt32].MakeByRefType(), #_In_ PULONG      pcPackages
        [IntPtr].MakeByRefType()  #_In_ PSecPkgInfo *ppPackageInfo
    ) -EntryPoint EnumerateSecurityPackages),
    (func secur32 FreeContextBuffer ([UInt32]) @(
          [IntPtr] #_In_ PVOID pvContextBuffer
    ) -EntryPoint FreeContextBuffer),
    (func iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]) -EntryPoint GetExtendedTcpTable),
    (func iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [Int32].MakeByRefType(), [Bool], [Int32], [Int32], [Int32]) -EntryPoint GetExtendedUdpTable),
    (func iphlpapi GetIpNetTable ([Int32]) @(
        [IntPtr],                 #_Out_   PMIB_IPNETTABLE pIpNetTable
        [Int32].MakeByRefType(),  #_Inout_ PULONG          pdwSize
        [bool]                    #_In_    BOOL            bOrder
    ) -EntryPoint GetIpNetTable),
    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],                #_In_      HANDLE                  TokenHandle
        [Int32],                 #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
        [IntPtr],                #_Out_opt_ LPVOID                  TokenInformation
        [UInt32],                #_In_      DWORD                   TokenInformationLength
        [UInt32].MakeByRefType() #_Out_     PDWORD                  ReturnLength
    ) -EntryPoint GetTokenInformation -SetLastError),
    (func kernel32 GlobalGetAtomName ([UInt32]) @(
        [UInt16], #_In_  ATOM   nAtom
        [IntPtr], #_Out_ LPTSTR lpBuffer
        [UInt32]  #_In_  int    nSize
    ) -EntryPoint GlobalGetAtomName -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr] #_In_ HANDLE hToken
    ) -EntryPoint ImpersonateLoggedOnUser -SetLastError),
    (func advapi32 I_QueryTagInformation ([UInt32]) @([IntPtr], $SC_SERVICE_TAG_QUERY_TYPE, $SC_SERVICE_TAG_QUERY.MakeByRefType()) -EntryPoint I_QueryTagInformation),
    (func advapi32 LookupPrivilegeName ([bool]) @(
        [string],                    #_In_opt_  LPCTSTR lpSystemName
        [IntPtr],                    #_In_      PLUID   lpLuid
        [sYstem.Text.StringBuilder], #_Out_opt_ LPTSTR  lpName
        [UInt32].MakeByRefType()     #_Inout_   LPDWORD cchName
    ) -EntryPoint LookupPrivilegeName -SetLastError),
    (func advapi32 LookupPrivilegeDisplayName ([bool]) @(
        [string],                    #_In_opt_  LPCTSTR lpSystemName,
        [string],                    #_In_      LPCTSTR lpName,
        [System.Text.StringBuilder], #_Out_opt_ LPTSTR  lpDisplayName,
        [UInt32].MakeByRefType(),    #_Inout_   LPDWORD cchDisplayName,
        [UInt32].MakeByRefType()     #_Out_     LPDWORD lpLanguageId
    ) -EntryPoint LookupPrivilegeDisplayName -SetLastError),
    (func secur32 LsaCallAuthenticationPackage_KERB_QUERY_TKT_CACHE ([UInt32]) @(
        [IntPtr],                                      #_In_  HANDLE    LsaHandle
        [UInt64],                                      #_In_  ULONG     AuthenticationPackage
        $KERB_QUERY_TKT_CACHE_REQUEST.MakeByRefType(), #_In_  PVOID     ProtocolSubmitBuffer
        [UInt64],                                      #_In_  ULONG     SubmitBufferLength
        [IntPtr].MakeByRefType(),#_Out_ PVOID     *ProtocolReturnBuffer
        [UInt64].MakeByRefType(),                      #_Out_ PULONG    *ReturnBufferLength
        [UInt32].MakeByRefType()                       #_Out_ PNTSTATUS ProtocolStatus
    ) -EntryPoint LsaCallAuthenticationPackage),
    (func secur32 LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT ([UInt32]) @(
        [IntPtr],                                   #_In_  HANDLE    LsaHandle
        [UInt64],                                   #_In_  ULONG     AuthenticationPackage
        $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(), #_In_  PVOID     ProtocolSubmitBuffer
        [UInt64],                                   #_In_  ULONG     SubmitBufferLength
        [IntPtr].MakeByRefType(),#_Out_ PVOID     *ProtocolReturnBuffer
        [UInt64].MakeByRefType(),                   #_Out_ PULONG    *ReturnBufferLength
        [UInt32].MakeByRefType()                    #_Out_ PNTSTATUS ProtocolStatus
    ) -EntryPoint LsaCallAuthenticationPackage),
    (func secur32 LsaConnectUntrusted ([UInt32]) @(
        [IntPtr].MakeByRefType()                #_Out_ PHANDLE LsaHandle
    ) -EntryPoint LsaConnectUntrusted),
    (func secur32 LsaDeregisterLogonProcess ([UInt32]) @(
        [IntPtr]                                #_In_ HANDLE LsaHandle
    ) -EntryPoint LsaDeregisterLogonProcess),
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
    (func secur32 LsaLookupAuthenticationPackage ([UInt32]) @(
        [IntPtr],                    #_In_  HANDLE      LsaHandle,
        $LSA_STRING.MakeByRefType(), #_In_  PLSA_STRING PackageName,
        [UInt64].MakeByRefType()     #_Out_ PULONG      AuthenticationPackage
    ) -EntryPoint LsaLookupAuthenticationPackage),
    (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
        [UInt32] #_In_ NTSTATUS Status
    ) -EntryPoint LsaNtStatusToWinError),
    (func secur32 LsaRegisterLogonProcess ([UInt32]) @(
        $LSA_STRING.MakeByRefType(), #_In_  PLSA_STRING           LogonProcessName,
        [IntPtr].MakeByRefType(),    #_Out_ PHANDLE               LsaHandle,
        [UInt64].MakeByRefType()     #_Out_ PLSA_OPERATIONAL_MODE SecurityMode
    ) -EntryPoint LsaRegisterLogonProcess),
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr], #_In_      HANDLE          ThreadHandle,
        [Int32],  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr], #_Inout_   PVOID           ThreadInformation,
        [Int32],  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]  #_Out_opt_ PULONG          ReturnLength
    ) -EntryPoint NtQueryInformationThread),
    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError),
    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError),
    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError),
    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError),
    (func kernel32 QueryFullProcessImageName ([bool]) @(
      [IntPtr],                    #_In_    HANDLE hProcess
      [UInt32],                    #_In_    DWORD  dwFlags,
      [System.Text.StringBuilder], #_Out_   LPTSTR lpExeName,
      [UInt32].MakeByRefType()     #_Inout_ PDWORD lpdwSize
    ) -EntryPoint QueryFullProcessImageName -SetLastError),    
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],               # _In_ HANDLE hProcess
        [IntPtr],               # _In_ LPCVOID lpBaseAddress
        [Byte[]],               # _Out_ LPVOID  lpBuffer
        [Int32],                # _In_ SIZE_T nSize
        [Int32].MakeByRefType() # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -EntryPoint ReadProcessMemory -SetLastError),
    (func advapi32 RevertToSelf ([bool]) @(
        # No Parameters
    ) -EntryPoint RevertToSelf -SetLastError),
    (func kernel32 Thread32First ([bool]) @(
        [IntPtr],                                  #_In_    HANDLE          hSnapshot,
        $THREADENTRY32.MakeByRefType()             #_Inout_ LPTHREADENTRY32 lpte
    ) -EntryPoint Thread32First -SetLastError), 
    (func kernel32 Thread32Next ([bool]) @(
        [IntPtr],                                  #_In_  HANDLE          hSnapshot,
        $THREADENTRY32.MakeByRefType()             #_Out_ LPTHREADENTRY32 lpte
    ) -EntryPoint Thread32Next -SetLastError),   
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORY_BASIC_INFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -EntryPoint VirtualQueryEx -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace ACE
$advapi32 = $Types['advapi32']
$iphlpapi = $Types['iphlpapi']
$kernel32 = $Types['kernel32']
$ntdll = $Types['ntdll']
$secur32 = $Types['secur32']
#endregion Function Definitions

#region API Abstractions
function CloseHandle
{
    <#
    .SYNOPSIS

    Closes an open object handle.

    .DESCRIPTION

    The CloseHandle function closes handles to the following objects:
    - Access token
    - Communications device
    - Console input
    - Console screen buffer
    - Event
    - File
    - File mapping
    - I/O completion port
    - Job
    - Mailslot
    - Memory resource notification
    - Mutex
    - Named pipe
    - Pipe
    - Process
    - Semaphore
    - Thread
    - Transaction
    - Waitable timer
    
    The documentation for the functions that create these objects indicates that CloseHandle should be used when you are finished with the object, and what happens to pending operations on the object after the handle is closed. In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks. After the last handle to an object is closed, the object is removed from the system. 

    .PARAMETER Handle

    A valid handle to an open object.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None
    
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr] #_In_ HANDLE hObject
    ) -EntryPoint CloseHandle -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle    
    )
    
    $SUCCESS = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $SUCCESS) 
    {
        Write-Debug "CloseHandle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <#
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

    .DESCRIPTION

    The ConvertSidToStringSid function uses the standard S-R-I-S-S… format for SID strings.
    
    .PARAMETER SidPointer

    A pointer to the SID structure to be converted.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None
    
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                 #_In_  PSID   Sid,
        [IntPtr].MakeByRefType() #_Out_ LPTSTR *StringSid
    ) -EntryPoint ConvertSidToStringSid -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa376399(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Verbose "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function CreateToolhelp32Snapshot
{
    <#
    .SYNOPSIS

    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

    .DESCRIPTION

    The snapshot taken by this function is examined by the other tool help functions to provide their results. Access to the snapshot is read only. The snapshot handle acts as an object handle and is subject to the same rules regarding which processes and threads it is valid in.

    To enumerate the heap or module states for all processes, specify TH32CS_SNAPALL and set th32ProcessID to zero. Then, for each additional process in the snapshot, call CreateToolhelp32Snapshot again, specifying its process identifier and the TH32CS_SNAPHEAPLIST or TH32_SNAPMODULE value.

    When taking snapshots that include heaps and modules for a process other than the current process, the CreateToolhelp32Snapshot function can fail or return incorrect information for a variety of reasons. For example, if the loader data table in the target process is corrupted or not initialized, or if the module list changes during the function call as a result of DLLs being loaded or unloaded, the function might fail with ERROR_BAD_LENGTH or other error code. Ensure that the target process was not started in a suspended state, and try calling the function again. If the function fails with ERROR_BAD_LENGTH when called with TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, call the function again until it succeeds.

    The TH32CS_SNAPMODULE and TH32CS_SNAPMODULE32 flags do not retrieve handles for modules that were loaded with the LOAD_LIBRARY_AS_DATAFILE or similar flags. For more information, see LoadLibraryEx.

    To destroy the snapshot, use the CloseHandle function.

    Note that you can use the QueryFullProcessImageName function to retrieve the full name of an executable image for both 32- and 64-bit processes from a 32-bit process.

    .PARAMETER ProcessId

    The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.
    
    If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.
    
    If the specified process is a 64-bit process and the caller is a 32-bit process, this function fails and the last error code is ERROR_PARTIAL_COPY (299).

    .PARAMETER Flags
    
    The portions of the system to be included in the snapshot.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: TH32CS (Enumeration)

    (func kernel32 CreateToolhelp32Snapshot ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwFlags,
        [UInt32]  #_In_ DWORD th32ProcessID
    ) -EntryPoint CreateToolhelp32Snapshot -SetLastError)
        
    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [UInt32]
        $Flags
    )
    
    $hSnapshot = $Kernel32::CreateToolhelp32Snapshot($Flags, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $hSnapshot) 
    {
        Write-Debug "CreateToolhelp32Snapshot Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hSnapshot
}

function DuplicateToken
{
    <#
    .SYNOPSIS

    The DuplicateToken function creates a new access token that duplicates one already in existence.

    .DESCRIPTION

    The DuplicateToken function creates an impersonation token, which you can use in functions such as SetThreadToken and ImpersonateLoggedOnUser. The token created by DuplicateToken cannot be used in the CreateProcessAsUser function, which requires a primary token. To create a token that you can pass to CreateProcessAsUser, use the DuplicateTokenEx function.

    .PARAMETER TokenHandle

    A handle to an access token opened with TOKEN_DUPLICATE access.

    .PARAMETER ImpersonationLevel

    Specifies a SECURITY_IMPERSONATION_LEVEL enumerated type that supplies the impersonation level of the new token. The Default is SecurityImpersonation.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, SECURITY_IMPERSONATION_LEVEL (Enumeration)
    Optional Dependencies: None

    (func advapi32 DuplicateToken ([bool]) @(
        [IntPtr]                 #_In_  HANDLE                       ExistingTokenHandle,
        [UInt32]                 #_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        [IntPtr].MakeByRefType() #_Out_ PHANDLE                      DuplicateTokenHandle
    ) -EntryPoint DuplicateToken -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa446616(v=vs.85).aspx

    .EXAMPLE

    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,

        [Parameter()]
        [ValidateSet('None','SecurityAnonymous','SecurityIdentification','SecurityImpersonation','SecurityDelegation')]
        [string]
        $ImpersonationLevel = 'SecurityImpersonation'
    )

    $DuplicateTokenHandle = [IntPtr]::Zero

    $success = $Advapi32::DuplicateToken($TokenHandle, $SECURITY_IMPERSONATION_LEVEL::$ImpersonationLevel, [ref]$DuplicateTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $success)
    {
        Write-Debug "DuplicateToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $DuplicateTokenHandle
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

function GetIpNetTable
{
    <#
    .SYNOPSIS

    Retreives the IPv4 to physical address mapping table.

    .DESCRIPTION

    The GetIpNetTable function enumerates the Address Resolution Protocol (ARP) entries for IPv4 on a local system from the IPv4 to physical address mapping table and returns this information in a MIB_IPNETTABLE structure.

    on Windows Vista and later, the GetIpNetTable2 function can be used to retrieve the neighbor IP addresses for both IPv6 and IPv4.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: MIB_IPNETROW (Struct), MIB_IPNET_TYPE (Enum)
    Optional Dependencies: None
    
    (func iphlpapi GetIpNetTable ([Int32]) @(
        [IntPtr],                 #_Out_   PMIB_IPNETTABLE pIpNetTable
        [Int32].MakeByRefType(),  #_Inout_ PULONG          pdwSize
        [bool]                    #_In_    BOOL            bOrder
    ))

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa365956%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396

    .EXAMPLE

    GetIpNetTable

    AdapterIndex PhysicalAddress   IpAddress          Type
    ------------ ---------------   ---------          ----
              14 00-50-56-C0-00-08 192.168.1.1      DYNAMIC
              14 00-50-56-F8-64-30 192.168.1.2      DYNAMIC
              14 00-0C-29-BB-51-6D 192.168.1.137    DYNAMIC
              14 00-00-00-00-00-00 192.168.1.254    INVALID
              14 FF-FF-FF-FF-FF-FF 192.168.1.255    STATIC
              14 01-00-5E-00-00-16 224.0.0.22       STATIC
              14 01-00-5E-00-00-FC 224.0.0.252      STATIC
              14 01-00-5E-7F-FF-FA 239.255.255.250  STATIC
              14 FF-FF-FF-FF-FF-FF 255.255.255.255  STATIC
               1 00-00-00-00-00-00 224.0.0.22       STATIC
               1 00-00-00-00-00-00 224.0.0.252      STATIC
               1 00-00-00-00-00-00 239.255.255.250  STATIC
              11 01-00-5E-00-00-16 224.0.0.22       STATIC
              10 01-00-5E-00-00-16 224.0.0.22       STATIC
    #>

    $pThrowAway = [IntPtr]::Zero
    $dwSize = [Int32]0

    # Run the function once to get the size of the MIB_NETTABLE Structure
    $SUCCESS = $iphlpapi::GetIpNetTable($pThrowAway, [ref]$dwSize, $false)
    
    # ERROR_INSUFFICIENT_BUFFER means that $dwSize now contains the size of the stucture
    if($SUCCESS -eq 122)
    {
        $pIpNetTable = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)
        $SUCCESS = $iphlpapi::GetIpNetTable($pIpNetTable, [ref]$dwSize, $false)
        
        if($SUCCESS -eq 0)
        {
            $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($pIpNetTable)

            for($i = 0; $i -lt $count; $i++)
            {
                $CurrentPtr = [IntPtr]($pIpNetTable.ToInt64() + 4 + ($i * 24))
                $IpNetRow = $CurrentPtr -as $MIB_IPNETROW
    
                [byte[]]$bAddress = $IpNetRow.bPhysAddr

                $obj = @{
                    AdapterIndex = $IpNetRow.dwIndex
                    PhysicalAddress = [System.BitConverter]::ToString($bAddress).Replace('-',':')
                    IpAddress = [string]((New-Object -TypeName System.Net.IPAddress($IpNetRow.dwAddr)).IPAddressToString)
                    Type = [string]($IpNetRow.dwType -as $MIB_IPNET_TYPE)
                }

                Write-Output $obj
            }
        }
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pIpNetTable)
}

function GetTokenInformation
{
    <#
    .SYNOPSIS

    The GetTokenInformation function retrieves a specified type of information about an access token. The calling process must have appropriate access rights to obtain the information.
    
    To determine if a user is a member of a specific group, use the CheckTokenMembership function. To determine group membership for app container tokens, use the CheckTokenMembershipEx function.

    .PARAMETER TokenHandle

    A handle to an access token from which information is retrieved. If TokenInformationClass specifies TokenSource, the handle must have TOKEN_QUERY_SOURCE access. For all other TokenInformationClass values, the handle must have TOKEN_QUERY access.

    .PARAMETER TokenInformationClass

    Specifies a value from the TOKEN_INFORMATION_CLASS enumerated type to identify the type of information the function retrieves. Any callers who check the TokenIsAppContainer and have it return 0 should also verify that the caller token is not an identify level impersonation token. If the current token is not an app container but is an identity level token, you should return AccessDenied.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Module Dependencies: PSReflect
    Required Function Dependencies: ConvertSidToStringSid
    Required Structure Dependencies: TOKEN_USER, SID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, TOKEN_OWNER, TOKEN_SOURCE, LUID, TOKEN_MANDATORY_LABEL
    Required Enumeration Dependencies: LuidAttributes, TOKEN_TYPE, SECURITY_IMPERSONATION_LEVEL
    Optional Dependencies: TokenInformationClass (Enum)

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],                #_In_      HANDLE                  TokenHandle
        [Int32],                 #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
        [IntPtr],                #_Out_opt_ LPVOID                  TokenInformation
        [UInt32],                #_In_      DWORD                   TokenInformationLength
        [UInt32].MakeByRefType() #_Out_     PDWORD                  ReturnLength
    ) -EntryPoint GetTokenInformation -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TokenUser','TokenGroups','TokenPrivileges','TokenOwner','TokenPrimaryGroup','TokenDefaultDacl','TokenSource','TokenType','TokenImpersonationLevel','TokenStatistics','TokenRestrictedSids','TokenSessionId','TokenGroupsAndPrivileges','TokenSandBoxInert','TokenOrigin','TokenElevationType','TokenLinkedToken','TokenElevation','TokenHasRestrictions','TokenAccessInformation','TokenVirtualizationAllowed','TokenVirtualizationEnabled','TokenIntegrityLevel','TokenUIAccess','TokenMandatoryPolicy','TokenLogonSid','TokenIsAppContainer','TokenCapabilities','TokenAppContainerSid','TokenAppContainerNumber','TokenUserClaimAttributes','TokenDeviceClaimAttributes','TokenDeviceGroups','TokenRestrictedDeviceGroups')]
        [string]
        $TokenInformationClass
    )

    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $SUCCESS = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, [IntPtr]::Zero, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)

    # retrieve the proper buffer value
    $SUCCESS = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
        throw "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    switch($TokenInformationClass)
    {
        TokenUser
        {
            <#
            The buffer receives a TOKEN_USER structure that contains the user account of the token.
                ConvertSidToStringSid (Function)
                TOKEN_USER (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenUser = $TokenPtr -as $TOKEN_USER
            $UserSid = ConvertSidToStringSid -SidPointer $TokenUser.User.Sid

            $Sid = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
            $UserName = $Sid.Translate([System.Security.Principal.NTAccount])

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name Sid -Value $UserSid
            $obj | Add-Member -MemberType NoteProperty -Name Name -Value $UserName

            Write-Output $obj
        }
        TokenGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenPrivileges
        {
            <#
            The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
                TOKEN_PRIVILEGES (Structure)
                LUID_AND_ATTRIBUTES (Structure)
                LuidAttributes (Enumeration)
            #>
            $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                
            for($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
            {
                $obj = New-Object -TypeName psobject
                
                $obj | Add-Member -MemberType NoteProperty -Name Privilege -Value (LookupPrivilegeName -PrivilegeValue $TokenPrivileges.Privileges[$i].Luid.LowPart)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenPrivileges.Privileges[$i].Attributes
                    
                Write-Output $obj   
            }

        }
        TokenOwner
        {
            <#
            The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
                ConvertSidToStringSid (Function)
                TOKEN_OWNER (Structure)
            #>
            $TokenOwner = $TokenPtr -as $TOKEN_OWNER
    
            if($TokenOwner.Owner -ne $null)
            {
                $OwnerSid = ConvertSidToStringSid -SidPointer $TokenOwner.Owner
                
                $Sid = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)
                $OwnerName = $Sid.Translate([System.Security.Principal.NTAccount])

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value $OwnerSid
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $OwnerName

                Write-Output $obj
            }
            else
            {
                Write-Output $null
            }
        }
        TokenPrimaryGroup
        {
            <#
            The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
                TOKEN_PRIMARY_GROUP (Structure)
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDefaultDacl
        {
            <#
            The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
                TOKEN_DEFAULT_DACL (Structure)
                ACL (Structure)
            #>
            $Dacl = $TokenPtr -as $TOKEN_DEFAULT_DACL
            Write-Output $Dacl.DefaultDacl
        }
        TokenSource
        {
            <#
            The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
                TOKEN_SOURCE (Structure)
                LUID (Structure)
            #>
            
            Write-Output $TokenPtr
            #$TokenSource = $TokenPtr -as $TOKEN_SOURCE
            #Write-Output ($TokenSource.SourceName -join "")
        }
        TokenType
        {
            <#
            The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
                TOKEN_TYPE (Enumeration)
            #>
            if($TokenPtr -ne $null)
            {
                Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $TOKEN_TYPE)
            }
        }
        TokenImpersonationLevel
        {
            <#
            The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
            #>
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $SECURITY_IMPERSONATION_LEVEL)
        }
        TokenStatistics
        {
            <#
            The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
                TOKEN_STATISTICS (Structure)
                LUID (Structure)
                TOKEN_TYPE (Enumeration)
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
            #>
            $TokenStats = $TokenPtr -as $TOKEN_STATISTICS

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name TokenId -Value $TokenStats.TokenId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name AuthenticationId -Value $TokenStats.AuthenticationId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name TokenType -Value $TokenStats.TokenType
            $obj | Add-Member -MemberType NoteProperty -Name ImpersonationLevel -Value $TokenStats.ImpersonationLevel
            $obj | Add-Member -MemberType NoteProperty -Name DynamicCharged -Value $TokenStats.DynamicCharged
            $obj | Add-Member -MemberType NoteProperty -Name DynamicAvailable -Value $TokenStats.DynamicAvailable
            $obj | Add-Member -MemberType NoteProperty -Name GroupCount -Value $TokenStats.GroupCount
            $obj | Add-Member -MemberType NoteProperty -Name PrivilegeCount -Value $TokenStats.PrivilegeCount
            $obj | Add-Member -MemberType NoteProperty -Name ModifiedId -Value $TokenStats.ModifiedId.LowPart
                
            Write-Output $obj
        }
        TokenRestrictedSids
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenSessionId
        {
            # The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            # If the token is associated with the terminal server client session, the session identifier is nonzero.
            # Windows Server 2003 and Windows XP:  If the token is associated with the terminal server console session, the session identifier is zero.
            # In a non-Terminal Services environment, the session identifier is zero.
            # If TokenSessionId is set with SetTokenInformation, the application must have the Act As Part Of the Operating System privilege, and the application must be enabled to set the session ID in a token.
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr))
        }
        TokenGroupsAndPrivileges
        {
            <#
            The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
                TOKEN_GROUPS_AND_PRIVILEGES (Structure)
                SID_AND_ATTRIBUTES (Structure)
                LUID (Structure)
            #>
            $GroupsAndPrivs = ($TokenPtr -as $TOKEN_GROUPS_AND_PRIVILEGES)
                
            $SidList = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

            for($i = 0; $i -lt $GroupsAndPrivs.SidCount; $i++)
            {
                $currentPtr = [IntPtr]($GroupsAndPrivs.Sids.ToInt64() + ($SID_AND_ATTRIBUTES::GetSize() * $i))
                $SidAndAttr = $currentPtr -as $SID_AND_ATTRIBUTES

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $SidAndAttr.Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $SidAndAttr.Attributes

                $SidList.Add($obj)
            }
                
            $PrivList = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

            for($i = 0; $i -lt $GroupsAndPrivs.PrivilegeCount; $i++)
            {
                $currentPtr = [IntPtr]($GroupsAndPrivs.Privileges.ToInt64() + ($LUID_AND_ATTRIBUTES::GetSize() * $i))
                $LuidAndAttr = ($currentPtr -as $LUID_AND_ATTRIBUTES)

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Privilege -Value $LuidAndAttr.Luid.LowPart
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $LuidAndAttr.Attributes

                $PrivList.Add($obj)
            }

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name Sids -Value $SidList.ToArray()
            $obj | Add-Member -MemberType NoteProperty -Name Privilegs -Value $PrivList.ToArray()

            Write-Output $obj
        }
        TokenSandBoxInert
        {
            # The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenOrigin
        {
            <#
            The buffer receives a TOKEN_ORIGIN value.
            If the token resulted from a logon that used explicit credentials, such as passing a name, domain, and password to the LogonUser function, then the TOKEN_ORIGIN structure will contain the ID of the logon session that created it.
            If the token resulted from network authentication, such as a call to AcceptSecurityContext or a call to LogonUser with dwLogonType set to LOGON32_LOGON_NETWORK or LOGON32_LOGON_NETWORK_CLEARTEXT, then this value will be zero.
                TOKEN_ORIGIN (Structure)
                LUID (Structure)
            #>
            $TokenOrigin = $TokenPtr -as $LUID
            Write-Output $TokenOrigin.LowPart
        }
        TokenElevationType
        {
            <#
            The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
                TOKEN_ELEVATION_TYPE (Enumeration)
            #>
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $TOKEN_ELEVATION_TYPE)
        }
        TokenLinkedToken
        {
            <#
            The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
                TOKEN_LINKED_TOKEN (Structure)
            #>
            Write-Output ($TokenPtr -as $TOKEN_LINKED_TOKEN).LinkedToken
        }
        TokenElevation
        {
            <#
            The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.                                    
                TOKEN_ELEVATION (Structure)
            #>
            Write-Output (($TokenPtr -as $TOKEN_ELEVATION).TokenIsElevated -ne 0)
        }
        TokenHasRestrictions
        {
            # The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenAccessInformation
        {
            <#
            The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
                TOKEN_ACCESS_INFORMATION (Structure)
                SID_AND_ATTRIBUTES_HASH (Structure)
                SID_HASH_ENTRY (Structure)
                TOKEN_PRIVILEGES (Structure)
                LUID_AND_ATTRIBUTES (Structure)
                LUID (Structure)
                TOKEN_TYPE (Enumeration)
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
                TOKEN_MANDATORY_POLICY (Structure)
            #>
            <#
            $TokenAccessInfo = ($TokenPtr -as $TOKEN_ACCESS_INFORMATION)
                
            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name SidHash -Value ($TokenAccessInfo.SidHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name RestrictedSidHash -Value ($TokenAccessInfo.RestrictedSidHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name Privileges -Value ($TokenAccessInfo.Privileges -as $TOKEN_PRIVILEGES)
            $obj | Add-Member -MemberType NoteProperty -Name AuthenticationId -Value $TokenAccessInfo.AuthenticationId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name TokenType -Value $TokenAccessInfo.TokenType
            $obj | Add-Member -MemberType NoteProperty -Name ImpersonationLevel -Value $TokenAccessInfo.ImpersonationLevel
            $obj | Add-Member -MemberType NoteProperty -Name AppContainerNumber -Value $TokenAccessInfo.AppContainerNumber
            $obj | Add-Member -MemberType NoteProperty -Name PackageSid -Value (ConvertSidToStringSid -SidPointer $TokenAccessInfo.PackageSid)
            $obj | Add-Member -MemberType NoteProperty -Name CapabilitiesHash -Value ($TokenAccessInfo.CapabilitiesHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name TrustLevelSid -Value (ConvertSidToStringSid -SidPointer $TokenAccessInfo.TrustLevelSid)

            Write-Output $obj
            #>

            Write-Output $TokenPtr
            #throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenVirtualizationAllowed
        {
            # The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenVirtualizationEnabled
        {
            # The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenIntegrityLevel
        {
            <#
            The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
                TOKEN_MANDATORY_LABEL
                ConvertSidToStringSid
            #>
            $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL

            switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
            {
                S-1-16-0
                {
                    Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                }
                S-1-16-4096
                {
                    Write-Output "LOW_MANDATORY_LEVEL"
                }
                S-1-16-8192
                {
                    Write-Output "MEDIUM_MANDATORY_LEVEL"
                }
                S-1-16-8448
                {
                    Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                }
                S-1-16-12288
                {
                    Write-Output "HIGH_MANDATORY_LEVEL"
                }
                S-1-16-16384
                {
                    Write-Output "SYSTEM_MANDATORY_LEVEL"
                }
                S-1-16-20480
                {
                    Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                }
                S-1-16-28672
                {
                    Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                }
            }
        }
        TokenUIAccess
        {
            # The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenMandatoryPolicy
        {
            <#
            The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
                TOKEN_MANDATORY_POLICY
                TOKENMANDATORYPOLICY
            #>
            $MandatoryPolicy = $TokenPtr -as $TOKEN_MANDATORY_POLICY
            Write-Output $MandatoryPolicy.Policy
        }
        TokenLogonSid
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that specifies the token's logon SID.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenIsAppContainer
        {
            # The buffer receives a DWORD value that is nonzero if the token is an app container token. Any callers who check the TokenIsAppContainer and have it return 0 should also verify that the caller token is not an identify level impersonation token. If the current token is not an app container but is an identity level token, you should return AccessDenied.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenCapabilities
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the capabilities associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenAppContainerSid
        {
            <#
            The buffer receives a TOKEN_APPCONTAINER_INFORMATION structure that contains the AppContainerSid associated with the token. If the token is not associated with an app container, the TokenAppContainer member of the TOKEN_APPCONTAINER_INFORMATION structure points to NULL.
                TOKEN_APPCONTAINER_INFORMATION (Structure)
            #>
            Write-Output ($TokenPtr -as $TOKEN_APPCONTAINER_INFORMATION)
        }
        TokenAppContainerNumber
        {
            # The buffer receives a DWORD value that includes the app container number for the token. For tokens that are not app container tokens, this value is zero.
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr))
        }
        TokenUserClaimAttributes
        {
            <#
            The buffer receives a CLAIM_SECURITY_ATTRIBUTES_INFORMATION structure that contains the user claims associated with the token.
                CLAIM_SECURITY_ATTRIBUTES_INFORMATION (Structure)
                CLAIM_SECURITY_ATTRIBUTE_V1 (Structure)
                CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE (Structure)
                CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE (Structure)
            #>
            <#
            $AttributeInformation = $TokenPtr -as $CLAIM_SECURITY_ATTRIBUTES_INFORMATION
                
            if($AttributeInformation.AttributeCount -ne 0)
            {

            }
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDeviceClaimAttributes
        {
            <#
            The buffer receives a CLAIM_SECURITY_ATTRIBUTES_INFORMATION structure that contains the device claims associated with the token.
                CLAIM_SECURITY_ATTRIBUTES_INFORMATION (Structure)
                CLAIM_SECURITY_ATTRIBUTE_V1 (Structure)
                CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE (Structure)
                CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE (Structure)
            #>
            <#
            $AttributeInformation = $TokenPtr -as $CLAIM_SECURITY_ATTRIBUTES_INFORMATION
                
            if($AttributeInformation.AttributeCount -ne 0)
            {

            }
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDeviceGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the device groups that are associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            #Write-Output ($TokenPtr -as $TOKEN_GROUPS)
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenRestrictedDeviceGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the restricted device groups that are associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
}

function GlobalGetAtomName
{
    <#
    .SYNOPSIS

    Retrieves a copy of the character string associated with the specified global atom.

    .DESCRIPTION

    The string returned for an integer atom (an atom whose value is in the range 0x0001 to 0xBFFF) is a null-terminated string in which the first character is a pound sign (#) and the remaining characters represent the unsigned integer atom value.

    .PARAMETER AtomIndex

    The global atom (index) associated with the character string to be retrieved.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func kernel32 GlobalGetAtomName ([UInt32]) @(
        [UInt16],  #_In_  ATOM   nAtom
        [string].MakeByRefType(), #_Out_ LPTSTR lpBuffer
        [UInt16]   #_In_  int    nSize
    ) -EntryPoint GlobalGetAtomName -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms649063(v=vs.85).aspx

    .EXAMPLE

    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt16]
        $AtomIndex
    )

    $AtomName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)

    $SUCCESS = $kernel32::GlobalGetAtomName($AtomIndex, $AtomName, 1024); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($SUCCESS -eq 0)
    {
        throw "[GlobalGetAtomName]: Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($AtomName))
}

function ImpersonateLoggedOnUser
{
    <#
    .SYNOPSIS

    The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user. The user is represented by a token handle.

    .DESCRIPTION

    The impersonation lasts until the thread exits or until it calls RevertToSelf.
    
    The calling thread does not need to have any particular privileges to call ImpersonateLoggedOnUser.
    
    If the call to ImpersonateLoggedOnUser fails, the client connection is not impersonated and the client request is made in the security context of the process. If the process is running as a highly privileged account, such as LocalSystem, or as a member of an administrative group, the user may be able to perform actions they would otherwise be disallowed. Therefore, it is important to always check the return value of the call, and if it fails, raise an error; do not continue execution of the client request.
    
    All impersonate functions, including ImpersonateLoggedOnUser allow the requested impersonation if one of the following is true:
    - The requested impersonation level of the token is less than SecurityImpersonation, such as SecurityIdentification or SecurityAnonymous.
    - The caller has the SeImpersonatePrivilege privilege.
    - A process (or another process in the caller's logon session) created the token using explicit credentials through LogonUser or LsaLogonUser function.
    - The authenticated identity is same as the caller.
    
    Windows XP with SP1 and earlier:  The SeImpersonatePrivilege privilege is not supported.

    .PARAMETER TokenHandle

    A handle to a primary or impersonation access token that represents a logged-on user. This can be a token handle returned by a call to LogonUser, CreateRestrictedToken, DuplicateToken, DuplicateTokenEx, OpenProcessToken, or OpenThreadToken functions. If hToken is a handle to a primary token, the token must have TOKEN_QUERY and TOKEN_DUPLICATE access. If hToken is a handle to an impersonation token, the token must have TOKEN_QUERY and TOKEN_IMPERSONATE access.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr] #_In_ HANDLE hToken
    ) -EntryPoint ImpersonateLoggedOnUser -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle
    )

    $SUCCESS = $Advapi32::ImpersonateLoggedOnUser($TokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        throw "ImpersonateLoggedOnUser Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function LookupPrivilegeName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $PrivilegeValue
    )

    $L = [Activator]::CreateInstance($LUID)
    $L.LowPart = $PrivilegeValue

    $lpLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LUID::GetSize())
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($L, $lpLuid, $true)

    $lpName = New-Object -TypeName System.Text.StringBuilder

    $cchName = 0

    $SUCCESS = $Advapi32::LookupPrivilegeName($null, $lpLuid, $lpName, [ref]$cchName); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    $lpName.EnsureCapacity($cchName + 1) | Out-Null

    $SUCCESS = $Advapi32::LookupPrivilegeName($null, $lpLuid, $lpName, [ref]$cchName); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS) 
    {
        Write-Error "[LookupPrivilegeName] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output ($lpName.ToString())
}

function LookupPrivilegeDisplayName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Privilege
    )

    $lpDisplayName = New-Object -TypeName System.Text.StringBuilder

    $cchDisplayName = 0
    $lpLanguageId = 0

    $SUCCESS = $Advapi32::LookupPrivilegeDisplayName($null, $Privilege, $lpDisplayName, [ref]$cchDisplayName, [ref]$lpLanguageId)

    $lpDisplayName.EnsureCapacity($cchDisplayName + 1) | Out-Null

    $SUCCESS = $Advapi32::LookupPrivilegeDisplayName($null, $Privilege, $lpDisplayName, [ref]$cchDisplayName, [ref]$lpLanguageId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS) 
    {
        Write-Error "[LookupPrivilegeDisplayName] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output ($lpDisplayName.ToString())
}

function LsaCallAuthenticationPackage
{
    <#
    .SYNOPSIS

    The LsaCallAuthenticationPackage function is used by a logon application to communicate with an authentication package.
    
    This function is typically used to access services provided by the authentication package.

    .DESCRIPTION

    Logon applications can call LsaCallAuthenticationPackage to communicate with an authentication package. There are several reasons why an application may do this:
    
    - To implement multiple-message authentication protocols, such as the NTLM Challenge-Response protocol.
    - To pass state change information to the authentication package. For example, the NTLM might notify the MSV1_0 package that a previously unreachable domain controller is now reachable. The authentication package would then re-logon any users logged on to that domain controller.
    
    Typically, this function is used to exchange information with a custom authentication package. This function is not needed by an application that is using one of the authentication packages supplied with Windows, such as MSV1_0 or Kerberos.
    
    You must call LsaCallAuthenticationPackage to clean up PKINIT device credentials for LOCAL_SYSTEM and NETWORK_SERVICE. When there is no PKINIT device credential, a successful call does no operation. When there is a PKINIT device credential, a successful call cleans up the PKINIT device credential so that only the password credential remains.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378261(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle,

        [Parameter()]
        [ValidateSet('MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', 'NTLMSP_NAME_A')]
        [string]
        $AuthenticationPackageName = 'MICROSOFT_KERBEROS_NAME_A',

        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId
    )

    <#
    (func secur32 LsaCallAuthenticationPackage ([UInt32]) @(
        [IntPtr],                                  #_In_  HANDLE    LsaHandle
        [UInt64],                                  #_In_  ULONG     AuthenticationPackage
        $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(),#_In_  PVOID     ProtocolSubmitBuffer
        [UInt64],                                  #_In_  ULONG     SubmitBufferLength
        [IntPtr],                                  #_Out_ PVOID     *ProtocolReturnBuffer
        [UInt64].MakeByRefType(),                  #_Out_ PULONG    *ReturnBufferLength
        [UInt32].MakeByRefType()                   #_Out_ PNTSTATUS ProtocolStatus
    ))
    #>

    $AuthenticationPackage = LsaLookupAuthenticationPackage -LsaHandle $LsaHandle -PackageName $AuthenticationPackageName

    switch($AuthenticationPackageName)
    {
        MSV1_0_PACKAGE_NAME
        {
            throw New-Object -TypeName System.NotImplementedException("MSV1_0_PACKAGE_NAME Package has not been implemented yet.")
        }
        MICROSOFT_KERBEROS_NAME_A
        {
            # Request information about all of the cached tickets for the specified user logon session
            <#
            $KERB_QUERY_TKT_CACHE_REQUEST = struct $Mod Kerberos.KERB_QUERY_TKT_CACHE_REQUEST @{
                MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
                LogonId = field 1 $LUID
            }
            #>
            $ProtocolSubmitBuffer = [Activator]::CreateInstance($KERB_QUERY_TKT_CACHE_REQUEST)
            $ProtocolSubmitBuffer.MessageType = $KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheMessage
            $LogonIdLuid = [Activator]::CreateInstance($LUID)
            $LogonIdLuid.LowPart = $LogonId
            $LogonIdLuid.HighPart = 0
            $ProtocolSubmitBuffer.LogonId = $LogonIdLuid

            $ProtocolReturnBuffer = [IntPtr]::Zero
            $ReturnBufferLength = [UInt64]0
            $ProtocolStatus = [UInt32]0 

            $SUCCESS = $Secur32::LsaCallAuthenticationPackage_KERB_QUERY_TKT_CACHE($LsaHandle, $AuthenticationPackage, [ref]$ProtocolSubmitBuffer, $KERB_RETRIEVE_TKT_REQUEST::GetSize(), [ref]$ProtocolReturnBuffer, [ref]$ReturnBufferLength, [ref]$ProtocolStatus)

            if($SUCCESS -eq 0)
            {
                if($ProtocolStatus -eq 0)
                {
                    $Response = $ProtocolReturnBuffer -as $KERB_QUERY_TKT_CACHE_RESPONSE

                    for($i = 0; $i -lt $Response.CountOfTickets; $i++)
                    {
                        $currentTicketPtr = [IntPtr]::Add($ProtocolReturnBuffer, (8 + ($i * $KERB_TICKET_CACHE_INFO::GetSize())))
                        $data = $currentTicketPtr -as $KERB_TICKET_CACHE_INFO
                            
                        $StartTime = [DateTime]::FromFileTime($data.StartTime)
                        $EndTime = [DateTime]::FromFileTime($data.EndTime)
                        [timespan]$TicketLength = $EndTime.Subtract($StartTime)

                        $props = @{
                            ServerName = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.ServerName.Buffer, $data.ServerName.Length / 2))
                            RealmName = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.RealmName.Buffer, $data.RealmName.Length / 2))
                            StartTime = $StartTime
                            EndTime = $EndTime
                            TicketLength = $TicketLength
                            RenewTime = ([datetime]::FromFileTime($data.RenewTime))
                            EncryptionType = ($data.EncryptionType -as $KERB_ENCRYPTION_TYPE).ToString()
                            TicketFlags = ($data.TicketFlags -as $KERB_TICKET_FLAGS).ToString()
                        }

                        Write-Output $props
                    }
                }
                else
                {
                    $WinErrorCode = LsaNtStatusToWinError -NtStatus $ProtocolStatus
                    $LastError = [ComponentModel.Win32Exception]$WinErrorCode
                    throw "LsaCallAuthenticationPackage Error: $($LastError.Message)"
                }
            }
            else
            {
                $WinErrorCode = LsaNtStatusToWinError -NtStatus $SUCCESS
                $LastError = [ComponentModel.Win32Exception]$WinErrorCode
                throw "LsaCallAuthenticationPackage Error: $($LastError.Message)"
            }          
        }
        NEGOSSP_NAME_A
        {
            throw New-Object -TypeName System.NotImplementedException("NEGOSSP_NAME_A Package has not been implemented yet.")
        }
        NTLMSP_NAME_A
        {
            throw New-Object -TypeName System.NotImplementedException("NTLMSP_NAME_A Package has not been implemented yet.")
        }
    }
}

function LsaConnectUntrusted
{
    <#
    .SYNOPSIS

    The LsaConnectUntrusted function establishes an untrusted connection to the LSA server.

    .DESCRIPTION

    LsaConnectUntrusted returns a handle to an untrusted connection; it does not verify any information about the caller. The handle should be closed using the LsaDeregisterLogonProcess function.
    
    If your application simply needs to query information from authentication packages, you can use the handle returned by this function in calls to LsaCallAuthenticationPackage and LsaLookupAuthenticationPackage.
    
    Applications with the SeTcbPrivilege privilege may create a trusted connection by calling LsaRegisterLogonProcess.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378265(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaConnectUntrusted
    #>

    param
    (

    )

    <#
    (func secur32 LsaConnectUntrusted ([UInt32]) @(
        [IntPtr].MakeByRefType() #_Out_ PHANDLE LsaHandle
    ))
    #>
    
    $LsaHandle = [IntPtr]::Zero

    $SUCCESS = $Secur32::LsaConnectUntrusted([ref]$LsaHandle)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaConnectUntrusted Error: $($LastError.Message)"
    }

    Write-Output $LsaHandle
}

function LsaDeregisterLogonProcess
{
    <#
    .SYNOPSIS

    The LsaDeregisterLogonProcess function deletes the caller's logon application context and closes the connection to the LSA server.

    .DESCRIPTION

    If your logon application references the connection handle after calling the LsaDeregisterLogonProcess function, unexpected behavior can result.
    
    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378269(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaConnectUntrusted

    #
    # Do Somthing with the LSA Handle
    #
    
    LsaDeregisterLogonProcess -LsaHandle $hLsa
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle
    )

    <#
    (func secur32 LsaDeregisterLogonProcess ([UInt32]) @(
        [IntPtr] #_In_ HANDLE LsaHandle
    ))
    #>

    $SUCCESS = $Secur32::LsaDeregisterLogonProcess($LsaHandle)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaDeregisterLogonProcess Error: $($LastError.Message)"
    }
}

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
        }
        catch
        {

        }

        LsaFreeReturnBuffer -Buffer $sessionDataPtr
        $CurrentLuidPtr = [IntPtr]($CurrentLuidPtr.ToInt64() + $LUID::GetSize())
    }
}

function LsaLookupAuthenticationPackage
{
    <#
    .SYNOPSIS

    The LsaLookupAuthenticationPackage function obtains the unique identifier of an authentication package.

    .DESCRIPTION

    The authentication package identifier is used in calls to authentication functions such as LsaLogonUser and LsaCallAuthenticationPackage.

    .PARAMETER LsaHandle

    Handle obtained from a previous call to LsaRegisterLogonProcess or LsaConnectUntrusted.

    .PARAMETER PackageName

    Specifies the name of the authentication package. Supported packages are 'MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', and 'NTLMSP_NAME_A'.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378297(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaConnectUntrusted

    LsaLookupAuthenticationPackage -LsaHandle $hLsa -PackageName MICROSOFT_KERBEROS_NAME_A
    2
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle,

        [Parameter(Mandatory = $true)]
        [ValidateSet('MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', 'NTLMSP_NAME_A')]
        [string]
        $PackageName
    )

    <#
    (func secur32 LsaLookupAuthenticationPackage ([UInt32]) @(
        [IntPtr],                           #_In_  HANDLE      LsaHandle,
        $LSA_UNICODE_STRING.MakeByRefType() #_In_  PLSA_STRING PackageName,
        [UInt64].MakeByRefType()            #_Out_ PULONG      AuthenticationPackage
    ))
    #>

    switch($PackageName)
    {
        MSV1_0_PACKAGE_NAME {$authPackageName = 'NTLM'; break}
        MICROSOFT_KERBEROS_NAME_A {$authPackageName = 'Kerberos'; break}
        NEGOSSP_NAME_A {$authPackageName = 'Negotiate'; break}
        NTLMSP_NAME_A {$authPackageName = 'NTLM'; break}
    }

    $authPackageArray = [System.Text.Encoding]::ASCII.GetBytes($authPackageName)
    [int]$size = $authPackageArray.Length
    [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
    [System.Runtime.InteropServices.Marshal]::Copy($authPackageArray, 0, $pnt, $authPackageArray.Length)
    
    $lsaString = [Activator]::CreateInstance($LSA_STRING)
    $lsaString.Length = [UInt16]$authPackageArray.Length
    $lsaString.MaximumLength = [UInt16]$authPackageArray.Length
    $lsaString.Buffer = $pnt
    
    $AuthenticationPackage = [UInt64]0

    $SUCCESS = $Secur32::LsaLookupAuthenticationPackage($LsaHandle, [ref]$lsaString, [ref]$AuthenticationPackage)
    
    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaLookupAuthenticationPackage Error: $($LastError.Message)"
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pnt)

    Write-Output $AuthenticationPackage
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

function LsaRegisterLogonProcess
{
    <#
    .SYNOPSIS

    The LsaLookupAuthenticationPackage function obtains the unique identifier of an authentication package.

    .DESCRIPTION

    The authentication package identifier is used in calls to authentication functions such as LsaLogonUser and LsaCallAuthenticationPackage.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378297(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaRegisterLogonProcess

    #>

    <#
    (func secur32 LsaRegisterLogonProcess ([UInt32]) @(
        $LSA_STRING.MakeByRefType() #_In_  PLSA_STRING           LogonProcessName,
        [IntPtr].MakeByRefType()    #_Out_ PHANDLE               LsaHandle,
        [UInt64].MakeByRefType()    #_Out_ PLSA_OPERATIONAL_MODE SecurityMode
    ))
    #>

    $lsaStringArray = [System.Text.Encoding]::ASCII.GetBytes("INVOKE-IR")
    [int]$size = $lsaStringArray.Length
    [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
    [System.Runtime.InteropServices.Marshal]::Copy($lsaStringArray, 0, $pnt, $lsaStringArray.Length)
    
    $lsaString = [Activator]::CreateInstance($LSA_STRING)
    $lsaString.Length = [UInt16]$lsaStringArray.Length
    $lsaString.MaximumLength = [UInt16]$lsaStringArray.Length
    $lsaString.Buffer = $pnt

    $LsaHandle = [IntPtr]::Zero
    $SecurityMode = [UInt64]0

    $SUCCESS = $Secur32::LsaRegisterLogonProcess([ref]$lsaString, [ref]$LsaHandle, [ref]$SecurityMode)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaRegisterLogonProcess Error: $($LastError.Message)"
    }

    Write-Output $LsaHandle
}

function NtQueryInformationThread
{
    <#
    .SYNOPSIS

    Retrieves information about the specified thread.

    .PARAMETER ThreadHandle

    A handle to the thread about which information is being requested.

    .PARAMETER ThreadInformationClass

    If this parameter is the ThreadIsIoPending value of the THREADINFOCLASS enumeration, the function determines whether the thread has any I/O operations pending.
    
    Use the public function GetThreadIOPendingFlag instead to obtain this information.
    
    If this parameter is the ThreadQuerySetWin32StartAddress value of the THREADINFOCLASS enumeration, the function returns the start address of the thread. Note that on versions of Windows prior to Windows Vista, the returned start address is only reliable before the thread starts running.
    
    If this parameter is the ThreadSubsystemInformation value of the THREADINFOCLASS enumeration, the function retrieves a SUBSYSTEM_INFORMATION_TYPE value indicating the subsystem type of the thread. The buffer pointed to by the ThreadInformation parameter should be large enough to hold a single SUBSYSTEM_INFORMATION_TYPE enumeration.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, THREADINFOCLASS (Enumeration)
    Optional Dependencies: None

    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr], #_In_      HANDLE          ThreadHandle,
        [Int32],  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr], #_Inout_   PVOID           ThreadInformation,
        [Int32],  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]  #_Out_opt_ PULONG          ReturnLength
    ) -EntryPoint NtQueryInformationThread)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684283(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ThreadBasicInformation','ThreadTimes','ThreadPriority','ThreadBasePriority','ThreadAffinityMask','ThreadImpersonationToken','ThreadDescriptorTableEntry','ThreadEnableAlignmentFaultFixup','ThreadEventPair_Reusable','ThreadQuerySetWin32StartAddress','ThreadZeroTlsCell','ThreadPerformanceCount','ThreadAmILastThread','ThreadIdealProcessor','ThreadPriorityBoost','ThreadSetTlsArrayAddress','ThreadIsIoPending','ThreadHideFromDebugger','ThreadBreakOnTermination','ThreadSwitchLegacyState','ThreadIsTerminated','ThreadLastSystemCall','ThreadIoPriority','ThreadCycleTime','ThreadPagePriority','ThreadActualBasePriority','ThreadTebInformation','ThreadCSwitchMon','ThreadCSwitchPmu','ThreadWow64Context','ThreadGroupInformation','ThreadUmsInformation','ThreadCounterProfiling','ThreadIdealProcessorEx','ThreadCpuAccountingInformation','ThreadSuspendCount','ThreadHeterogeneousCpuPolicy','ThreadContainerId','ThreadNameInformation','ThreadSelectedCpuSets','ThreadSystemThreadInformation','ThreadActualGroupAffinity','ThreadDynamicCodePolicyInfo','ThreadExplicitCaseSensitivity','ThreadWorkOnBehalfTicket','ThreadSubsystemInformation','ThreadDbgkWerReportActive','ThreadAttachContainer','MaxThreadInfoClass')]
        [string]
        $ThreadInformationClass
    )
    
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $Success = $Ntdll::NtQueryInformationThread($ThreadHandle, $THREADINFOCLASS::$ThreadInformationClass, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "[NtQueryInformationThread] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    switch($ThreadInformationClass)
    {
        ThreadBasicInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadTimes
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadPriority
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadBasePriority
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadAffinityMask
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadImpersonationToken
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadDescriptorTableEntry
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadEnableAlignmentFaultFixup
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadEventPair_Reusable
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadQuerySetWin32StartAddress
        {
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
        }
        ThreadZeroTlsCell
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadPerformanceCount
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadAmILastThread
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadIdealProcessor
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadPriorityBoost
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSetTlsArrayAddress
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadIsIoPending
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadHideFromDebugger
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadBreakOnTermination
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSwitchLegacyState
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadIsTerminated
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadLastSystemCall
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadIoPriority
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadCycleTime
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadPagePriority
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadActualBasePriority
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadTebInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadCSwitchMon
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadCSwitchPmu
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadWow64Context
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadGroupInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadUmsInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadCounterProfiling
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadIdealProcessorEx
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadCpuAccountingInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSuspendCount
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadHeterogeneousCpuPolicy
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadContainerId
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadNameInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSelectedCpuSets
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSystemThreadInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadActualGroupAffinity
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadDynamicCodePolicyInfo
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadExplicitCaseSensitivity
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadWorkOnBehalfTicket
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadSubsystemInformation
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadDbgkWerReportActive
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        ThreadAttachContainer
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
        MaxThreadInfoClass
        {
            throw [System.NotImplementedException]"The $($ThreadInformationClass) class is not implemented yet."
        }
    }
}

function OpenProcess
{
    <#
    .SYNOPSIS

    Opens an existing local process object.

    .DESCRIPTION

    To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
    The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    When you are finished with the handle, be sure to close it using the CloseHandle function.

    .PARAMETER ProcessId

    The identifier of the local process to be opened.
    If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

    .PARAMETER DesiredAccess

    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, PROCESS_ACCESS (Enumeration)
    Optional Dependencies: None

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}

function OpenProcessToken
{ 
    <#
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.

    .PARAMETER ProcessHandle

    A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
    For a list of access rights for access tokens, see Access Rights for Access-Token Objects.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, TOKEN_ACCESS (Enumeration)
    Optional Dependencies: None

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function OpenThread
{
    <#
    .SYNOPSIS

    Opens an existing thread object.

    .DESCRIPTION

    The handle returned by OpenThread can be used in any function that requires a handle to a thread, such as the wait functions, provided you requested the appropriate access rights. The handle is granted access to the thread object only to the extent it was specified in the dwDesiredAccess parameter.
    When you are finished with the handle, be sure to close it by using the CloseHandle function.

    .PARAMETER ThreadId

    The identifier of the thread to be opened.

    .PARAMETER DesiredAccess

    The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, THREAD_ACCESS (Enumeration)
    Optional Dependencies: None

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('THREAD_TERMINATE','THREAD_SUSPEND_RESUME','THREAD_GET_CONTEXT','THREAD_SET_CONTEXT','THREAD_SET_INFORMATION','THREAD_QUERY_INFORMATION','THREAD_SET_THREAD_TOKEN','THREAD_IMPERSONATE','THREAD_DIRECT_IMPERSONATION','THREAD_SET_LIMITED_INFORMATION','THREAD_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','THREAD_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
    
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $THREAD_ACCESS::$val
    }

    $hThread = $Kernel32::OpenThread($dwDesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0) 
    {
        throw "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hThread
}

function OpenThreadToken
{
    <#
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread

    .DESCRIPTION

    Tokens with the anonymous impersonation level cannot be opened.
    Close the access token handle returned through the Handle parameter by calling CloseHandle.

    .PARAMETER ThreadHandle

    A handle to the thread whose access token is opened.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are reconciled against the token's discretionary access control list (DACL) to determine which accesses are granted or denied.

    .PARAMETER OpenAsSelf

    TRUE if the access check is to be made against the process-level security context.
    FALSE if the access check is to be made against the current security context of the thread calling the OpenThreadToken function.
    The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, $TOKEN_ACCESS (Enumeration)
    Optional Dependencies: None

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError)
        
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379296(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $OpenAsSelf = $false   
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "[OpenThreadToken] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function RevertToSelf
{
    <#
    .SYNOPSIS

    The RevertToSelf function terminates the impersonation of a client application.

    .DESCRIPTION

    A process should call the RevertToSelf function after finishing any impersonation begun by using the DdeImpersonateClient, ImpersonateDdeClientWindow, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient, ImpersonateSelf, ImpersonateAnonymousToken or SetThreadToken function.
    
    An RPC server that used the RpcImpersonateClient function to impersonate a client must call the RpcRevertToSelf or RpcRevertToSelfEx to end the impersonation.
    
    If RevertToSelf fails, your application continues to run in the context of the client, which is not appropriate. You should shut down the process if RevertToSelf fails.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379317(v=vs.85).aspx

    .EXAMPLE

        RevertToSelf
    #>

    <#
    (func advapi32 RevertToSelf ([bool]) @() -SetLastError)
    #>

    $SUCCESS = $Advapi32::RevertToSelf(); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        throw "[RevertToSelf] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function Thread32First
{
    <#
    .SYNOPSIS

    Retrieves information about the first thread of any process encountered in a system snapshot.

    .PARAMETER SnapshotHandle

    A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func kernel32 Thread32First ([bool]) @(
        [IntPtr],                      #_In_    HANDLE          hSnapshot
        $THREADENTRY32.MakeByRefType() #_Inout_ LPTHREADENTRY32 lpte
    ) -EntryPoint Thread32First -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686728(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SnapshotHandle
    )
        
    $Thread = [Activator]::CreateInstance($THREADENTRY32)
    $Thread.dwSize = $THREADENTRY32::GetSize()

    $Success = $Kernel32::Thread32First($hSnapshot, [Ref]$Thread); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "Thread32First Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $Thread
}

#region Lee's Code...
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
    $null = $iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)
    
    try
    {
        $Ret = $iphlpapi::GetExtendedTcpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0);
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
        
    $null = $iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET6, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)
        
    try
    {
        $Ret = $iphlpapi::GetExtendedTcpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET6, $TCP_TABLE_CLASS::TCP_TABLE_OWNER_MODULE_ALL, 0);
            
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
    $null = $iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)

    try
    {
        $Ret = $iphlpapi::GetExtendedUdpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0);
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
    $null = $iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref]$TableBufferSize, $true, $AF_INET6, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0)
    $TableBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TableBufferSize)

    try
    {
        $Ret = $iphlpapi::GetExtendedUdpTable($TableBuffer, [ref] $TableBufferSize, $true, $AF_INET6, $UDP_TABLE_CLASS::UDP_TABLE_OWNER_MODULE, 0);
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
#endregion Lee's code...
#endregion API Abstractions

#Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE -ScanType RegistryAutoRun
#Start-AceScript -Uri https://10.182.18.200 -SweepId ([Guid]::NewGuid()) -ScanId ([Guid]::NewGuid()) -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE -ScanType All
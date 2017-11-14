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

    foreach($o in (Get-PSIWindowsSecurityEvent -ReturnHashtables))
    {
        $o.Add('ComputerName', $HostFQDN)
        $o.Add('ScanType', 'WindowsSecurityEvent')
        $o.Add('SweepId', $SweepId)
        $o.Add('ScanId', $ScanId)
        $o.Add('ResultDate', $ResultDate)

        $message = ConvertTo-JsonV2 -InputObject $o
        $dataList.Add($message)
    }

    $props = @{
        ComputerName = $HostFQDN
        ScanType     = 'WindowsSecurityEvent'
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

Start-AceScript -Uri https://10.182.18.200 -SweepId $args[0] -ScanId ([Guid]::NewGuid()) -RoutingKey siem -Thumbprint 8D1DB3B7B85B6F9E9DE87B291DF66692A10240AE
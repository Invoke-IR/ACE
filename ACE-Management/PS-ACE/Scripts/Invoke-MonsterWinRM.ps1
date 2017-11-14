# WinRM In Memory Deployment
function Invoke-MonsterWinRM
{
    param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [string]
        $ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]
        $Thumbprint,

        [Parameter()]
        [ValidateSet('All','AccessToken','ArpCache','AtomTable','InjectedThread','KerberosTicket','LogonSession','MasterBootRecord','NetworkConnection','FullProcess','ScheduledTask','SecurityPackage','FullService','SimpleNamedPipe')]
        [string[]]
        $ScanType = 'All'
    )

    $scriptblock = {
        param
        (
            [Parameter(Mandatory = $true)]
            [guid]
            $SweepId,

            [Parameter(Mandatory = $true)]
            [string]
            $Uri,

            [Parameter(Mandatory = $true)]
            [string]
            $ScriptPath,

            [Parameter(Mandatory = $true)]
            [string]
            $Thumbprint,

            [Parameter()]
            [ValidateSet('All','AccessToken','ArpCache','AtomTable','InjectedThread','KerberosTicket','LogonSession','MasterBootRecord','NetworkConnection','FullProcess','ScheduledTask','SecurityPackage','FullService','SimpleNamedPipe')]
            [string[]]
            $ScanType = 'All'
        )

        function Invoke-AceWebRequest
        {
            param
            (
                [Parameter(Mandatory = $true)]
                [string]
                $Uri,

                [Parameter(Mandatory = $true)]
                [string]
                $ApiKey,

                [Parameter(Mandatory)]
                [string]
                $Thumbprint,

                [Parameter()]
                [ValidateSet('Delete','Get','Post','Put')]
                [string]
                $Method = 'Get',

                [Parameter()]
                [string]
                $ContentType = 'application/json',

                [Parameter()]
                [string]
                $Body
            )
            try
            {
                # Create web request
                $WebRequest = [System.Net.WebRequest]::Create($Uri)
    
                $WebRequest.Headers.Add('X-API-Version:1.0')
                $webrequest.Headers.Add("X-ApiKey:$($ApiKey)")

                $WebRequest.Method = $Method
                $WebRequest.ContentType = $ContentType

                # Set the callback to check for null certificate and thumbprint matching.
                $WebRequest.ServerCertificateValidationCallback = {
            
                    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            
                    if ($certificate -eq $null)
                    {
                        $Host.UI.WriteWarningLine("Null certificate.")
                        return $true
                    }
    
                    if ($certificate.Thumbprint -eq $Thumbprint)
                    {
                        return $true
                    }
                    else
                    {
                        $Host.UI.WriteWarningLine("Thumbprint mismatch. Certificate thumbprint $($certificate.Thumbprint)")
                        $Host.UI.WriteWarningLine("   Expected thumbprint: $($Thumbprint)")
                        $Host.UI.WriteWarningLine("   Received thumbprint: $($certificate.Thumbprint)")
                    }
    
                    return $false
                }

                if($PSBoundParameters.ContainsKey('Body'))
                {
                    $byteArray = [System.Text.Encoding]::UTF8.GetBytes($Body)
                    $Webrequest.ContentLength = $byteArray.Length
            
                    $dataStream = $Webrequest.GetRequestStream()            
                    $dataStream.Write($byteArray, 0, $byteArray.Length)
                    $dataStream.Close()
                }

                # Get response stream
                $ResponseStream = $webrequest.GetResponse().GetResponseStream()
    
                # Create a stream reader and read the stream returning the string value.
                $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
                $StreamReader.ReadToEnd()

                $StreamReader.Close()
                $ResponseStream.Close()
            }
            catch
            {
                Write-Error "Failed: $($_.exception.innerexception.message)"
            }
        }

        try
        {
            $MasterScript = Invoke-AceWebRequest -Uri "$($Uri)$($ScriptPath)" -Thumbprint $Thumbprint -ApiKey 1
            Invoke-Expression -Command $MasterScript
            Start-AceScript -Uri $Uri -SweepId $SweepId -ScanId ([Guid]::NewGuid()) -Thumbprint $Thumbprint -ScanType $ScanType
            Write-Host -NoNewline -ForegroundColor Green -Object "[+] "
            Write-Host $env:COMPUTERNAME
        }
        catch
        {
            Write-Host -NoNewline -ForegroundColor Red -Object "[-] "
            Write-Host $env:COMPUTERNAME
        }
    }

    $SweepId = [Guid]::NewGuid()
    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptblock -ArgumentList @($SweepId, $Uri, $ScriptPath, $Thumbprint, $ScanType) -SessionOption (New-PSSessionOption -NoMachineProfile)
}
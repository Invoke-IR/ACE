function Configure-AceWebService
{
    param
    (
        [Parameter()]
        [string]
        $FilePath = 'C:\Windows\Temp'
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Download ACEWebService latest release
    Invoke-WebRequest -Uri https://github.com/Invoke-IR/ACE/releases/download/test/ACEWebService.zip -OutFile "$($FilePath)\ACEWebService.zip"
    Expand-Archive -Path "$($FilePath)\ACEWebService.zip" -DestinationPath $FilePath
    
    # Download standalone .NET Core
    Invoke-WebRequest -Uri https://dotnetcli.azureedge.net/dotnet/Runtime/2.0.5/dotnet-runtime-2.0.5-win-x64.zip -OutFile "$($FilePath)\dotnet.zip"
    Expand-Archive -Path "$($FilePath)\dotnet.zip" -DestinationPath "$($FilePath)\ACEWebService\dotnet"
    
    # Cleanup Downloads
    Remove-Item -Path "$($FilePath)\dotnet.zip"
    Remove-Item -Path "$($FilePath)\ACEWebService.zip"
    
    # Create appsettings.Production.json file
    $appsettings = New-AppSettingsJson
    $appsettings | Out-File -FilePath "$($FilePath)\ACEWebService\appsettings.Production.json" -Force

    # Allow port 80 through the firewall
    $null = New-NetFirewallRule -DisplayName '[ACE] HTTP Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('80')
    
    # Setup portforward
    netsh interface portproxy add v4tov4 listenaddress=* listenport=80 connectaddress=127.0.0.1 connectport=5000

    # Start and configure WinRM
    Start-Service -Name WinRM
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value * -Force

    # Change directories to ACEWebService directory
    Set-Location "$($FilePath)\ACEWebService"
}

function New-AppSettingsJson
{
    $RabbitMQServer = Read-Host -Prompt RabbitMQServer
    $RabbitMQUser = Read-Host -Prompt RabbitMQUser
    $RabbitMQPassword = Read-Host -Prompt RabbitMQPassword -AsSecureString
    $NginxSSLThumbprint = Read-Host -Prompt Thumbprint
    $SQLServer = Read-Host -Prompt SQLServer
    $SQLPassword = Read-Host -Prompt SQLPassword -AsSecureString
    $EncryptionPassphrase = Read-Host -Prompt 'Choose an encryption passphrase for the SQL Server' -AsSecureString

    $RabbitMQPasswordClear = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($RabbitMQPassword))
    $SQLPasswordClear = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SQLPassword))
    $EncryptionPassphraseClear = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassphrase))

$appsettings = @"
{
  "Logging": {
    "IncludeScopes": false,
    "LogLevel": {
      "Default": "Debug",
      "System": "Information",
      "Microsoft": "Information"
    }
  },

  "AppSettings": {
    "RabbitMQServer": "$($RabbitMQServer)",
    "RabbitMQUserName": "$($RabbitMQUser)",
    "RabbitMQPassword": "$($RabbitMQPasswordClear)",
	"EncryptionPassphrase": "$($EncryptionPassphraseClear)",
    "Thumbprint": "$($NginxSSLThumbprint)"
  },

  "ConnectionStrings": {
    "DefaultConnection": "Server=$($SQLServer);Database=ACEWebService;User Id=sa;Password=$($SQLPasswordClear);MultipleActiveResultSets=true"
  }
}
"@

    Write-Output $appsettings
}
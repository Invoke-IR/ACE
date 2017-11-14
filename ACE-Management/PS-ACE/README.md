# PS-ACE
The ACE Web Application provides a RESTful API for managment and sweep tasking. PS-ACE is a PowerShell module that interacts with this API.

The supported mechanism for provisioning ACE is to use the start.sh script in the ACE-Docker directory. Upon completion, start.sh provides the user with all of the information required to interact with ACE's RESTful API. The three pieces of information necessary to interact with the ACE Web Application are:
* Web Server URI
* Builtin Administrator's API Key
* Web Server's SSL Certificate Thumbprint

Below is an example of the output from start.sh:
```
==========================================================
|      Thank you for provisioning ACE with Docker!!      |
==========================================================

Please use the following information to interact with ACE:
             Uri: https://10.57.106.141
          ApiKey: 9C8DC642-268D-41EA-9521-43F718119FB7
      Thumbprint: FA4608B93B017DF46D1BC6155DC4C5AF7D83EA1D

==========================================================
```

The best way to pass this information to the PS-ACE cmdlets is through a technique called [splatting](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/about_Splatting?view=powershell-5.0). Splatting allows for a Hash Table to be passed as a set of parameter names (Keys) and values (Values) by using the '@' instead of the '$'.

Below is an example of creating a hash table called **props** with keys Uri, ApiKey, and Thumbprint (these are derived from the output of start.sh above) and using this hash table to splat **Get-AceUser**:

```powershell
# Create a hash table with ACE's common parameters
PS> $props = @{
    Uri = 'https://192.168.50.187'
    ApiKey = 'd0bf91fa-9934-40ca-8cb9-5a1168546abc'
    Thumbprint = '39F459D8CBE1D92396A435F6D5B375AED42CE518'
}

# Pass parameters through Splatting the props variable
PS> Get-AceUser @props

id        : 334d89c9-da7a-43e8-a648-5dc8b22019ed
userName  : admin
firstName : Admin
lastName  : Admin
isAdmin   : True
apiKey    : 9C8DC642-268D-41EA-9521-43F718119FB7
```

## Cmdlets
### Get-AceComputer
### Get-AceCredential
### Get-AceSchedule
### Get-AceScript
### Get-AceSweep
### Get-AceSweepResult
### Get-AceUser
### Invoke-AceWebRequest
### New-AceCredential
### New-AceScheduledScan
### New-AceScript
### New-AceUser
### Remove-AceCredential
### Remove-AceScript
### Remove-AceUser
### Send-AceResult
### Start-AceDiscovery
### Start-AceSweep
### Update-AceCredential
### Update-AceUser
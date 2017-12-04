using ACEWebService.Entities;
using ACEWebService.ViewModels;
using Microsoft.Extensions.Options;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System;
using System.Linq;
using System.Security;
using System.Text;

namespace ACEWebService.Services
{
    public interface IDownloadService
    {
        void DownloadRequest(DownloadRequestViewModel param, Guid Id);
    }

    public class DownloadService : IDownloadService
    {
        private ACEWebServiceDbContext _context;
        ICryptographyService _cryptoService;
        private readonly AppSettings _settings;

        public DownloadService(ACEWebServiceDbContext context, ICryptographyService cryptoService, IOptions<AppSettings> settings)
        {
            _context = context;
            _cryptoService = cryptoService;
            _settings = settings.Value;
        }

        public void DownloadRequest(DownloadRequestViewModel param, Guid Id)
        {
            Computer computer = _context.Computers.Single(c => c.Id == param.ComputerId);
            Credential credential = _context.Credentials.Single(c => c.Id == computer.CredentialId);

            if (computer.WinRM || computer.RPC)
            {
                // Create a PowerShell script to run PSInvestigate
                string executionArgs = string.Format(
                    @"Download-AceFile -Uri {0} -Thumbprint {1} -Path {2} -Id {3}",
                    param.Uri,
                    _settings.Thumbprint,
                    param.FilePath,
                    Id
                );
                string psScript = string.Format(
                    @"Invoke-Expression (New-Object System.Net.WebClient).DownloadString('{0}/scripts/Download-AceFile.ps1'); {1}; Get-Process | Out-File -FilePath C:\temp\jared.txt",
                    param.Uri,
                    executionArgs
                );
                Console.WriteLine("[{0}] PsScript: {1}", computer.ComputerName, psScript);
                string commandline = string.Format(
                    @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand {0}",
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript))
                );

                if (computer.WinRM)
                {
                    KickOffCim(computer, credential, commandline, new WSManSessionOptions());
                }
                else
                {
                    KickOffCim(computer, credential, commandline, new DComSessionOptions());
                }
            }
            else if (computer.SSH)
            {
                throw new NotImplementedException();
            }
            else if (computer.SMB)
            {
                throw new NotImplementedException();
            }
            else
            {
                throw new Exception(string.Format("No valid protocols available for {0}", computer.ComputerName));
            }
        }

        private void KickOffCim(Computer computer, Credential credential, string commandline, CimSessionOptions options)
        {
            // Convert stored password to a secure string
            SecureString securePwd = new SecureString();
            foreach (char c in _cryptoService.Decrypt(credential.Password))
            {
                Console.WriteLine("[char]: {0}", c);
                securePwd.AppendChar(c);
            }
            
            CimCredential cimCreds = null;

            if (credential.UserName.Contains('\\'))
            {
                // Create a CimCredential object
                cimCreds = new CimCredential(PasswordAuthenticationMechanism.Kerberos, credential.UserName.Split('\\')[0], credential.UserName.Split('\\')[1], securePwd);
            }
            else
            {
                // Create a CimCredential object
                cimCreds = new CimCredential(PasswordAuthenticationMechanism.Default, null, credential.UserName, securePwd);
            }

            // Create a CimSession with the remote system
            options.AddDestinationCredentials(cimCreds);
            CimSession session = CimSession.Create(computer.ComputerName, options);

            // Create a CimMethodParametersCollection to pass to method invocation
            CimMethodParametersCollection collection = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("CommandLine", commandline, CimFlags.None)
            };

            CimMethodResult result = session.InvokeMethod("root/cimv2", "Win32_Process", "Create", collection);
            if (result.ReturnValue.ToString() == "0")
            {

            }
            else
            {

            }

            session.Dispose();
        }
    }
}

using ACEWebService.Entities;
using ACEWebService.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace ACEWebService.Services
{
    public interface ISweepExecutionService
    {
        Guid Sweep(SweepExecutionViewModel param);
    }

    public class SweepExecutionService : ISweepExecutionService
    {
        private ACEWebServiceDbContext _context;
        private ICryptographyService _cryptoService;

        public SweepExecutionService(ACEWebServiceDbContext context, ICryptographyService cryptoService)
        {
            _context = context;
            _cryptoService = cryptoService;
        }

        public Guid Sweep(SweepExecutionViewModel param)
        {
            Guid Id = Guid.NewGuid();

            _context.Sweeps.Add(new Sweep
            {
                Id = Id,
                Status = "Running",
                StartTime = DateTime.UtcNow,
                ScanCount = param.ComputerId.Length,
                CompleteCount = 0
            });
            _context.SaveChanges();

            List<Task> tasks = new List<Task>();

            /*
            List<Scan> scans = new List<Scan>();

            foreach (Guid compId in param.ComputerId)
            {
                // Create scan object
                Guid scanId = Guid.NewGuid();
                scans.Add(new Scan
                {
                    Id = scanId,
                    Status = "Running",
                    StartTime = DateTime.UtcNow,
                    ComputerId = compId,
                    SweepIdentifier = Id
                });
            }

            _context.Scans.AddRange(scans);
            */

            _context.SaveChanges();

            // Get Script object
            Script script = _context.Scripts.Single(s => s.Id == param.ScriptId);

            // Create Routing Key
            string RoutingKey = string.Format("{0}{1}", script.Enrichment, script.Output);

            // Get Thumbprint
            string thumbprint = null;
            string[] lines = System.IO.File.ReadAllLines(@"C:\inetpub\ACEWebService\appsettings.Production.json");
            foreach(string l in lines)
            {
                if (l.Contains("Thumbprint"))
                {
                    thumbprint = l.Split('"')[3];
                }
            }

            foreach (Guid compid in param.ComputerId)
            {
                Guid scanId = Guid.NewGuid();

                // Retreive Computer and Credential objects from DB
                Computer computer = _context.Computers.Single(c => c.Id == compid);
                Credential credential = _context.Credentials.Single(c => c.Id == computer.CredentialId);

                // Kick off scan
                if (computer.WinRM)
                {
                    Console.WriteLine("==== WINRM ====");

                    // Create a PowerShell script to run PSInvestigate
                    string executionArgs = string.Format(@"-Uri {0} -SweepId {1} -ScanId {2} -RoutingKey {3} -Thumbprint {4}", param.Uri, Id, scanId, RoutingKey, thumbprint);

                    Console.WriteLine(executionArgs);

                    string psScript = string.Format(@"iex (New-Object System.Net.WebClient).DownloadString('{0}{1}'); Start-AceScript {2}", param.Uri, script.Uri, executionArgs);

                    // Base64 Encode the PowerShell script
                    string psScriptEnc = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));

                    // Build full powershell command line to be run
                    string commandline = string.Format(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand {0}", psScriptEnc);

                    Console.WriteLine(commandline);

                    tasks.Add(Task.Run(() => { KickOffCimAsync(computer, credential, commandline, new WSManSessionOptions()); }));
                }
                else if (computer.RPC)
                {
                    Console.WriteLine("==== RPC ====");

                    // Create a PowerShell script to run PSInvestigate
                    string executionArgs = string.Format(@"-Uri {0} -SweepId {1} -ScanId {2} -RoutingKey {3} -Thumbprint {4}", param.Uri, Id, scanId, RoutingKey, thumbprint);
                    string psScript = string.Format(@"iex (New-Object System.Net.WebClient).DownloadString('{0}{1}'); Start-AceScript {2}", param.Uri, script.Uri, executionArgs);

                    // Base64 Encode the PowerShell script
                    string psScriptEnc = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));

                    // Build full powershell command line to be run
                    string commandline = string.Format(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -EncodedCommand {0}", psScriptEnc);

                    Console.WriteLine(commandline);

                    tasks.Add(Task.Run(() => { KickOffCimAsync(computer, credential, commandline, new DComSessionOptions()); }));
                }
                else if (computer.SSH)
                {
                    Console.WriteLine("==== SSH ====");

                    // Build command line to be run over SSH
                    string commandline = string.Format(@"curl -k {0}{1} | sudo python /dev/stdin --Server {0} --SweepId {2} --ScanId {3} --RoutingKey {4}", param.Uri, script.Uri, Id, scanId, RoutingKey);
                    //tasks.Add(Task.Run(() => { KickOffSSHAsync(computer, credential, commandline); }));
                    using (var client = new SshClient(computer.ComputerName, credential.UserName, _cryptoService.Decrypt(credential.Password)))
                    {
                        client.Connect();
                        client.RunCommand(commandline);
                        client.Disconnect();
                    }
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

            Task.WaitAll(tasks.ToArray());

            IQueryable<Scan> scansCompleted = _context.Set<Scan>().Where(s => s.SweepIdentifier == Id && s.Status != "Running");
            IQueryable<Scan> scansFailed = _context.Set<Scan>().Where(s => s.SweepIdentifier == Id && s.Status == "Failed");
            Sweep sweep = _context.Sweeps.Single(s => s.Id == Id);
            sweep.CompleteCount = scansCompleted.ToArray().Length;
            sweep.ErrorCount = scansFailed.ToArray().Length;
            sweep.Status = "Completed";
            _context.Sweeps.Update(sweep);
            _context.SaveChanges();

            return Id;
        }

        private void KickOffCimAsync(Computer computer, Credential credential, string commandline, CimSessionOptions options)
        {
            var optionsBuilder = new DbContextOptionsBuilder<ACEWebServiceDbContext>();
            optionsBuilder.UseSqlServer("Server=(localdb)\\MSSQLLocalDB;Database=ACEWebService;Trusted_Connection=True;MultipleActiveResultSets=true");
            using (ACEWebServiceDbContext context = new ACEWebServiceDbContext(optionsBuilder.Options))
            {
                // Convert stored password to a secure string
                SecureString securePwd = new SecureString();
                foreach (char c in _cryptoService.Decrypt(credential.Password))
                {
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
                CimMethodParametersCollection collection = new CimMethodParametersCollection();
                collection.Add(CimMethodParameter.Create("CommandLine", commandline, CimFlags.None));

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

        private static void KickOffSMBAsync()
        {
            throw new NotImplementedException();
        }

        private void KickOffSSHAsync(Computer computer, Credential credential, string commandline)
        {
            using (var client = new SshClient(computer.ComputerName, credential.UserName, _cryptoService.Decrypt(credential.Password)))
            {
                client.Connect();
                client.RunCommand(commandline);
                client.Disconnect();
            }
        }
    }
}
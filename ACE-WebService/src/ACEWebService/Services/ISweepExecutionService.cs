using ACEWebService.Entities;
using ACEWebService.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Renci.SshNet;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

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
        private readonly AppSettings _settings;

        public SweepExecutionService(ACEWebServiceDbContext context, ICryptographyService cryptoService, IOptions<AppSettings> settings)
        {
            _context = context;
            _cryptoService = cryptoService;
            _settings = settings.Value;
        }

        public Guid Sweep(SweepExecutionViewModel param)
        {
            // Generate Sweep Id and add the Sweep to the DB
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

            // Retrieve the target Script's data from the DB
            Script script = _context.Scripts.Single(s => s.Id == param.ScriptId);
            
            // Retrieve Credential objects from the DB and put in a dictionary based on the Id field
            Dictionary<Guid, Credential> credDictionary = _context.Credentials.ToDictionary(credential => credential.Id);

            // Create Parallel Tasks
            int numThreads = 20;
            var collection = new BlockingCollection<Wrapper<ACETasking>>(1000);
            var tasks = new Task[numThreads];
            for (var x = 0; x < numThreads; x++)
            {
                tasks[x] = CreateTask(collection);
            }

            foreach (Guid compid in param.ComputerId)
            {
                // Generate Scan Id and add the Scan to the DB
                Guid scanId = Guid.NewGuid();
                _context.Scans.Add(new Scan
                {
                    Id = scanId,
                    Status = "Running",
                    StartTime = DateTime.UtcNow,
                    ComputerId = compid,
                    SweepIdentifier = Id
                });
                
                // Retreive Computer objects from DB
                Computer computer = _context.Computers.Single(c => c.Id == compid);

                // Add items to the task collection
                collection.Add(new Wrapper<ACETasking>
                {
                    Item = new ACETasking{
                        Computer = computer,
                        CredentialDictionary = credDictionary,
                        Uri = param.ExternalUri,
                        Thumbprint = _settings.Thumbprint,
                        Script = script,
                        SweepId = Id,
                        ScanId = scanId
                    }
                });
            }

            _context.SaveChanges();
            collection.CompleteAdding();
            Console.WriteLine("Finished adding items to queue, waiting on tasks");
            Task.WaitAll(tasks);

            return Id;
        }

        // I need to change the type of object expected by Wrapper to something more complex
        private Task CreateTask(BlockingCollection<Wrapper<ACETasking>> input)
        {
            return Task.Factory.StartNew(() =>
            {
                foreach (var x in input.GetConsumingEnumerable())
                {
                    Credential credential = x.Item.CredentialDictionary[x.Item.Computer.CredentialId];
                    
                    if (x.Item.Computer.WinRM || x.Item.Computer.RPC)
                    {
                        // Create a PowerShell script to run PSInvestigate
                        string executionArgs = string.Format(
                            @"Start-AceScript -ServerUri {0} -ScriptUri {1} -Thumbprint {2} -SweepId {3} -ScanId {4} -RoutingKey {5}",
                            x.Item.Uri,
                            x.Item.Script.Uri,
                            x.Item.Thumbprint,
                            x.Item.SweepId,
                            x.Item.ScanId,
                            x.Item.Script.RoutingKey
                        );

                        string psScript = string.Format(
                            @"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]; if($certificate -eq $null){{return $true}}; if($certificate.Thumbprint -eq '{0}'){{return $true}}else{{return $false}}}}; Invoke-Expression (New-Object System.Net.WebClient).DownloadString('{1}/scripts/Start-AceScript.ps1'); {2}", 
                            x.Item.Thumbprint,
                            x.Item.Uri, 
                            executionArgs
                        );

                        Console.WriteLine("[WinRM:{0}] PsScript: {1}", x.Item.Computer.ComputerName, psScript);

                        string commandline = string.Format(
                            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand {0}", 
                            Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript))
                        );

                        if (x.Item.Computer.WinRM)
                        {
                            KickOffCimAsync(x.Item.Computer, credential, commandline, new WSManSessionOptions());
                        }
                        else
                        {
                            KickOffCimAsync(x.Item.Computer, credential, commandline, new DComSessionOptions());
                        }
                    }
                    else if (x.Item.Computer.SSH)
                    {
                        //Creates a string of the target script to run over SSH
                        string rawScript = System.Text.Encoding.ASCII.GetString(System.IO.File.ReadAllBytes(string.Format("scripts\\{0}.ace", x.Item.Script.Id)));

                        // Build command line to be run over SSH
                        string commandline = string.Format(
                            @"echo ""{0}"" | sudo python - --Server {1} --SweepId {2} --ScanId {3} --RoutingKey {4} --Thumbprint {5}",
                            rawScript,
                            x.Item.Uri, 
                            x.Item.SweepId,
                            x.Item.ScanId,
                            x.Item.Script.RoutingKey,
                            x.Item.Thumbprint
                        );
                        Console.WriteLine("[SSH] CommandLine: {0}", commandline);

                        KickOffSSHAsync(x.Item.Computer, credential, commandline);
                    }
                    else if (x.Item.Computer.SMB)
                    {
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new Exception(string.Format("No valid protocols available for {0}", x.Item.Computer.ComputerName));
                    }

                    x.Item = null;
                }
            },

            //Use this to make sure each task gets its own thread
            TaskCreationOptions.LongRunning);
        }

        private void KickOffCimAsync(Computer computer, Credential credential, string commandline, CimSessionOptions options)
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

    internal class Wrapper<T>
    {
        public T Item { get; set; }
    }

    internal class ACETasking
    {
        public Computer Computer;
        public Dictionary<Guid, Credential> CredentialDictionary;
        public string Uri;
        public string Thumbprint;
        public Script Script;
        public Guid SweepId;
        public Guid ScanId;
    }
}
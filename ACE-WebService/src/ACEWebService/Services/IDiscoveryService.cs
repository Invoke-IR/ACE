using ACEWebService.Entities;
using ACEWebService.Security;
using ACEWebService.ViewModels;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net.Sockets;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace ACEWebService.Services
{
    public interface IDiscoveryService
    {
        void Discover(DiscoveryActiveDirectoryViewModel param);
        void Discover(DiscoveryComputerListViewModel param);
    }

    public class DiscoveryActiveDirectoryService : IDiscoveryService
    {
        private ACEWebServiceDbContext _context;
        IConfigurationRoot _configuration;
        ICryptographyService _cryptoService;

        public DiscoveryActiveDirectoryService(ACEWebServiceDbContext context, ICryptographyService cryptoService)
        {
            _context = context;
            _cryptoService = cryptoService;
        }

        public void Discover(DiscoveryActiveDirectoryViewModel param)
        {
            Console.WriteLine("=========================");
            Console.WriteLine("Domain: {0}", param.Domain);
            Console.WriteLine("=========================");

            List<Computer> computerList = new List<Computer>();

            Console.WriteLine("=========================");
            Console.WriteLine("CredentialId: {0}", param.CredentialId);
            Console.WriteLine("=========================");

            Credential credential = _context.Credentials.SingleOrDefault(cred => cred.Id == param.CredentialId);

            Console.WriteLine("=========================");
            Console.WriteLine("UserName: {0}", credential.UserName);
            Console.WriteLine("=========================");

            SearchResultCollection results = GetDomainComputers(param.Domain, credential);

            foreach (SearchResult result in results)
            {
                string computername = (string)result.Properties["dnshostname"][0];
                //string operatingsystem = (string)result.Properties["operatingsystem"][0];

                Console.WriteLine("=========================");
                Console.WriteLine("ComputerName: {0}", computername);
                Console.WriteLine("=========================");

                try
                {
                    Computer computer = _context.Computers.Single(c => c.ComputerName == computername);

                    computer.ComputerName = computername;
                    //computer.OperatingSystem = operatingsystem;
                    computer.CredentialId = param.CredentialId;
                    computer.SSH = TestPort(computername, 22);
                    computer.RPC = TestPort(computername, 135);
                    computer.SMB = TestPort(computername, 445);
                    computer.WinRM = TestPort(computername, 5985);

                    _context.Computers.Update(computer);
                }
                catch
                {
                    Guid id = Guid.NewGuid();
                    Console.WriteLine("=========================");
                    Console.WriteLine("Id: {0}", id);
                    Console.WriteLine("=========================");

                    computerList.Add(new Computer
                    {
                        Id = id,
                        ComputerName = computername,
                        OperatingSystem = null,
                        CredentialId = param.CredentialId,
                        Scanned = false,
                        SSH = TestPort(computername, 22),
                        RPC = TestPort(computername, 135),
                        SMB = TestPort(computername, 445),
                        WinRM = TestPort(computername, 5985)
                    });
                }
            }

            _context.Computers.AddRange(computerList);
            _context.SaveChanges();
        }

        public void Discover(DiscoveryComputerListViewModel param)
        {
            List<Computer> computerList = new List<Computer>();

            foreach(string name in param.ComputerName)
            {
                Console.WriteLine("=========================");
                Console.WriteLine("ComputerName: {0}", name);
                Console.WriteLine("=========================");

                try
                {
                    Computer computer = _context.Computers.Single(c => c.ComputerName == name);

                    computer.SSH = TestPort(computer.ComputerName, 22);
                    computer.RPC = TestPort(computer.ComputerName, 135);
                    computer.SMB = TestPort(computer.ComputerName, 445);
                    computer.WinRM = TestPort(computer.ComputerName, 5985);

                    _context.Computers.Update(computer);
                }
                catch
                {
                    Guid id = Guid.NewGuid();
                    Console.WriteLine("=========================");
                    Console.WriteLine("Id: {0}", id);
                    Console.WriteLine("=========================");

                    computerList.Add(new Computer
                    {
                        Id = id,
                        ComputerName = name,
                        OperatingSystem = null,
                        CredentialId = param.CredentialId,
                        Scanned = false,
                        SSH = TestPort(name, 22),
                        RPC = TestPort(name, 135),
                        SMB = TestPort(name, 445),
                        WinRM = TestPort(name, 5985)
                    });

                    //computerList.Add(GetComputer(name, null, param.CredentialId, false));
                }
            }

            Console.WriteLine("=========================");
            Console.WriteLine("Post Loop");
            Console.WriteLine("=========================");

            _context.Computers.AddRange(computerList);
            _context.SaveChanges();
        }

        private SearchResultCollection GetDomainComputers(string domain, Credential credential)
        {
            List<SearchResult> results = new List<SearchResult>();

            Console.WriteLine("=========================");
            Console.WriteLine("Pre Directory Search: {0}", domain);
            Console.WriteLine("=========================");

            //using (DirectoryEntry entry = new DirectoryEntry(string.Format("LDAP://{0}", domain), credential.UserName, Cryptography.Decrypt(credential.Password, _configuration["EncryptionPassphrase"].ToString())))
            using (DirectoryEntry entry = new DirectoryEntry(string.Format("LDAP://{0}", domain), credential.UserName, _cryptoService.Decrypt(credential.Password)))
            {
                Console.WriteLine("=========================");
                Console.WriteLine("Post Directory Search: {0}", domain);
                Console.WriteLine("=========================");

                using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                {
                    mySearcher.Filter = ("(objectCategory=computer)");

                    // No size limit, reads all objects
                    mySearcher.SizeLimit = 0;

                    // Read data in pages of 250 objects. Make sure this value is below the limit configured in your AD domain (if there is a limit)
                    mySearcher.PageSize = 0;

                    // Let searcher know which properties are going to be used, and only load those
                    mySearcher.PropertiesToLoad.Add("dnshostname");
                    //mySearcher.PropertiesToLoad.Add("operatingsystem");

                    return mySearcher.FindAll();
                }
            }
        }

        private Computer GetComputer(string computername, string operatingsystem, Guid credentialId, bool scanned)
        {
            return new Computer
            {
                Id = Guid.NewGuid(),
                ComputerName = computername,
                OperatingSystem = operatingsystem,
                CredentialId = credentialId,
                Scanned = scanned,
                SSH = TestPort(computername, 22),
                RPC = TestPort(computername, 135),
                SMB = TestPort(computername, 445),
                WinRM = TestPort(computername, 5985)
            };
        }

        private bool TestPort(string ComputerName, int Port)
        {
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // Connect using a timeout (1 seconds)

                IAsyncResult result = socket.BeginConnect(ComputerName, Port, null, null);

                return result.AsyncWaitHandle.WaitOne(1000, true);
            }
        }
    }
}
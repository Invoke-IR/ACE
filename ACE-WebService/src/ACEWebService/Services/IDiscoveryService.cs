using ACEWebService.Entities;
using ACEWebService.ViewModels;
using System;
using System.Collections.Generic;
//using System.DirectoryServices;
using System.Net.Sockets;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.Collections.Concurrent;

namespace ACEWebService.Services
{
    public interface IDiscoveryService
    {
        //void Discover(DiscoveryActiveDirectoryViewModel param);
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

        /*
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
        */

        /*
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
        */

        public void Discover(DiscoveryComputerListViewModel param)
        {
            var computerDictionary = new ConcurrentDictionary<string, Computer>();
            // Add all current DB entries to computerDictionary
            foreach (Computer comp in _context.Computers)
            {
                computerDictionary.TryAdd(comp.ComputerName, comp);
            }

            // Set up Threads
            var numThreads = 20;
            var collection = new BlockingCollection<Wrapper<ACEComputer>>();
            var tasks = new Task[numThreads];
            
            for (var x = 0; x < numThreads; x++)
            {
                tasks[x] = CreateTask(collection, computerDictionary);
            }

            foreach (string computer in param.ComputerName)
            {
                collection.Add(new Wrapper<ACEComputer>
                {
                    Item = new ACEComputer{
                        ComputerName = computer,
                        CredentialId = param.CredentialId
                    }
                });
            }
            collection.CompleteAdding();
            Console.WriteLine("Finished adding items to queue, waiting on tasks");
            Task.WaitAll(tasks);

            // Delete all old entries from the Computer Table
            _context.Computers.RemoveRange(_context.Computers);
            _context.SaveChanges();
            // Update table with all entries from the cache
            _context.Computers.AddRange(computerDictionary.Values);
            // Save all changes done to the DB
            _context.SaveChanges();
        }

        private static Task CreateTask(BlockingCollection<Wrapper<ACEComputer>> input, ConcurrentDictionary<string, Computer> dictionary)
        {
            return Task.Factory.StartNew(() =>
            {
                foreach (var x in input.GetConsumingEnumerable())
                {
                    Computer oldcomp = new Computer();
                    if (dictionary.TryGetValue(x.Item.ComputerName, out oldcomp))
                    {
                        dictionary.TryUpdate(
                            x.Item.ComputerName,
                            new Computer
                            {
                                Id = oldcomp.Id,
                                ComputerName = x.Item.ComputerName,
                                OperatingSystem = null,
                                CredentialId = x.Item.CredentialId,
                                Scanned = oldcomp.Scanned,
                                SSH = TestPort(x.Item.ComputerName, 22),
                                RPC = TestPort(x.Item.ComputerName, 135),
                                SMB = TestPort(x.Item.ComputerName, 445),
                                WinRM = TestPort(x.Item.ComputerName, 5985)
                            }, 
                            oldcomp);
                    }
                    else
                    {
                        dictionary.TryAdd(x.Item.ComputerName, new Computer
                        {
                            Id = Guid.NewGuid(),
                            ComputerName = x.Item.ComputerName,
                            OperatingSystem = null,
                            CredentialId = x.Item.CredentialId,
                            Scanned = false,
                            SSH = TestPort(x.Item.ComputerName, 22),
                            RPC = TestPort(x.Item.ComputerName, 135),
                            SMB = TestPort(x.Item.ComputerName, 445),
                            WinRM = TestPort(x.Item.ComputerName, 5985)
                        });
                    }

                    x.Item = null;
                }
                Console.WriteLine($"Exiting thread {Thread.CurrentThread}");
            },
            //Use this to make sure each task gets its own thread
            TaskCreationOptions.LongRunning);
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

        internal static bool TestPort(string hostname, int port)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(200);
                    if (!success)
                    {
                        return false;
                    }

                    client.EndConnect(result);
                }
            }
            catch
            {
                return false;
            }
            return true;
        }
    }

    internal class ACEComputer
    {
        public string ComputerName;
        public Guid CredentialId;
    }
}
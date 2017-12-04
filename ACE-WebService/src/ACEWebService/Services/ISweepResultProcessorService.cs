using ACEWebService.ViewModels;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using System;
using System.IO;
using System.Text;

namespace ACEWebService.Services
{
    public interface ISweepResultProcessorService
    {
        void Process(Guid scanId, SweepResultViewModel scanData);
    }

    public class ScanResultRabbitMQService : ISweepResultProcessorService
    {
        private readonly AppSettings _settings;

        public ScanResultRabbitMQService(IOptions<AppSettings> settings)
        {
            _settings = settings.Value;
        }

        public void Process(Guid scanId, SweepResultViewModel sweepData)
        {
            var factory = new ConnectionFactory()
            {
                HostName = _settings.RabbitMQServer,
                UserName = _settings.RabbitMQUserName,
                Password = _settings.RabbitMQPassword,
        };

            using (var connection = factory.CreateConnection())
            using (var channel = connection.CreateModel())
            {
                channel.ExchangeDeclare(exchange: "ace_exchange", type: "topic");

                foreach (string message in sweepData.Data)
                {
                    byte[] body = Encoding.UTF8.GetBytes(message);
                    string key = sweepData.RoutingKey;

                    if(key.Contains("none"))
                    {
                        key = key.Replace("none.", "");
                    }

                    channel.BasicPublish(exchange: "ace_exchange",
                        routingKey: key,
                        basicProperties: null,
                        body: body);
                }
            }
        }
    }

    public class SweepResultFileWriterService : ISweepResultProcessorService
    {
        private string _sweepResultsDirectory;

        public SweepResultFileWriterService(string sweepResultsDirectory)
        {
            _sweepResultsDirectory = sweepResultsDirectory;
        }

        public void Process(Guid sweepId, SweepResultViewModel scanData)
        {
            string resultsDir = _sweepResultsDirectory + Path.DirectorySeparatorChar + sweepId + Path.DirectorySeparatorChar + scanData.ScanId;
            string resultsFileName = scanData.ScanType + "_" + scanData.ResultDate + "_" + scanData.ComputerName + "_" + scanData.ScanId + ".json";
            string resultsFile = resultsDir + Path.DirectorySeparatorChar + Path.GetFileName(resultsFileName);  // Prevent directory traversal

            if (!Directory.Exists(resultsDir))
            {
                Directory.CreateDirectory(resultsDir);
            }

            if (File.Exists(resultsFile))
            {
                throw new Exception("Results file already exists. Results file path: " + resultsFile);
            }

            foreach(string message in scanData.Data)
            {
                Console.WriteLine(message);
                File.AppendAllText(resultsFile, string.Format("{0}\r", message), Encoding.UTF8);
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ACEWebService
{
    public class AppSettings
    {
        public string RabbitMQServer { get; set; }
        public string RabbitMQUserName { get; set; }
        public string RabbitMQPassword { get; set; }
        public string Thumbprint { get; set; }
    }
}

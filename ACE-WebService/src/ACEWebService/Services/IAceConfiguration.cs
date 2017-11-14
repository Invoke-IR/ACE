using Microsoft.Extensions.Configuration;

namespace ACEWebService.Services
{
    public interface IAceConfiguration
    {

    }

    public class AceConfiguration : IAceConfiguration
    {
        private IConfigurationRoot _configuration;

        public AceConfiguration(IConfigurationRoot configuration)
        {
            _configuration = configuration;
        }
    }
}
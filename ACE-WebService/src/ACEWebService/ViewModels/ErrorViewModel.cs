using Newtonsoft.Json;

namespace VTIProxy.ViewModels
{
    public class ErrorViewModel
    {
        public string Message { get; set; }
        public string StackTrace { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
using ACEWebService.Services;
using ACEWebService.ViewModels;
using Quartz;
using System;

public class HelloJob : IJob
{
    public void Execute(IJobExecutionContext context)
    {
        JobDataMap dataMap = context.JobDetail.JobDataMap;
        //Guid[] ComputerId = dataMap["computerid"] as Guid[];

        //foreach(Guid c in ComputerId)
        //{
            Console.WriteLine("Sweep is executing at {0}.", DateTime.Now.ToString());
            Console.WriteLine("  scriptid: {0}", dataMap["scriptid"]);
            Console.WriteLine("       uri: {0}", dataMap["uri"]);
        //}
    }
}
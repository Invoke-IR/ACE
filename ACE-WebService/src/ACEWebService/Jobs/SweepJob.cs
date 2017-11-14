using System;
using ACEWebService.Services;
using ACEWebService.ViewModels;
using Quartz;

namespace ACEWebService.Jobs
{
    public class SweepJob : IJob
    {
        private ISweepExecutionService _sweepExecutionService;

        public SweepJob(ISweepExecutionService sweepExecutionService)
        {
            _sweepExecutionService = sweepExecutionService;
        }

        public void Execute(IJobExecutionContext context)
        {
            JobDataMap dataMap = context.JobDetail.JobDataMap;

            Console.WriteLine("HelloJob is executing.");
            Console.WriteLine("  scriptid: {0}", dataMap["scriptid"]);
            Console.WriteLine("       uri: {0}", dataMap["uri"]);

            _sweepExecutionService.Sweep(new SweepExecutionViewModel
            {
                ComputerId = dataMap["computerid"] as Guid[],
                ScriptId = (Guid)dataMap["scriptid"],
                Uri = dataMap["uri"] as string
            });
        }
    }
}

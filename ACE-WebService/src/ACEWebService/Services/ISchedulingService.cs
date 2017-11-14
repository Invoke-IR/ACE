using ACEWebService.Entities;
using ACEWebService.Jobs;
using ACEWebService.ViewModels;
using Quartz;
using Quartz.Impl;
using System;
using System.Collections.Generic;

namespace ACEWebService.Services
{
    public interface ISchedulingService
    {
        bool Delete(Schedule sched);
        IJobDetail Get(string name);
        //List<IJobDetail> GetInstances(Schedule sched);
        Schedule ScheduleTimed(ScheduleTimeViewModel param);    
    }

    public class SchedulingQuartzService : ISchedulingService
    {
        public Schedule ScheduleTimed(ScheduleTimeViewModel param)
        {
            return SetTimedEvent(param);
        }

        public bool Delete(Schedule sched)
        {
            IScheduler scheduler = StdSchedulerFactory.GetDefaultScheduler();

            //Remove Job from Quartz Scheduler
            JobKey jobKey = new JobKey(sched.JobName);
            if(scheduler.CheckExists(jobKey))
            {
                return scheduler.DeleteJob(jobKey);
            }
            else
            {
                return true;
            }
        }

        public IJobDetail Get(string name)
        {
            IScheduler scheduler = StdSchedulerFactory.GetDefaultScheduler();

            JobKey jobKey = new JobKey(name);

            if(scheduler.CheckExists(jobKey))
            {
                return scheduler.GetJobDetail(jobKey);
            }
            else
            {
                throw new Exception("Requested Job does not exist");
            }
        }

        public static Schedule SetTimedEvent(ScheduleTimeViewModel param)
        {
            /*
            Guid id = Guid.NewGuid();
            string jobName = Guid.NewGuid().ToString();
            string triggerName = Guid.NewGuid().ToString();

            IScheduler scheduler = StdSchedulerFactory.GetDefaultScheduler();
            scheduler.Start();

            IJobDetail job = JobBuilder.Create<SweepJob>()
                .WithIdentity(new JobKey(jobName))
                .UsingJobData("uri", param.Uri)
                .UsingJobData("scriptId", param.ScriptId)
                .Build();
            job.JobDataMap.Put("computerid", param.ComputerId);

            ITrigger trigger = TriggerBuilder.Create()
                .WithIdentity(new TriggerKey(triggerName))
                .StartNow()
                //.StartAt(new DateTime(2017, 07, 13, param.Hour, param.Minute, 0))
                .WithSimpleSchedule(x => x
                    .WithIntervalInSeconds(60))
                .Build();

            //ITrigger trigger = TriggerBuilder.Create().WithIdentity(new TriggerKey(triggerName)).WithDailyTimeIntervalSchedule(s => s.StartingDailyAt(TimeOfDay.HourAndMinuteOfDay(param.Hour, param.Minute)).WithRepeatCount(param.RepeatCount)).Build();

            Console.WriteLine("  Now: {0}", DateTime.UtcNow.ToString());
            Console.WriteLine("Start: {0}", trigger.StartTimeUtc.ToString());

            scheduler.ScheduleJob(job, trigger);

            DateTime now = DateTime.Now;

            Schedule sched = new Schedule
            {
                Id = id,
                JobName = jobName,
                TriggerName = triggerName,
                StartTime = new DateTime(now.Year, now.Month, now.Day, param.Hour, param.Minute, 0),
                ExecutionCount = 0,
                RepeatCount = param.RepeatCount,
                ScriptId = param.ScriptId
            };
            */

            // construct a scheduler factory
            ISchedulerFactory schedFact = new StdSchedulerFactory();

            // get a scheduler
            IScheduler sched = schedFact.GetScheduler();
            sched.Start();

            string jobName = Guid.NewGuid().ToString();
            string triggerName = Guid.NewGuid().ToString();

            // define the job and tie it to our HelloJob class
            IJobDetail job = JobBuilder.Create<HelloJob>()
                .WithIdentity(jobName, "group1")
                .UsingJobData("uri", param.Uri)
                .UsingJobData("scriptid", param.ScriptId)
                .Build();
            job.JobDataMap.Put("computerid", param.ComputerId);

            DateTime now = DateTime.Now;
            Console.WriteLine("Start Time: {0}", DateBuilder.DateOf(param.Hour, param.Minute, 0));

            // Trigger the job to run now, and then every 40 seconds
            ITrigger trigger = TriggerBuilder.Create()
              .WithIdentity(triggerName, "group1")
              //.StartNow()
              .StartAt(DateBuilder.DateOf(param.Hour, param.Minute, 0))      
              .WithSimpleSchedule(x => x
                  .WithIntervalInMinutes(param.Interval)
                  .WithRepeatCount(param.RepeatCount))
              .Build();
            
            sched.ScheduleJob(job, trigger);

            Schedule schedule = new Schedule
            {
                Id = Guid.NewGuid(),
                JobName = jobName,
                TriggerName = triggerName,
                StartTime = trigger.StartTimeUtc.UtcDateTime,
                ExecutionCount = 0,
                RepeatCount = param.RepeatCount,
                ScriptId = param.ScriptId
            };

            return schedule;
        }
    }
}
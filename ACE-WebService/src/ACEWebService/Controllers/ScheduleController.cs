using ACEWebService.Entities;
using ACEWebService.Services;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Quartz;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DIGSWebService.Controllers
{
    [Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class ScheduleController : Controller
    {
        private ACEWebServiceDbContext _context;
        private ISchedulingService _schedulingService;

        public ScheduleController(ACEWebServiceDbContext context, ISchedulingService schedulingService)
        {
            _context = context;
            _schedulingService = schedulingService;
        }

        // DELETE /ace/user/{id}
        [HttpDelete("{id}")]
        public Schedule Delete([FromRoute]Guid id)
        {
            /*
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                Schedule sched = _context.Schedules.SingleOrDefault(s => s.Id == id);

                if (_schedulingService.Delete(sched))
                {
                    _context.Schedules.Remove(sched);
                    _context.SaveChanges();
                    return sched;
                }
                else
                {
                    throw new Exception("Failed to delete Scheduled Job. Job may be currently running.");
                }
            }
            else
            {
                throw new Exception("Only Administrator accounts can perform this action.");
            }
            */
            throw new NotImplementedException();
        }

        // GET /ace/schedule
        [HttpGet]
        public IEnumerable<Schedule> Get()
        {
            /*
            return _context.Schedules;
            */
            throw new NotImplementedException();
        }

        // GET /ace/schedule/{id}
        public IJobDetail Get([FromRoute]string id)
        {
            /*
            return _schedulingService.Get(id);
            */
            throw new NotImplementedException();
        }

        // POST /ace/schedule
        [HttpPost]
        public IActionResult SetTimer([FromBody]ScheduleTimeViewModel param)
        {
            /*
            if (ModelState.IsValid)
            {
                Schedule sched = _schedulingService.ScheduleTimed(param);

                _context.Schedules.Add(sched);
                _context.SaveChanges();

                return Ok(sched);
            }
            else
            {
                return BadRequest(ModelState);
            }
            */
            throw new NotImplementedException();
        }
    }
}
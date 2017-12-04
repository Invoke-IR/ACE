using ACEWebService.Entities;
using ACEWebService.Services;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ACEWebService.Controllers
{
    [Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class SweepController : Controller
    {
        private ISweepExecutionService _sweepExecutionService;
        private ACEWebServiceDbContext _context;

        public SweepController(ISweepExecutionService sweepExecutionService, ACEWebServiceDbContext context)
        {
            _sweepExecutionService = sweepExecutionService;
            _context = context;
        }

        // GET /ace/sweep
        [HttpGet()]
        public IEnumerable<Sweep> Get()
        {
            return _context.Sweeps;
        }

        // GET /ace/sweep/{id}
        [HttpGet("{id}")]
        public Sweep Get([FromRoute]Guid Id)
        {
            Sweep sweep = _context.Sweeps.Single(s => s.Id == Id);
            return sweep;
        }

        // POST /ace/sweep
        [HttpPost]
        public IActionResult Post([FromBody]SweepExecutionViewModel param)
        {
            if (ModelState.IsValid)
            {
                Guid Id = _sweepExecutionService.Sweep(param);
                return Ok(Id);
            }
            else
            {
                //return BadRequest(ModelState);
                return BadRequest(ModelState);
            }
        }

        // PUT /ace/sweep/{id}
        [AllowAnonymous]
        [HttpPut("{id}")]
        public IActionResult Put([FromRoute]Guid id, [FromBody]Guid scanId)
        {
            if (ModelState.IsValid)
            {
                Scan scan = _context.Scans.SingleOrDefault(s => s.Id == scanId);
                scan.StopTime = DateTime.UtcNow;
                scan.Status = "Completed";
                _context.Scans.Update(scan);
                _context.SaveChanges();

                Sweep sweep = _context.Sweeps.SingleOrDefault(sw => sw.Id == id);
                sweep.CompleteCount++;
                _context.Sweeps.Update(sweep);
                _context.SaveChanges();

                return Ok(scanId);
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
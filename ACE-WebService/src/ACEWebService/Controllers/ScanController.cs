using ACEWebService.Entities;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;

namespace ACEWebService.Controllers
{
    [Route("ace/[controller]")]
    public class ScanController : Controller
    {
        private ACEWebServiceDbContext _context;
        
        public ScanController(ACEWebServiceDbContext context)
        {
            _context = context;
        }

        // GET /ace/scan/{sweepId}
        [HttpGet("{id}")]
        public IQueryable<Scan> GetSweepScans([FromRoute]Guid id)
        {
            return _context.Set<Scan>().Where(s => s.SweepIdentifier == id);
        }

        // POST /ace/scan/success/{id}
        [Route("/ace/scan/success/{id}")]
        [HttpPost("{id}")]
        public IActionResult Success([FromRoute]Guid id)
        {
            if (ModelState.IsValid)
            {
                Scan scan = _context.Scans.Single(s => s.Id == id);
                scan.StopTime = DateTime.UtcNow;
                scan.Status = "Completed";
                _context.Scans.Update(scan);

                Sweep sweep = _context.Sweeps.Single(s => s.Id == scan.SweepIdentifier);
                sweep.CompleteCount++;
                if ((sweep.CompleteCount + sweep.ErrorCount) == sweep.ScanCount)
                {
                    sweep.Status = "Completed";
                }
                _context.Sweeps.Update(sweep);

                _context.SaveChanges();

                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // POST /ace/scan/failed/{id}
        [Route("/ace/scan/failed/{id}")]
        [HttpPost("{id}")]
        public IActionResult Failure([FromRoute]Guid id)
        {
            if (ModelState.IsValid)
            {
                Scan scan = _context.Scans.Single(s => s.Id == id);
                scan.StopTime = DateTime.UtcNow;
                scan.Status = "Failed";
                _context.Scans.Update(scan);

                Sweep sweep = _context.Sweeps.Single(s => s.Id == scan.SweepIdentifier);
                sweep.ErrorCount++;
                if ((sweep.CompleteCount + sweep.ErrorCount) == sweep.ScanCount)
                {
                    sweep.Status = "Completed";
                }
                _context.Sweeps.Update(sweep);

                _context.SaveChanges();

                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
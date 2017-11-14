using ACEWebService.Services;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;

namespace ACEWebService.Controllers
{
    [Route("ace/[controller]")]
    public class ResultController : Controller
    {
        private ISweepResultProcessorService _sweepProcessorService;
        //IConfigurationRoot _configuration;

        public ResultController(ISweepResultProcessorService sweepWriterService)
        {
            _sweepProcessorService = sweepWriterService;
        }

        // POST /ace/result/{scandId}
        [HttpPost("{id}")]
        public IActionResult Post([FromRoute]Guid id, [FromBody]SweepResultViewModel result)
        {
            if (ModelState.IsValid)
            {
                _sweepProcessorService.Process(id, result);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
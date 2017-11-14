using ACEWebService.Services;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;

namespace ACEWebService.Controllers
{
    [Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class DiscoverController : Controller
    {
        private IDiscoveryService _discoverService;
        
        public DiscoverController(IDiscoveryService discoverService)
        {
            _discoverService = discoverService;
        }

        // POST /ace/discover/domain
        [Route("/ace/discover/domain")]
        [HttpPost]
        public IActionResult Domain([FromBody]DiscoveryActiveDirectoryViewModel param)
        {
            if (ModelState.IsValid)
            {
                _discoverService.Discover(param);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // POST /ace/discover/computerlist
        [Route("/ace/discover/computerlist")]
        [HttpPost()]
        public IActionResult ComputerList([FromBody]DiscoveryComputerListViewModel param)
        {
            if (ModelState.IsValid)
            {
                _discoverService.Discover(param);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
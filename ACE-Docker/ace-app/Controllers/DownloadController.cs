using ACEWebService.Entities;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.AspNetCore.Hosting;

namespace ACEWebService.Controllers
{
    //[Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class DownloadController : Controller
    {
        private ACEWebServiceDbContext _context;
        private IHostingEnvironment _hostingEnv;

        public DownloadController(ACEWebServiceDbContext context, IHostingEnvironment hostingEnv)
        {
            _context = context;
            _hostingEnv = hostingEnv;
        }

        // POST /ace/download
        [HttpPost]
        public IActionResult RequestFile([FromBody]DownloadRequestViewModel param)
        {
            if (ModelState.IsValid)
            {
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // POST /ace/download/{id}
        [HttpPost("{id}")]
        public IActionResult ReceiveFile([FromRoute]Guid id, [FromBody]DownloadReceiveViewModel param)
        {
            if (ModelState.IsValid)
            {
                // Create file from uploaded script
                string scriptLocation = string.Format(@"{0}/Downloads/{1}", _hostingEnv.ContentRootPath, id);
                System.IO.File.WriteAllBytes(scriptLocation, param.Content);

                // Add database entry for new script
                Download download = new Download
                {
                    Id = id,
                    ComputerName = param.ComputerName,
                    Name = param.Name,
                    FullPath = param.FullPath,
                    DownloadTime = DateTime.UtcNow,
                    ModifiedTime = param.ModifiedTime,
                    AccessedTime = param.AccessedTime,
                    BornTime = DateTime.UtcNow
                };
                _context.Downloads.Add(download);
                _context.SaveChanges();

                return Ok(download);
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}

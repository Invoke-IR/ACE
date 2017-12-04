using ACEWebService.Entities;
using ACEWebService.Services;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.AspNetCore.Hosting;

namespace ACEWebService.Controllers
{
    [Route("ace/[controller]")]
    public class DownloadController : Controller
    {
        private ACEWebServiceDbContext _context;
        private IHostingEnvironment _hostingEnv;
        private IDownloadService _downloadService;

        public DownloadController(ACEWebServiceDbContext context, IHostingEnvironment hostingEnv, IDownloadService downloadService)
        {
            _context = context;
            _hostingEnv = hostingEnv;
            _downloadService = downloadService;
        }

        // POST /ace/download
        [Authorize(Policy = "ApiKey")]
        [HttpPost]
        public IActionResult RequestFile([FromBody]DownloadRequestViewModel param)
        {
            if (ModelState.IsValid)
            {
                Guid Id = Guid.NewGuid();
                _downloadService.DownloadRequest(param, Id);
                return Ok(Id);
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
                _context.Downloads.Add(new Download{
                    Id = id,
                    ComputerName = param.ComputerName,
                    Name = param.Name,
                    FullPath = param.FullPath,
                    Content = param.Content,
                    DownloadTime = DateTime.UtcNow
                });
                _context.SaveChanges();

                return Ok(param.FullPath);
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}

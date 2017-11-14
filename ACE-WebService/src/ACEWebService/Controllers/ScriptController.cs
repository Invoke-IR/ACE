using ACEWebService.Entities;
using ACEWebService.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;

namespace ACEWebService.Controllers
{
    //[Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class ScriptController : Controller
    {
        private ACEWebServiceDbContext _context;
        private IHostingEnvironment _hostingEnv;

        public ScriptController(ACEWebServiceDbContext context, IHostingEnvironment hostingEnv)
        {
            _context = context;
            _hostingEnv = hostingEnv;
        }

        // GET /ace/script/delete/{id}
        [HttpGet("delete/{id}")]
        public Script Delete([FromRoute]Guid id)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                try
                {
                    Script script = _context.Scripts.SingleOrDefault(s => s.Id == id);

                    // Delete the script from disk
                    string scriptLocation = string.Format(@"{0}\{1}", _hostingEnv.ContentRootPath, script.Uri);
                    System.IO.File.Delete(scriptLocation);

                    // Remove the script from the database
                    _context.Scripts.Remove(script);
                    _context.SaveChanges();
                    return script;
                }
                catch
                {
                    throw new Exception("Failed to delete script.");
                }
            }
            else
            {
                throw new Exception("Only administrator users can delete credentials.");
            }
        }

        // GET /ace/script
        [HttpGet]
        public IEnumerable<Script> Get()
        {
            return _context.Scripts;
        }

        // POST /ace/script
        [HttpPost]
        public IActionResult Upload([FromBody]FileViewModel param)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                if (ModelState.IsValid)
                {
                    // Create a unique identifier for the uploaded script
                    Guid id = Guid.NewGuid();

                    // Create file from uploaded script
                    string scriptLocation = string.Format(@"{0}\scripts\{1}.ace", _hostingEnv.ContentRootPath, id);
                    System.IO.File.WriteAllBytes(scriptLocation, param.Content);

                    // Build enrichment string
                    StringBuilder enrichments = new StringBuilder();

                    foreach (string e in param.Enrichment)
                    {
                        enrichments.Append(string.Format("{0}.", e));
                    }

                    // Add database entry for new script
                    Script script = new Script
                    {
                        Id = id,
                        Name = param.Name,
                        Uri = string.Format(@"/scripts/{0}.ace", id),
                        Language = param.Language,
                        Enrichment = enrichments.ToString().Substring(0, enrichments.Length -2),
                        Output = param.Output,
                        CreationTime = DateTime.UtcNow,
                        LastUpdateTime = DateTime.UtcNow,
                    };
                    _context.Scripts.Add(script);
                    _context.SaveChanges();

                    return Ok(script);
                }
                else
                {
                    return BadRequest(ModelState);
                }
            }
            else
            {
                throw new Exception("Only Administrators can upload new scripts.");
            }
        }
    }
}
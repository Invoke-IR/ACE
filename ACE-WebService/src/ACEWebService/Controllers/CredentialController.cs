using ACEWebService.Entities;
using ACEWebService.Security;
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
    public class CredentialController : Controller
    {
        private ACEWebServiceDbContext _context;
        private ICryptographyService _cryptoService;

        public CredentialController(ACEWebServiceDbContext context, ICryptographyService cryptoService)
        {
            _context = context;
            _cryptoService = cryptoService;
        }

        // GET /ace/credential/delete/{id}
        [HttpGet("delete/{id}")]
        public Credential Delete([FromRoute]Guid id)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if(requestor.IsAdmin)
            {
                try
                {
                    Credential credential = _context.Credentials.SingleOrDefault(cred => cred.Id == id);
                    _context.Credentials.Remove(credential);
                    _context.SaveChanges();
                    return credential;
                }
                catch
                {
                    throw new Exception("Failed to delete credential");
                }
            }
            else
            {
                throw new Exception("Only administrator users can delete credentials.");
            }
        }

        // GET /ace/credential
        [HttpGet()]
        public IEnumerable<Credential> Get()
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                return _context.Credentials;
            }
            else
            {
                throw new Exception("Only administrator users can enumerate credentials.");
            }
        }

        // POST /ace/credential
        [HttpPost()]
        public IActionResult Post([FromBody]CredentialViewModel param)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                if (ModelState.IsValid)
                {
                    Credential cred = new Credential
                    {
                        UserName = param.UserName,
                        Password = _cryptoService.Encrypt(param.Password)
                    };
                    _context.Credentials.Add(cred);
                    _context.SaveChanges();
                    return Ok(cred);
                }
                else
                {
                    return BadRequest(ModelState);
                }
            }
            else
            {
                throw new Exception("Only administrator users can add new credentials.");
            }
        }

        // PUT /ace/credential/{id}
        [HttpPut("{id}")]
        public Credential Update([FromRoute]Guid Id, [FromBody]CredentialViewModel param)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if (requestor.IsAdmin)
            {
                Credential credential = _context.Credentials.SingleOrDefault(cred => cred.Id == Id);
                credential.UserName = param.UserName;
                credential.Password = _cryptoService.Encrypt(param.Password);
                _context.Credentials.Update(credential);
                _context.SaveChanges();
                return credential;
            }
            else
            {
                throw new Exception("Only administrator users can update credentials.");
            }
        }
    }
}

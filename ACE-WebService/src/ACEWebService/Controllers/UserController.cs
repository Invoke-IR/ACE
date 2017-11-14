using ACEWebService.Entities;
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
    public class UserController : Controller
    {
        private ACEWebServiceDbContext _context;

        public UserController(ACEWebServiceDbContext context)
        {
            _context = context;
        }

        // GET /ace/user/delete/{id}
        [HttpGet("delete/{id}")]
        public User Delete([FromRoute]Guid id)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if(requestor.IsAdmin)
            {
                if (id == requestor.Id)
                {
                    throw new Exception("A user cannot delete itself.");
                }
                else
                {
                    try
                    {
                        User user = _context.Users.SingleOrDefault(u => u.Id == id);
                        _context.Users.Remove(user);
                        _context.SaveChanges();
                        return user;
                    }
                    catch
                    {
                        throw new Exception("Failed to delete account.");
                    }
                }
            }
            else
            {
                throw new Exception("Only Administrator accounts can delete accounts.");
            }
        }

        // GET /ace/user
        [HttpGet]
        public IEnumerable<User> Get()
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if(requestor.IsAdmin)
            {
                return _context.Users;
            }
            else
            {
                List<User> userList = new List<User>();
                userList.Add(requestor);
                return userList;
            }
        }

        // POST /ace/user
        [HttpPost]
        public IActionResult Post([FromBody]UserViewModel param)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            if(requestor.IsAdmin)
            {
                if (ModelState.IsValid)
                {
                    User user = new User
                    {
                        UserName = param.UserName,
                        FirstName = param.FirstName,
                        LastName = param.LastName,
                        IsAdmin = param.IsAdmin,
                        ApiKey = Guid.NewGuid().ToString()
                    };
                    _context.Users.Add(user);
                    _context.SaveChanges();
                    return Ok(user);
                }
                else
                {
                    return BadRequest(ModelState);
                }
            }
            else
            {
                throw new Exception("Only Administrators can create accounts.");
            }
        }

        // PUT /ace/user/{id}
        [HttpPut("{Id}")]
        public User Update([FromRoute]Guid Id, [FromBody]UserViewModel param)
        {
            User requestor = _context.Users.SingleOrDefault(u => u.ApiKey == Request.Headers["X-ApiKey"]);

            User user = _context.Users.SingleOrDefault(u => u.Id == Id);
            user.UserName = param.UserName;
            user.FirstName = param.FirstName;
            user.LastName = param.LastName;
            user.IsAdmin = param.IsAdmin;
            _context.Users.Update(user);
            _context.SaveChanges();
            return user;
        }
    }
}

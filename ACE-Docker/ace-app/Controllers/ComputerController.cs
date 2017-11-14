using ACEWebService.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ACEWebService.Controllers
{
    [Authorize(Policy = "ApiKey")]
    [Route("ace/[controller]")]
    public class ComputerController : Controller
    {
        private ACEWebServiceDbContext _context;

        public ComputerController(ACEWebServiceDbContext context)
        {
            _context = context;
        }

        [HttpGet("{id}")]
        // GET /ace/computer/{id}
        public Computer Get([FromRoute]Guid id)
        {
            Computer computer = _context.Computers.SingleOrDefault(c => c.Id == id);
            return computer;
        }

        // GET /ace/computer
        [HttpGet()]
        public IEnumerable<Computer> Get()
        {
            return _context.Computers;
        }
    }
}

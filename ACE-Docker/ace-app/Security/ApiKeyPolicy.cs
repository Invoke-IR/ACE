using ACEWebService.Entities;
using ACEWebService.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using System.Linq;
using System.Threading.Tasks;

namespace ACEWebService.Security
{
    public class ApiKeyRequirement : IAuthorizationRequirement
    {
        public ApiKeyRequirement()
        {

        }
    }

    public class ApiKeyHandler : AuthorizationHandler<ApiKeyRequirement>
    {
        private ACEWebServiceDbContext _context;

        public ApiKeyHandler(ACEWebServiceDbContext context)
        {
            _context = context;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyRequirement requirement)
        {
            var mvcContext = context.Resource as Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext;

            if (mvcContext != null)
            {
                StringValues apiKeyHeaderValues = new StringValues();
                mvcContext.HttpContext.Request.Headers.TryGetValue("x-apikey", out apiKeyHeaderValues);

                User user = _context.Users.SingleOrDefault(u => u.ApiKey == apiKeyHeaderValues.ToString());
                if (user.ApiKey == apiKeyHeaderValues.ToString())
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }
}
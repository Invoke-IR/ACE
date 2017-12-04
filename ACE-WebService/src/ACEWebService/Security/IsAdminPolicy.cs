using ACEWebService.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using System.Linq;
using System.Threading.Tasks;

namespace ACEWebService.Security
{
    public class IsAdminRequirement : IAuthorizationRequirement
    {
        public IsAdminRequirement()
        {

        }
    }

    public class IsAdminHandler : AuthorizationHandler<ApiKeyRequirement>
    {
        private ACEWebServiceDbContext _context;

        public IsAdminHandler(ACEWebServiceDbContext context)
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
                    if (user.IsAdmin)
                    {
                        context.Succeed(requirement);
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
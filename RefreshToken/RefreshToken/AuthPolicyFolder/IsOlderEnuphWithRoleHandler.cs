using JWTRefreshTokenInDotNet6.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace RefreshToken.AuthPolicyFolder
{
    public class IsOlderEnuphWithRoleHandler : AuthorizationHandler<IsOlderEnuphWithRoleRequirments>
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public IsOlderEnuphWithRoleHandler(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, IsOlderEnuphWithRoleRequirments requirement)
        {
            var Age = context.User.Claims.Where(c => c.Type == "Age").FirstOrDefault().Value;
            var UserId = context.User.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).FirstOrDefault().Value;

            var User = await _userManager.FindByIdAsync(UserId);
            if (requirement.Age <= User.Age
                && context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
            await Task.CompletedTask;
        }
    }
}
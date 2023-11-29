using Microsoft.AspNetCore.Authorization;

namespace RefreshToken.AuthPolicyFolder
{
    public class IsOlderEnuphWithRoleRequirments : IAuthorizationRequirement
    {
        public IsOlderEnuphWithRoleRequirments(int Age)
        {
            this.Age = Age;
        }

        public int Age { get; set; }
    }
}
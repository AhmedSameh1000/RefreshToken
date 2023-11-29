using JWTRefreshTokenInDotNet6.Models;
using Microsoft.AspNetCore.Identity;

namespace RefreshToken.Seeding
{
    public class SeedRoles
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public SeedRoles(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public async Task SeedData()
        {
            var UserRole = new IdentityRole()
            {
                Id = "1",
                Name = "User",
                NormalizedName = "USER"
            };
            var AdminRole = new IdentityRole()
            {
                Id = "2",
                Name = "Admin",
                NormalizedName = "ADMIN"
            };
            await _roleManager.CreateAsync(UserRole);
            await _roleManager.CreateAsync(AdminRole);

            var UserToSeed = new ApplicationUser
            {
                Id = Guid.NewGuid().ToString(),
                Email = "Ahmed@gmail.com",
                UserName = "Ahmed@gmail.com",
                FirstName = "Ahmed",
                LastName = "Sameh",
                Age = 23
            };
            var Result = await _userManager.CreateAsync(UserToSeed, "ahmeds1490");

            if (Result.Succeeded)
            {
                await _userManager.AddToRoleAsync(UserToSeed, UserRole.Name);
                await _userManager.AddToRoleAsync(UserToSeed, AdminRole.Name);
            }
        }
    }
}
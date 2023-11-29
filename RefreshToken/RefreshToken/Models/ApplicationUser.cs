using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWTRefreshTokenInDotNet6.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50)]
        public string FirstName { get; set; }

        [MaxLength(50)]
        public int Age { get; set; }

        public string LastName { get; set; }

        public List<UserRefreshToken>? RefreshTokens { get; set; }
    }
}
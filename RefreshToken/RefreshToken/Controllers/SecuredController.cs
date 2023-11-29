using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTRefreshTokenInDotNet6.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult GetData()
        {
            var Names = new List<string>() { "Ahmed", "Sameh", "Ali", "Mohamed" };
            return Ok(Names);
        }
    }
}
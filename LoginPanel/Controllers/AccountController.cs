using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using LoginPanel.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;

namespace LoginPanel.Controllers;

public class AccountController : ControllerBase
{
    private UserManager<User> _userManager;
    private SignInManager<User> _signInManager;
    
    public AccountController(UserManager<User> userManager, SignInManager<User> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes("FvMY28K4FZVCwyhB");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString });
        }

        return Unauthorized();
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // Kullanıcı adı benzersiz mi kontrol et
        var existingUser = await _userManager.FindByNameAsync(model.UserName);
        if (existingUser != null)
        {
            return BadRequest("Kullanıcı adı zaten kullanılıyor.");
        }

        // Yeni kullanıcı oluştur
        var newUser = new User { UserName = model.UserName, FirstName = model.FirstName, LastName = model.LastName};
        var result = await _userManager.CreateAsync(newUser, model.Password);

        if (result.Succeeded)
        {
            // Kullanıcı başarıyla oluşturuldu, JWT token oluştur ve döndür
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes("FvMY28K4FZVCwyhB");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, newUser.Id)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString });
        }

        return BadRequest("Kullanıcı oluşturulamadı. Lütfen tekrar deneyin.");
    }
    
    [HttpGet("user-info")]
    [Authorize]
    public IActionResult GetUserInfo()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.Name);
        if (userIdClaim != null)
        {
            var userId = userIdClaim.Value;
            return Ok(userId);
        }

        return BadRequest("Kullanıcı bilgisi alınamadı");
    }
    
    


    
    
}
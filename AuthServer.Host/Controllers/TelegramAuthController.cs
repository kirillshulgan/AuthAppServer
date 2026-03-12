using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthServer.Host.Controllers;

[ApiController]
[Route("api/auth")]
public class TelegramAuthController : ControllerBase
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public TelegramAuthController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public class TelegramTokenRequest { public string Token { get; set; } }

    [HttpPost("telegram-token")]
    public async Task<IActionResult> VerifyToken([FromBody] TelegramTokenRequest request)
    {
        // 1. Получаем публичные ключи (JWKS) от самого Telegram
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "https://oauth.telegram.org/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever());

        var openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // 2. Настраиваем правила валидации токена
        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = "https://oauth.telegram.org",
            ValidAudience = "8720807101", // Ваш Telegram Client ID
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            // 3. Валидируем токен (если подпись не совпадет, выкинет Exception)
            var principal = tokenHandler.ValidateToken(request.Token, validationParameters, out var validatedToken);

            // 4. Достаем данные пользователя из токена
            var telegramId = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var name = principal.FindFirst("name")?.Value;

            if (string.IsNullOrEmpty(telegramId)) return Unauthorized("Invalid token claims.");

            // 5. Логика Identity: Ищем пользователя или создаем нового
            var info = new ExternalLoginInfo(principal, "Telegram", telegramId, "Telegram");
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: true, bypassTwoFactor: true);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                // Если аккаунта нет, создаем нового пользователя (упрощенный пример)
                var user = new ApplicationUser { UserName = $"tg_{telegramId}", Email = $"tg_{telegramId}@telegram.local" };
                var createResult = await _userManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    await _userManager.AddLoginAsync(user, info);
                    await _signInManager.SignInAsync(user, isPersistent: true);
                    return Ok();
                }
                return BadRequest("Could not create user.");
            }
        }
        catch (Exception ex)
        {
            // Токен невалидный, просрочен или подделан
            return Unauthorized(new { error = ex.Message });
        }
    }
}

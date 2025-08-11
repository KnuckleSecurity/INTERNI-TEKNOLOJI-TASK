namespace NewsApi.Endpoints;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;            // CookieOptions
using NewsApi.Infrastructure.Options;

public static class AuthEndpoints
{
    public record LoginRequest(string Username, string Password);

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder routes)
    {
        var g = routes.MapGroup("/auth").WithTags("Auth");

        // DEMO: sabit admin -> "admin" / "12345"
        g.MapPost("/login", (LoginRequest req, IOptions<JwtOptions> opt, HttpResponse res) =>
        {
            if (req.Username != "admin" || req.Password != "12345")
                return Results.Unauthorized();

            var jwt = opt.Value;
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, req.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwt.Issuer,
                audience: jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(jwt.ExpiresMinutes),
                signingCredentials: creds);

            var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);

            // JWT'yi HttpOnly cookie olarak yaz
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = false,           
                SameSite = SameSiteMode.Lax,  
                Expires = DateTime.UtcNow.AddMinutes(jwt.ExpiresMinutes),
                Path = "/"
            };

            res.Cookies.Append("access_token", tokenStr, cookieOptions);

            // Artık token'ı JSON içinde dönmüyoruz
            return Results.Ok(new { message = "Login başarılı" });
        });

        // Logout: cookie'yi sil
        g.MapPost("/logout", (HttpResponse res) =>
        {
            res.Cookies.Delete("access_token", new CookieOptions { Path = "/" });
            return Results.Ok(new { message = "Çıkış yapıldı" });
        });

        return routes;
    }
}

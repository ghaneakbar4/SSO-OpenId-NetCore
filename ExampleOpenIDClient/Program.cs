using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // SameSiteMode.None is required to support OpenID Connect.
    options.MinimumSameSitePolicy = SameSiteMode.None;
});

// Add cookie and OpenID Connect authentication services.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.ForwardChallenge = OpenIdConnectDefaults.AuthenticationScheme;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
})
.AddOpenIdConnect(options => {
    options.Authority = builder.Configuration["OpenID:Authority"];
    options.ClientId = builder.Configuration["OpenID:ClientId"];
    options.ClientSecret = builder.Configuration["OpenID:ClientSecret"];

    options.Scope.Clear();

    foreach (var scope in builder.Configuration.GetSection("OpenID:Scopes").Get<string[]>())
    {
        options.Scope.Add(scope);
    }

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.GetClaimsFromUserInfoEndpoint = true;

    options.ClaimsIssuer = OpenIdConnectDefaults.AuthenticationScheme;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = builder.Configuration["OpenID:NameClaimType"],

        // The following is only required if supporting HS256, HS384 or HS512.
        // If using the default RS256 signature algorithm, no issuer signing key has to be specified
        // as the key identifier in the JWT header is used to automatically retrieve the public key from the authority.
        // If using HS256, the client secret must be specified as the issuer signing key.
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["OpenID:ClientSecret"]))
    };

    options.SaveTokens = true;
});

// Add the HTTP client factory for demonstrating secure web API calls.
builder.Services.AddHttpClient();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();

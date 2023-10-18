using ComponentSpace.OpenID.Security;
using ExampleOpenIDProvider.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using Serilog;

WebApplication? app = null;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((hostBuilderContext, loggerConfiguration) => loggerConfiguration.ReadFrom.Configuration(hostBuilderContext.Configuration));

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Add the default identity but any authentication scheme may be used.
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddRazorPages();

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // SameSiteMode.None is required for SSO protocols.
    options.MinimumSameSitePolicy = SameSiteMode.None;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    // Use a unique identity cookie name rather than sharing the cookie across applications in the domain.
    options.Cookie.Name = "ExampleOpenIDProvider.Identity";

    // SameSiteMode.None is required to support SSO protocols.
    options.Cookie.SameSite = SameSiteMode.None;
});

// In a production environment, more restrictive CORS policy should be applied. 
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy =>
        {
            policy.WithOrigins("*").AllowAnyMethod().AllowAnyHeader();
        });
});

// Add OpenID provider services.
builder.Services.AddOpenIDProvider(builder.Configuration.GetSection("OpenIDProvider"));

// Optionally add SAML SSO services.
// This is required only if SAML SSO to an identity provider is supported.
builder.Services.AddSaml(builder.Configuration.GetSection("SAML"));

// Optionally add support for JWT bearer tokens.
// This is required only if JWT bearer tokens are used to authorize access to a web API.
builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["JWT:Authority"];
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidAudience = builder.Configuration["JWT:Audience"],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            // The default clock skew is 5 minutes. Specify a lower value in the TokenValidationParameters if testing expired access tokens.
            //ClockSkew = TimeSpan.Zero,

            // The following delegate is only required if supporting HS256, HS384 or HS512.
            // If using the default RS256 signature algorithm, no issuer signing key has to be returned as the
            // key identifier in the JWT header is used to automatically retrieve the public key from the authority.
            // If using HS256, the client secret must be returned as the issuer signing key.
            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
            {
                var tokenValidationDelegates = app!.Services.CreateScope().ServiceProvider.GetRequiredService<ITokenValidationDelegates>();

                return tokenValidationDelegates.IssuerSigningKeyResolver(token, securityToken, kid, validationParameters);
            }
        };
    });

builder.Services.AddRequiredScopeAuthorization();

// Optionally add a refresh token database.
// This is required only if refresh tokens are supported.
// An in-memory database is used. A production application would use a more appropriate provider.
builder.Services.AddDbContext<OpenIDUserContext>(options => options.UseInMemoryDatabase("OpenIDUser"));

app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseCors();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
// Simplifies the integration of Azure AD with ASP.NET Core applications. Provides helper classes
// for working with Microsoft Identity Platform, such as setting up OpenID Connect, token validation, and claims-based authentication.
// Manages interactions with Azure AD, such as token lifetimes, scopes, and UserInfo retrieval.
//Automatically validates ID tokens and retrieves user claims for authentication.
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Azure AD configuration - Inegrates AD for authentication using OpenID Connect and JWT Bearer for authorization
// This code configures OpenID Connect (OIDC) as the authentication scheme and integrates Azure AD via the Microsoft Identity Web library.
// AddMicrosoftIdentityWebApp reads the Azure AD settings from the "AzureAd" section of the appsettings.json file.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // This event is triggered when the ID token from Azure AD is successfully validated.
    // The event is used to generate a JWT token for the application to use for subsequent API calls.
    options.Events.OnTokenValidated = async context =>
    {
        Console.WriteLine("OnTokenValidated event triggered.");

        if (context.Principal != null)
        {
            Console.WriteLine($"User Principal: {context.Principal.Identity?.Name}");
            // Step 1. Retrieve User Information: Pull user details from the validated token:
          
            var username = context.Principal.FindFirst("name")?.Value; //retrieves the username claim.
            var email = context.Principal.Identity?.Name; //retrieves the email claim.

            if (username != null && email != null)
            {
                // Call API to generate token
                Console.WriteLine($"In Program.cs : Configure : {email} {username}");
                var token = await ApiTokenGenerator.GetTokenFromApi(
                    builder.Configuration["ApiUrl"] + "/api/auth/generateToken",
                    new { Username = username, Email = email, Role = "Employee" });

                if (!string.IsNullOrEmpty(token))
                {
                    //The generated JWT token is stored in the user's session for later use
                    context.HttpContext.Session.SetString("JwtToken", token);
                    Console.WriteLine("JWT Token stored in session.");
                }
            }
        }
        else
        {
            Console.WriteLine("Principal is null.");
        }
    };

    options.Events.OnRedirectToIdentityProviderForSignOut = async context =>
    {
        // This event is triggered when the user signs out. It ensures that the session is cleaned up
        context.HttpContext.Session.Remove("JwtToken");
    };
});

// JWT Bearer configuration (for subsequent authorization)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                context.Token = context.HttpContext.Session.GetString("JwtToken");
                return Task.CompletedTask;
            }
        };
    });


builder.Services.AddHttpClient(); // Add HttpClient support
//Adds support for Razor pages/views that integrate with Azure AD login/logout functionality.

builder.Services.AddControllersWithViews().AddMicrosoftIdentityUI();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set timeout duration
    options.Cookie.HttpOnly = true; // Make the session cookie accessible only through HTTP, not JavaScript
    options.Cookie.IsEssential = true; // Mark the cookie as essential for GDPR compliance
});


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
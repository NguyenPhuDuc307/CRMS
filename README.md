# CRMS

## Init Project

**Init project .NET API**

```sh
dotnet new webapi -o kozy-api
```

**Add packages**

```sh
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.AspNetCore.OpenApi
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.VisualStudio.Web.CodeGeneration.Design
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet add package Npgsql.EntityFrameworkCore.SQLServer
dotnet add package Swashbuckle.AspNetCore
```

**appsettings.json**

```json
"ConnectionStrings": {
  "DefaultConnection": "Host=localhost;Port=5432;Database=kozy_api;Username=ducnp"
}
```

**ApplicationUser.cs**

```cs
public class ApplicationUser : IdentityUser
{
    // Add any additional properties you need for your user here
}
```

**ApplicationDbContext.cs**

```cs
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Define DbSets for your entities here
    // public DbSet<YourEntity> YourEntities { get; set; }
}
```

**Program.cs**

```cs
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.")));

builder.Services.AddIdentityCore<ApplicationUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

**Migrate**

```sh
dotnet ef migrations add InitialCreate -o Data/Migrations
```

```sh
dotnet ef database update
```

## JWT

**appsettings.json**

```json
"Jwt": {
  "Key": "YourSuperSecretKeyThatShouldBeAtLeast256BitsLong!",
  "Issuer": "PionAPI",
  "Audience": "PionAPI",
  "ExpireMinutes": "60"
}
```

**JwtSettings.cs**

```cs
public class JwtSettings
{
    public string Key { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpireMinutes { get; set; }
}
```

**AuthDto.cs**

```cs
public class LoginDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class RegisterDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class AuthResponseDto
{
    public string Token { get; set; } = string.Empty;
}
```

**IJwtService.cs**

```cs
public interface IJwtService
{
    string GenerateToken(string userId);
}
```

**JwtService.cs**

```cs
public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;

    public JwtService(JwtSettings jwtSettings)
    {
        _jwtSettings = jwtSettings ?? throw new ArgumentNullException(nameof(jwtSettings));
    }

    public string GenerateToken(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            throw new ArgumentException("User ID cannot be null or empty.", nameof(userId));

        var keyBytes = Encoding.UTF8.GetBytes(_jwtSettings.Key);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
```

**Program.cs**

```cs
// JWT Configuration
var jwtSettings = new JwtSettings();
builder.Configuration.GetSection("Jwt").Bind(jwtSettings);
builder.Services.AddSingleton(jwtSettings);

var key = Encoding.ASCII.GetBytes(jwtSettings.Key);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddScoped<IJwtService, JwtService>();

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
// Swagger
const string BearerScheme = "Bearer";
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Swagger pion Management", Version = "v1" });

    c.AddSecurityDefinition(BearerScheme, new OpenApiSecurityScheme
    {
        Description = $@"JWT Authorization header using the {BearerScheme} scheme. \r\n\r\n
                      Enter '{BearerScheme}' [space] and then your token in the text input below.
                      \r\n\r\nExample: '{BearerScheme} 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = BearerScheme
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = BearerScheme
                },
                Scheme = "oauth2",
                Name = BearerScheme,
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});

// CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy =>
        {
            // TODO: Restrict origins in production environment
            policy.AllowAnyOrigin() // NOSONAR: Permissive for development
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});
```

```cs
app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Migration
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await dbContext.Database.MigrateAsync();
}

await app.RunAsync();
```

**AuthController.cs**

```cs
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;

    public AuthController(UserManager<ApplicationUser> userManager, IJwtService jwtService)
    {
        _userManager = userManager;
        _jwtService = jwtService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = _jwtService.GenerateToken(user.Id);
            return Ok(new AuthResponseDto
            {
                Token = token
            });
        }

        return Unauthorized("Invalid credentials");
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            var token = _jwtService.GenerateToken(user.Id);
            return Ok(new AuthResponseDto
            {
                Token = token
            });
        }

        return BadRequest(result.Errors);
    }
}
```

**REST Client**

```http
@kozy_api_HostAddress = http://localhost:5230/api

### 1.1. Register
POST {{kozy_api_HostAddress}}/auth/register
Content-Type: application/json

{
  "email": "admin@deha.vn",
  "password": "Admin@123"
}

### 1.2. Login
POST {{kozy_api_HostAddress}}/auth/login
Content-Type: application/json

{
  "email": "admin@deha.vn",
  "password": "Admin@123"
}
```

## Swagger

**Program.cs**

```cs
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
const string BearerScheme = "Bearer";
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Swagger pion Management", Version = "v1" });

    c.AddSecurityDefinition(BearerScheme, new OpenApiSecurityScheme
    {
        Description = $@"JWT Authorization header using the {BearerScheme} scheme. \r\n\r\n
                      Enter '{BearerScheme}' [space] and then your token in the text input below.
                      \r\n\r\nExample: '{BearerScheme} 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = BearerScheme
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = BearerScheme
                },
                Scheme = "oauth2",
                Name = BearerScheme,
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});
```

```cs
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

**launchSettings.json**

```json
"http": {
  "commandName": "Project",
  "dotnetRunMessages": true,
  "launchBrowser": true,
  "launchUrl": "swagger",
  "applicationUrl": "http://localhost:5230",
  "environmentVariables": {
    "ASPNETCORE_ENVIRONMENT": "Development"
  }
}
```

**Run**

```sh
dotnet watch run -lp=http
```













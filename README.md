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

## Docker

**Dockerfile**

```Dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["kozy-api.csproj", "./"]
RUN dotnet restore "kozy-api.csproj"
COPY . .
WORKDIR "/src"
RUN dotnet build "kozy-api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "kozy-api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

ENTRYPOINT ["dotnet", "kozy-api.dll"]
```

**docker-compose.yml**

```yml
services:
  kozy-api:
    build:
      context: ./
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    container_name: kozy-api
    environment:
      - ASPNETCORE_URLS=http://+:8080
      - ASPNETCORE_ENVIRONMENT=Development
      - ConnectionStrings__DefaultConnection=Host=postgres;Port=5432;Database=kozy;Username=ducnp;Password=password123
    depends_on:
      - postgres
    networks:
      - kozy-network

  postgres:
    image: postgres:15
    container_name: kozy-postgres
    environment:
      POSTGRES_DB: kozy
      POSTGRES_USER: ducnp
      POSTGRES_PASSWORD: password123
    ports:
      - "5435:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - kozy-network

volumes:
  postgres_data:

networks:
  kozy-network:
    driver: bridge
```

## CRUDS

**Author.cs**

```cs
public class Author
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public int BirthYear { get; set; }
    public string? Nationality { get; set; }
    public string? Biography { get; set; }
}
```

**Book.cs**

```cs
public class Book
{
    public int Id { get; set; }
    public string? Title { get; set; }
    public string? Genre { get; set; }
    public int PublicationYear { get; set; }
    public string? Synopsis { get; set; }
    public int AuthorId { get; set; }
    public Author? Author { get; set; } // Navigation property to Author
}
```

**Migrate**

```sh
dotnet ef migrations add AddAuthorEntityAndBookEntity
```

```sh
dotnet ef database update
```

**ApplicationDbContext.cs**

```cs
public DbSet<Author> Authors { get; set; }
public DbSet<Book> Books { get; set; }
```

**Generate API Controllers**

```sh
dotnet aspnet-codegenerator controller -name AuthorsController -async -api -m Author -dc ApplicationDbContext -outDir Controllers
```

```sh
dotnet aspnet-codegenerator controller -name BooksController -async -api -m Book -dc ApplicationDbContext -outDir Controllers
```

**REST Client**

```http
@kozy_api_HostAddress = http://localhost:5230/api
@token = 
@authorId = 1
@bookId = 1
@q = Author

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

### 2.1 Get All Authors with Query
GET {{kozy_api_HostAddress}}/authors?q={{q}}
Content-Type: application/json
Authorization: Bearer {{token}}

### 2.2 Get Author by ID
GET {{kozy_api_HostAddress}}/authors/{{authorId}}
Authorization: Bearer {{token}}

### 2.3 Create Author
POST {{kozy_api_HostAddress}}/authors
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "name": "New Author",
  "birthYear": 1980,
  "nationality": "American",
  "biography": "This is a new author."
}

### 2.4 Update Author
PUT {{kozy_api_HostAddress}}/authors/{{authorId}}
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "name": "Updated Author",
  "birthYear": 1985,
  "nationality": "British",
  "biography": "This is an updated author."
}

### 2.5 Delete Author
DELETE {{kozy_api_HostAddress}}/authors/{{authorId}}
Authorization: Bearer {{token}}

### 3.1 Get All Books with Query
GET {{kozy_api_HostAddress}}/books?q={{q}}
Content-Type: application/json
Authorization: Bearer {{token}}

### 3.2 Get Book by ID
GET {{kozy_api_HostAddress}}/books/{{bookId}}
Content-Type: application/json
Authorization: Bearer {{token}}

### 3.3 Create Book
POST {{kozy_api_HostAddress}}/books
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "New Book",
  "authorId": {{authorId}},
  "publishedYear": 2020,
  "genre": "Fiction",
  "summary": "This is a new book."
}

### 3.4 Update Book
PUT {{kozy_api_HostAddress}}/books/{{bookId}}
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "Updated Book",
  "authorId": {{authorId}},
  "publishedYear": 2021,
  "genre": "Non-Fiction",
  "summary": "This is an updated book."
}

### 3.5 Delete Book
DELETE {{kozy_api_HostAddress}}/books/{{bookId}}
Content-Type: application/json
Authorization: Bearer {{token}}
```

## UnitTest

**Init UnitTest**

```sh
dotnet new xunit -n kozy-api.Tests
```

**Addreference and packages**

```sh
dotnet add reference ../kozy-api/kozy-api.csproj
```

```sh
dotnet add package Microsoft.EntityFrameworkCore.InMemory
```

**JwtServiceTests.cs**

```cs
public class JwtServiceTests
{
    private readonly JwtService _service;
    private readonly JwtSettings _jwtSettings;

    public JwtServiceTests()
    {
        // Setup JWT settings
        _jwtSettings = new JwtSettings
        {
            Key = "MySecretKeyForJWTTokenGeneration1234567890",
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            ExpireMinutes = 60
        };

        _service = new JwtService(_jwtSettings);
    }

    [Fact]
    public void GenerateToken_ValidUserId_ReturnsToken()
    {
        // Arrange
        var userId = "test-user-id";

        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void GenerateToken_NullUserId_ReturnsToken()
    {
        // Act
        var token = _service.GenerateToken(null!);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Theory]
    [InlineData("")]
    public void GenerateToken_EmptyUserId_ReturnsToken(string userId)
    {
        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void Constructor_NullJwtSettings_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new JwtService(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void GenerateToken_InvalidKey_ThrowsException(string? key)
    {
        // Arrange
        var invalidSettings = new JwtSettings
        {
            Key = key!,
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            ExpireMinutes = 60
        };

        var service = new JwtService(invalidSettings);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => service.GenerateToken("test-user-id"));
    }

    [Fact]
    public void GenerateToken_ValidSettings_ContainsCorrectClaims()
    {
        // Arrange
        var userId = "test-user-id";

        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        // Token should be a valid JWT format (3 parts separated by dots)
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
    }
}
```

## Report Generator

```sh
dotnet tool install dotnet-reportgenerator-globaltool --tool-path tools
```

```sh
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults
```

**.netconfig**

```netconfig
[ReportGenerator]
	reports = "./TestResults/*/coverage.cobertura.xml"
	targetdir = "./CoverageReport"
	reporttypes = "Html"
	title = "Coverage Report"
	classfilters = "+kozy_api.Controllers.*;+kozy_api.Services.*;-*Tests"
```

**generate-coverage-report.sh**

```sh
#!/bin/bash

dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults

reportgenerator

# Open report in browser (macOS)
if command -v open &> /dev/null; then
    open ./CoverageReport/index.html
fi
```

```sh
chmod +x generate-coverage-report.sh
./generate-coverage-report.sh
```

















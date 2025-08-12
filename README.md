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
  "Issuer": "KozyAPI",
  "Audience": "KozyAPI",
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
builder.Services.AddIdentityCore<ApplicationUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

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

**.dockerignore**

```
# .NET build artifacts
bin/
obj/
out/

# Development files
*.Development.json
appsettings.Development.json

# Git and version control
.git/
.gitignore
.gitattributes

# Documentation
README.md
*.md

# IDE files
.vs/
.vscode/
*.sln.docstates
*.userprefs
*.pidb
*.suo
*.user
*.userosscache
*.sln.docstates

# Scripts and tools
*.sh
*.bat
*.ps1

# Sensitive files
*.key
*.pem
*.p12
*.pfx
secrets/
.env
.env.*

# Logs
logs/
*.log

# Temporary files
tmp/
temp/
.tmp/

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Docker files (to avoid nested Docker builds)
Dockerfile*
docker-compose*
```

**Dockerfile**

```Dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Create a non-root user
RUN addgroup --system --gid 1001 dotnet && \
    adduser --system --uid 1001 --ingroup dotnet dotnet

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy only the project file first for better layer caching
COPY ["kozy-api.csproj", "./"]
RUN dotnet restore "kozy-api.csproj"

# Copy only necessary source files (exclude sensitive data)
COPY ["Controllers/", "./Controllers/"]
COPY ["Data/", "./Data/"]
COPY ["Dtos/", "./Dtos/"]
COPY ["Models/", "./Models/"]
COPY ["Services/", "./Services/"]
COPY ["Properties/", "./Properties/"]
COPY ["Program.cs", "./"]
COPY ["appsettings.json", "./"]

WORKDIR "/src"
RUN dotnet build "kozy-api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "kozy-api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app

# Change ownership to non-root user
COPY --from=publish --chown=dotnet:dotnet /app/publish .

# Switch to non-root user
USER dotnet

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
    public int PublishedYear { get; set; }
    public string? Synopsis { get; set; }
    public int AuthorId { get; set; }
    public Author? Author { get; set; } // Navigation property to Author
}
```

**ApplicationDbContext.cs**

```cs
public DbSet<Author> Authors { get; set; }
public DbSet<Book> Books { get; set; }
```

**Migrate**

```sh
dotnet ef migrations add AddAuthorEntityAndBookEntity
```

```sh
dotnet ef database update
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
  "synopsis": "This is a new book."
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
  "synopsis": "This is an updated book."
}

### 3.5 Delete Book
DELETE {{kozy_api_HostAddress}}/books/{{bookId}}
Content-Type: application/json
Authorization: Bearer {{token}}
```

## UnitTest

**Add sln**

```sh
# Tạo solution file
dotnet new sln -n kozy-api

# Thêm projects vào solution
dotnet sln add kozy-api/kozy-api.csproj
dotnet sln add kozy-api.Tests/kozy-api.Tests.csproj

# Kiểm tra solution
dotnet sln list
```

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

## Statement Testing

**AuthControllerTests.cs**

```cs
public class AuthControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IJwtService> _jwtServiceMock;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        _jwtServiceMock = new Mock<IJwtService>();
        _controller = new AuthController(_userManagerMock.Object, _jwtServiceMock.Object);
    }

    [Fact]
    public async Task Login_ReturnsOk_WhenCredentialsAreValid()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user123", Email = "test@example.com", UserName = "test@example.com" };
        var loginDto = new LoginDto { Email = "test@example.com", Password = "password123" };

        _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, loginDto.Password)).ReturnsAsync(true);
        _jwtServiceMock.Setup(x => x.GenerateToken(user.Id)).Returns("test-token");

        // Act
        var result = await _controller.Login(loginDto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AuthResponseDto>(okResult.Value);
        Assert.Equal("test-token", response.Token);
    }

    [Fact]
    public async Task Login_ReturnsUnauthorized_WhenUserNotFound()
    {
        // Arrange
        var loginDto = new LoginDto { Email = "wrong@example.com", Password = "password123" };
        _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email)).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Login(loginDto);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid credentials", unauthorizedResult.Value);
    }

    [Fact]
    public async Task Login_ReturnsUnauthorized_WhenPasswordIsWrong()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user123", Email = "test@example.com", UserName = "test@example.com" };
        var loginDto = new LoginDto { Email = "test@example.com", Password = "wrong-password" };

        _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, loginDto.Password)).ReturnsAsync(false);

        // Act
        var result = await _controller.Login(loginDto);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid credentials", unauthorizedResult.Value);
    }

    [Fact]
    public async Task Register_ReturnsOk_WhenRegistrationSucceeds()
    {
        // Arrange
        var registerDto = new RegisterDto { Email = "test@example.com", Password = "password123" };
        var user = new ApplicationUser { Id = "new-user-123", Email = registerDto.Email, UserName = registerDto.Email };

        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                       .ReturnsAsync(IdentityResult.Success)
                       .Callback<ApplicationUser, string>((u, p) => u.Id = user.Id);
        _jwtServiceMock.Setup(x => x.GenerateToken(It.IsAny<string>())).Returns("new-token");

        // Act
        var result = await _controller.Register(registerDto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AuthResponseDto>(okResult.Value);
        Assert.Equal("new-token", response.Token);
    }

    [Fact]
    public async Task Register_ReturnsBadRequest_WhenRegistrationFails()
    {
        // Arrange
        var registerDto = new RegisterDto { Email = "test@example.com", Password = "weak" };
        var errors = new[] {
            new IdentityError { Code = "PasswordTooShort", Description = "Password is too short" },
            new IdentityError { Code = "InvalidEmail", Description = "Email is invalid" }
        };

        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                       .ReturnsAsync(IdentityResult.Failed(errors));

        // Act
        var result = await _controller.Register(registerDto);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        var returnedErrors = Assert.IsAssignableFrom<IEnumerable<IdentityError>>(badRequestResult.Value);
        Assert.Equal(2, returnedErrors.Count());
    }

    [Fact]
    public async Task Register_ReturnsBadRequest_WhenUserAlreadyExists()
    {
        // Arrange
        var registerDto = new RegisterDto { Email = "existing@example.com", Password = "password123" };
        var error = new IdentityError { Code = "DuplicateUserName", Description = "Username already exists" };

        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                       .ReturnsAsync(IdentityResult.Failed(error));

        // Act
        var result = await _controller.Register(registerDto);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        var returnedErrors = Assert.IsAssignableFrom<IEnumerable<IdentityError>>(badRequestResult.Value);
        Assert.Single(returnedErrors);
        Assert.Equal("DuplicateUserName", returnedErrors.First().Code);
    }
}
```

**AuthorsControllerTests.cs**

```cs
public class AuthorsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly AuthorsController _controller;

    public AuthorsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _controller = new AuthorsController(_context);
    }

    // Test data as property
    private static List<Author> SampleAuthors => new()
    {
        new Author { Id = 1, Name = "Author One" },
        new Author { Id = 2, Name = "Author Two" },
        new Author { Id = 3, Name = "Author Three" }
    };

    [Fact]
    public async Task GetAuthors_ReturnsAllAuthors_WhenNoQueryProvided()
    {
        // Arrange
        var authors = SampleAuthors.Take(2);
        _context.Authors.AddRange(authors);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetAuthors(null);

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Author>>>(result);
        var returnValue = Assert.IsType<List<Author>>(actionResult.Value);
        Assert.Equal(2, returnValue.Count);
    }

    [Fact]
    public async Task GetAuthors_ReturnsFilteredAuthors_WhenQueryProvided()
    {
        // Arrange
        var authors = SampleAuthors.Take(3);

        _context.Authors.AddRange(authors);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetAuthors("One");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Author>>>(result);
        var returnValue = Assert.IsType<List<Author>>(actionResult.Value);
        Assert.Single(returnValue);
        Assert.Equal("Author One", returnValue.First().Name);
    }

    [Fact]
    public async Task GetAuthor_ReturnsAuthor_WhenAuthorExists()
    {
        // Arrange
        var author = SampleAuthors.Take(1);

        _context.Authors.AddRange(author);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetAuthor(1);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Author>>(result);
        var returnValue = Assert.IsType<Author>(actionResult.Value);
        Assert.Equal("Author One", returnValue.Name);
    }

    [Fact]
    public async Task GetAuthor_ReturnsNotFound_WhenAuthorDoesNotExists()
    {
        // Arrange
        var author = SampleAuthors.Take(1);

        _context.Authors.AddRange(author);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetAuthor(999);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Author>>(result);
        Assert.IsType<NotFoundResult>(actionResult.Result);
    }

    [Fact]
    public async Task PostAuthor_ReturnsCreatedAtAction_WhenAuthorIsValid()
    {
        // Arrange
        var author = new Author { Name = "New Author" };

        // Act
        var result = await _controller.PostAuthor(author);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Author>>(result);
        var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(actionResult.Result);
        var returnValue = Assert.IsType<Author>(createdAtActionResult.Value);

        Assert.Equal("GetAuthor", createdAtActionResult.ActionName);
        Assert.Equal("New Author", returnValue.Name);
        Assert.True(returnValue.Id > 0);
    }

    [Fact]
    public async Task PutAuthor_ReturnsBadRequest_WhenIdDoesNotMatchAuthorId()
    {
        // Arrange
        var author = new Author { Id = 2, Name = "Test Author" };

        // Act - ID in URL (1) doesn't match author.Id (2)
        var result = await _controller.PutAuthor(1, author);

        // Assert
        Assert.IsType<BadRequestResult>(result);
    }

    [Fact]
    public async Task PutAuthor_ReturnsNotFound_WhenAuthorDoesNotExist()
    {
        // Arrange
        var nonExistentAuthor = new Author { Id = 999, Name = "Non-existent Author" };

        // Act
        var result = await _controller.PutAuthor(999, nonExistentAuthor);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task PutAuthor_UpdatesExistingAuthor_WhenValidDataProvided()
    {
        // Arrange
        var existingAuthor = new Author { Id = 1, Name = "Original Name" };
        _context.Authors.Add(existingAuthor);
        await _context.SaveChangesAsync();

        // Clear tracking to simulate fresh request
        _context.ChangeTracker.Clear();

        var updatedAuthor = new Author { Id = 1, Name = "Updated Name" };

        // Act
        var result = await _controller.PutAuthor(1, updatedAuthor);

        // Assert
        Assert.IsType<NoContentResult>(result);

        // Verify database was updated
        var authorFromDb = await _context.Authors.AsNoTracking().FirstOrDefaultAsync(a => a.Id == 1);
        Assert.NotNull(authorFromDb);
        Assert.Equal("Updated Name", authorFromDb.Name);
    }

    [Fact]
    public async Task DeleteAuthor_ReturnsNoContent_WhenAuthorExists()
    {
        // Arrange
        var existingAuthor = new Author { Id = 1, Name = "Author to Delete" };
        _context.Authors.Add(existingAuthor);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.DeleteAuthor(1);

        // Assert
        Assert.IsType<NoContentResult>(result);

        // Verify the author was actually deleted
        var authorInDb = await _context.Authors.FindAsync(1);
        Assert.Null(authorInDb);
    }

    [Fact]
    public async Task DeleteAuthor_ReturnsNotFound_WhenAuthorDoesNotExist()
    {
        // Act
        var result = await _controller.DeleteAuthor(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    public void Dispose()
    {
        // Clean up resources
        _context.Dispose();
    }
}
```

**BooksControllerTests.cs**

```cs
public class BooksControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly BooksController _controller;

    public BooksControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _controller = new BooksController(_context);
    }

    // Test data as property
    private static List<Book> SampleBooks => new()
    {
        new Book { Id = 1, Title = "The Great Gatsby" },
        new Book { Id = 2, Title = "To Kill a Mockingbird" },
        new Book { Id = 3, Title = "1984" },
        new Book { Id = 4, Title = "The Catcher in the Rye" }
    };

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetBooks Tests

    [Fact]
    public async Task GetBooks_ReturnsAllBooks_WhenNoQueryProvided()
    {
        // Arrange
        var books = SampleBooks.Take(3).ToList();
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks(null);

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Equal(3, returnValue.Count);
    }

    [Fact]
    public async Task GetBooks_ReturnsAllBooks_WhenEmptyQueryProvided()
    {
        // Arrange
        var books = SampleBooks.Take(2).ToList();
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks("");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Equal(2, returnValue.Count);
    }

    [Fact]
    public async Task GetBooks_ReturnsFilteredBooks_WhenQueryProvided()
    {
        // Arrange
        var books = SampleBooks.ToList();
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks("The");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Equal(2, returnValue.Count); // "The Great Gatsby" and "The Catcher in the Rye"
        Assert.All(returnValue, book => Assert.Contains("The", book.Title));
    }

    [Fact]
    public async Task GetBooks_ReturnsEmptyList_WhenQueryNotFound()
    {
        // Arrange
        var books = SampleBooks.Take(2).ToList();
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks("NonExistentBook");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Empty(returnValue);
    }

    [Fact]
    public async Task GetBooks_ReturnsEmptyList_WhenNoBooksExist()
    {
        // Act
        var result = await _controller.GetBooks(null);

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Empty(returnValue);
    }

    #endregion

    #region GetBook Tests

    [Fact]
    public async Task GetBook_ReturnsBook_WhenBookExists()
    {
        // Arrange
        var book = SampleBooks.First();
        _context.Books.Add(book);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBook(1);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Book>>(result);
        var returnValue = Assert.IsType<Book>(actionResult.Value);
        Assert.Equal("The Great Gatsby", returnValue.Title);
        Assert.Equal(1, returnValue.Id);
    }

    [Fact]
    public async Task GetBook_ReturnsNotFound_WhenBookDoesNotExist()
    {
        // Act
        var result = await _controller.GetBook(999);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Book>>(result);
        Assert.IsType<NotFoundResult>(actionResult.Result);
    }

    #endregion

    #region PostBook Tests

    [Fact]
    public async Task PostBook_ReturnsCreatedAtAction_WhenBookIsValid()
    {
        // Arrange
        var newBook = new Book { Title = "New Book Title" };

        // Act
        var result = await _controller.PostBook(newBook);

        // Assert
        var actionResult = Assert.IsType<ActionResult<Book>>(result);
        var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(actionResult.Result);
        var returnValue = Assert.IsType<Book>(createdAtActionResult.Value);

        Assert.Equal("GetBook", createdAtActionResult.ActionName);
        Assert.Equal("New Book Title", returnValue.Title);
        Assert.True(returnValue.Id > 0);

        // Verify book was saved to database
        var bookInDb = await _context.Books.FindAsync(returnValue.Id);
        Assert.NotNull(bookInDb);
        Assert.Equal("New Book Title", bookInDb.Title);
    }

    #endregion

    #region PutBook Tests

    [Fact]
    public async Task PutBook_ReturnsNoContent_WhenUpdateIsSuccessful()
    {
        // Arrange
        var existingBook = new Book { Id = 1, Title = "Original Title" };
        _context.Books.Add(existingBook);
        await _context.SaveChangesAsync();

        // Clear tracking to simulate fresh request
        _context.ChangeTracker.Clear();

        var updatedBook = new Book { Id = 1, Title = "Updated Title" };

        // Act
        var result = await _controller.PutBook(1, updatedBook);

        // Assert
        Assert.IsType<NoContentResult>(result);

        // Verify the book was actually updated
        var bookFromDb = await _context.Books.AsNoTracking().FirstOrDefaultAsync(b => b.Id == 1);
        Assert.NotNull(bookFromDb);
        Assert.Equal("Updated Title", bookFromDb.Title);
    }

    [Fact]
    public async Task PutBook_ReturnsBadRequest_WhenIdDoesNotMatchBookId()
    {
        // Arrange
        var book = new Book { Id = 2, Title = "Test Book" };

        // Act - ID in URL (1) doesn't match book.Id (2)
        var result = await _controller.PutBook(1, book);

        // Assert
        Assert.IsType<BadRequestResult>(result);
    }

    [Fact]
    public async Task PutBook_ReturnsNotFound_WhenBookDoesNotExist()
    {
        // Arrange
        var nonExistentBook = new Book { Id = 999, Title = "Non-existent Book" };

        // Act
        var result = await _controller.PutBook(999, nonExistentBook);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    #region DeleteBook Tests

    [Fact]
    public async Task DeleteBook_ReturnsNoContent_WhenBookExists()
    {
        // Arrange
        var existingBook = new Book { Id = 1, Title = "Book to Delete" };
        _context.Books.Add(existingBook);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.DeleteBook(1);

        // Assert
        Assert.IsType<NoContentResult>(result);

        // Verify the book was actually deleted
        var bookInDb = await _context.Books.FindAsync(1);
        Assert.Null(bookInDb);
    }

    [Fact]
    public async Task DeleteBook_ReturnsNotFound_WhenBookDoesNotExist()
    {
        // Act
        var result = await _controller.DeleteBook(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteBook_RemovesOnlySpecificBook_WhenMultipleBooksExist()
    {
        // Arrange
        var books = SampleBooks.Take(3).ToList();
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.DeleteBook(2); // Delete "To Kill a Mockingbird"

        // Assert
        Assert.IsType<NoContentResult>(result);

        // Verify correct book was deleted
        var remainingBooks = await _context.Books.ToListAsync();
        Assert.Equal(2, remainingBooks.Count);
        Assert.Contains(remainingBooks, b => b.Title == "The Great Gatsby");
        Assert.Contains(remainingBooks, b => b.Title == "1984");
        Assert.DoesNotContain(remainingBooks, b => b.Title == "To Kill a Mockingbird");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task GetBooks_HandlesCaseInsensitiveSearch()
    {
        // Arrange
        var books = new List<Book>
        {
            new Book { Id = 1, Title = "The Great Gatsby" },
            new Book { Id = 2, Title = "the catcher in the rye" }
        };
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks("the");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Equal(2, returnValue.Count); // Both should match
    }

    [Fact]
    public async Task GetBooks_HandlesNullTitle()
    {
        // Arrange
        var books = new List<Book>
        {
            new Book { Id = 1, Title = "Valid Title" },
            new Book { Id = 2, Title = null }
        };
        _context.Books.AddRange(books);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetBooks("Valid");

        // Assert
        var actionResult = Assert.IsType<ActionResult<IEnumerable<Book>>>(result);
        var returnValue = Assert.IsType<List<Book>>(actionResult.Value);
        Assert.Single(returnValue);
        Assert.Equal("Valid Title", returnValue.First().Title);
    }

    #endregion
}
```

## Sonarqube

**Install sonarqube by docker**

```yml
services:
  sonarqube-db:
    image: postgres:15-alpine
    container_name: sonarqube-postgres
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar
      POSTGRES_DB: sonarqube
    volumes:
      - sonarqube_postgres_data:/var/lib/postgresql/data
    networks:
      - sonarqube-network
    restart: unless-stopped

  sonarqube:
    image: sonarqube:10.3-community
    container_name: sonarqube-server
    depends_on:
      - sonarqube-db
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://sonarqube-db:5432/sonarqube
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar
      SONAR_ES_BOOTSTRAP_CHECKS_DISABLE: true
    ports:
      - "9000:9000"
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_logs:/opt/sonarqube/logs
      - sonarqube_extensions:/opt/sonarqube/extensions
    networks:
      - sonarqube-network
    restart: unless-stopped
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536

volumes:
  sonarqube_postgres_data:
  sonarqube_data:
  sonarqube_logs:
  sonarqube_extensions:

networks:
  sonarqube-network:
    driver: bridge
```

**Install tool dotnet-sonarscanner**

```sh
dotnet tool install --global dotnet-sonarscanner
```

**run-sonar.sh**

```sh
#!/bin/bash

# Remove any existing results directory to ensure a clean state
rm -rf ./TestResults

# Run tests with OpenCover format for SonarQube compatibility
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover

# Begin SonarQube analysis with OpenCover format
dotnet sonarscanner begin /k:"kozy-api" \
    /d:sonar.host.url="http://localhost:9000" \
    /d:sonar.token="sqp_c7fd42b17716ff30ad1b0901913a671a8b2e12e5" \
    /d:sonar.scanner.scanAll=false \
    /d:sonar.cs.opencover.reportsPaths="TestResults/**/coverage.opencover.xml" \
    /d:sonar.exclusions="**/bin/**,**/obj/**,**/wwwroot/**,**/Migrations/**,**/Program.cs,**/Dockerfile" \
    /d:sonar.test.exclusions="**/bin/**,**/obj/**"

# Build the project
dotnet build --no-restore

# End SonarQube analysis
dotnet sonarscanner end /d:sonar.token="sqp_c7fd42b17716ff30ad1b0901913a671a8b2e12e5"
```

## Frontend - Angular

### Install Angular CLI

```sh
npm install -g @angular/cli
```

**Init Angular Project**

```sh
ng new kozy-client --routing=true --style=scss --package-manager=npm
```

**Bootstrap, HTTP client and reactive forms**

```sh
npm install bootstrap @popperjs/core
npm install @angular/forms @angular/common
```

**angular.json**

```json
"styles": [
  "node_modules/bootstrap/dist/css/bootstrap.min.css",
  "src/styles.scss"
],
"scripts": [
  "node_modules/bootstrap/dist/js/bootstrap.bundle.min.js"
]
```

### Generate component and service

```sh
ng generate component shared/navbar --skip-tests
ng generate component components/navbar
ng generate component pages/login --skip-tests
ng generate component pages/authors --skip-tests
ng generate component pages/books --skip-tests
```

**src/app/app.routes.ts**

```ts
export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'authors', component: AuthorsComponent, canActivate: [authGuard] },
  { path: 'books', component: BooksComponent, canActivate: [authGuard] },
  { path: '**', redirectTo: '/home' }
];
```

```sh
ng generate service services/auth --skip-tests
ng generate guard guards/auth --skip-tests
```

### Models

**src/app/models/auth.model.ts**

```ts
export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user?: any;
}

export interface User {
  id: number;
  email: string;
}
```

### Services

**src/app/services/author.service.ts**

```ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';
import { LoginRequest, RegisterRequest, AuthResponse } from '../models/auth.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:5230/api/auth';
  private tokenKey = 'auth_token';
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(this.hasToken());

  constructor(private http: HttpClient) { }

  get isAuthenticated(): Observable<boolean> {
    return this.isAuthenticatedSubject.asObservable();
  }

  login(credentials: LoginRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/login`, credentials)
      .pipe(
        tap(response => {
          if (response.token) {
            localStorage.setItem(this.tokenKey, response.token);
            this.isAuthenticatedSubject.next(true);
          }
        })
      );
  }

  register(userData: RegisterRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/register`, userData);
  }

  logout(): void {
    localStorage.removeItem(this.tokenKey);
    this.isAuthenticatedSubject.next(false);
  }

  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  private hasToken(): boolean {
    return !!this.getToken();
  }

  isLoggedIn(): boolean {
    return this.hasToken();
  }
}
```

**src/app/guards/auth.guard.ts**

```ts
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn()) {
    return true;
  } else {
    router.navigate(['/login']);
    return false;
  }
};
```

### Navbar

**src/app/components/navbar/navbar.component.ts**

```ts
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss'
})
export class NavbarComponent {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  isLoggedIn(): boolean {
    return this.authService.isLoggedIn();
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }
}
```

**src/app/components/navbar/navbar.component.html**

```html
<nav class="navbar navbar-expand-lg bg-body-tertiary">
  <div class="container-fluid">
    <a class="navbar-brand" routerLink="/">Kozy Library</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item">
          <a class="nav-link" routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{exact: true}">Home</a>
        </li>
        @if (isLoggedIn()) {
          <li class="nav-item">
            <a class="nav-link" routerLink="/authors" routerLinkActive="active">Authors</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" routerLink="/books" routerLinkActive="active">Books</a>
          </li>
          <li class="nav-item">
            <button class="nav-link btn" (click)="logout()">Logout</button>
          </li>
        } @else {
          <li class="nav-item">
            <a class="nav-link" routerLink="/login">Login</a>
          </li>
        }
      </ul>
    </div>
  </div>
</nav>
```

### App Component

**src/app/app.component.ts**

```ts
import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { NavbarComponent } from './components/navbar/navbar.component';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, NavbarComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {

}
```

**src/app/app.component.html**

```html
<app-navbar></app-navbar>
<router-outlet />
```

app.config.ts

```ts
import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';

import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }), 
    provideRouter(routes),
    provideHttpClient()
  ]
};
```

### Login

**src/app/pages/login/login.component.ts**

```ts
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { LoginRequest } from '../../models/auth.model';

@Component({
  selector: 'app-login',
  imports: [CommonModule, FormsModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent {
  credentials: LoginRequest = {
    email: '',
    password: ''
  };
  
  errorMessage: string = '';
  isLoading: boolean = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  onSubmit(): void {
    if (this.credentials.email && this.credentials.password) {
      this.isLoading = true;
      this.errorMessage = '';
      
      this.authService.login(this.credentials).subscribe({
        next: (response) => {
          this.isLoading = false;
          this.router.navigate(['/']);
        },
        error: (error) => {
          this.isLoading = false;
          this.errorMessage = error.error?.message || 'Login failed. Please try again.';
        }
      });
    }
  }
}
```

**src/app/pages/login/login.component.html**

```html
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
      <div class="card shadow">
        <div class="card-body">
          <h3 class="card-title text-center mb-4">Login</h3>
          
          @if (errorMessage) {
            <div class="alert alert-danger" role="alert">
              {{ errorMessage }}
            </div>
          }
          
          <form (ngSubmit)="onSubmit()" #loginForm="ngForm">
            <div class="mb-3">
              <label for="email" class="form-label">Email</label>
              <input 
                type="email" 
                class="form-control" 
                id="email" 
                name="email"
                [(ngModel)]="credentials.email" 
                required 
                email
                #email="ngModel">
              @if (email.invalid && (email.dirty || email.touched)) {
                <div class="text-danger mt-1">
                  @if (email.errors?.['required']) {
                    Email is required
                  }
                  @if (email.errors?.['email']) {
                    Please enter a valid email
                  }
                </div>
              }
            </div>
            
            <div class="mb-3">
              <label for="password" class="form-label">Password</label>
              <input 
                type="password" 
                class="form-control" 
                id="password" 
                name="password"
                [(ngModel)]="credentials.password" 
                required
                minlength="6"
                #password="ngModel">
              @if (password.invalid && (password.dirty || password.touched)) {
                <div class="text-danger mt-1">
                  @if (password.errors?.['required']) {
                    Password is required
                  }
                  @if (password.errors?.['minlength']) {
                    Password must be at least 6 characters
                  }
                </div>
              }
            </div>
            
            <div class="d-grid">
              <button 
                type="submit" 
                class="btn btn-primary"
                [disabled]="loginForm.invalid || isLoading">
                @if (isLoading) {
                  <span class="spinner-border spinner-border-sm me-2"></span>
                  Logging in...
                } @else {
                  Login
                }
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
```

**src/app/pages/home/home.component.ts**

```ts
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-home',
  imports: [CommonModule, RouterModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {
  constructor(private authService: AuthService) {}

  isLoggedIn(): boolean {
    return this.authService.isLoggedIn();
  }
}
```

## CRUDS

### Generate Environment Files

**src/environments/environment.ts**

```ts
export const environment = {
  production: false,
  apiUrl: 'http://localhost:5230/api'
};
```


**src/environments/environment.prod.ts**

```ts
export const environment = {
  production: true,
  apiUrl: 'http://localhost:8080/api'
};
```

### Models

**src/app/models/book.model.ts**

```ts
export interface Author {
  id: number;
  name: string;
  birthYear: number;
  nationality: string;
  biography: string;
}

export interface Book {
  id: number;
  title: string;
  authorId: number;
  publishedYear: number;
  genre: string;
  summary: string;
  author?: Author;
}
```

```sh
ng generate service services/author --skip-tests
ng generate service services/book --skip-tests
```

**src/app/services/author.service.ts**

```ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Author } from '../models/book.model';
import { AuthService } from './auth.service';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthorService {
  private apiUrl = `${environment.apiUrl}/authors`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) {}

  private getHeaders(): HttpHeaders {
    const token = this.authService.getToken();
    return new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });
  }

  getAuthors(query?: string): Observable<Author[]> {
    const url = query ? `${this.apiUrl}?q=${query}` : this.apiUrl;
    return this.http.get<Author[]>(url, { headers: this.getHeaders() });
  }

  getAuthor(id: number): Observable<Author> {
    return this.http.get<Author>(`${this.apiUrl}/${id}`, { headers: this.getHeaders() });
  }

  createAuthor(author: Omit<Author, 'id'>): Observable<Author> {
    return this.http.post<Author>(this.apiUrl, author, { headers: this.getHeaders() });
  }

  updateAuthor(id: number, author: Omit<Author, 'id'>): Observable<Author> {
    return this.http.put<Author>(`${this.apiUrl}/${id}`, author, { headers: this.getHeaders() });
  }

  deleteAuthor(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`, { headers: this.getHeaders() });
  }
}

```

**src/app/services/book.service.ts**

```ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Book } from '../models/book.model';
import { AuthService } from './auth.service';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class BookService {
  private apiUrl = `${environment.apiUrl}/books`;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) {}

  private getHeaders(): HttpHeaders {
    const token = this.authService.getToken();
    return new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });
  }

  getBooks(query?: string): Observable<Book[]> {
    const url = query ? `${this.apiUrl}?q=${query}` : this.apiUrl;
    return this.http.get<Book[]>(url, { headers: this.getHeaders() });
  }

  getBook(id: number): Observable<Book> {
    return this.http.get<Book>(`${this.apiUrl}/${id}`, { headers: this.getHeaders() });
  }

  createBook(book: Omit<Book, 'id'>): Observable<Book> {
    return this.http.post<Book>(this.apiUrl, book, { headers: this.getHeaders() });
  }

  updateBook(id: number, book: Omit<Book, 'id'>): Observable<Book> {
    return this.http.put<Book>(`${this.apiUrl}/${id}`, book, { headers: this.getHeaders() });
  }

  deleteBook(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`, { headers: this.getHeaders() });
  }
}
```

**src/app/pages/authors/authors.component.ts**

```ts
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Author } from '../../models/book.model';
import { AuthorService } from '../../services/author.service';

@Component({
  selector: 'app-authors',
  imports: [CommonModule, FormsModule],
  templateUrl: './authors.component.html',
  styleUrl: './authors.component.scss'
})
export class AuthorsComponent implements OnInit {
  authors: Author[] = [];
  searchQuery = '';
  showModal = false;
  editingAuthor: Author | null = null;
  authorData = { name: '', birthYear: 2024, nationality: '', biography: '' };
  errorMessage = '';

  constructor(private authorService: AuthorService) {}

  ngOnInit(): void {
    this.loadAuthors();
  }

  loadAuthors(): void {
    this.authorService.getAuthors().subscribe({
      next: authors => this.authors = authors,
      error: () => this.errorMessage = 'Failed to load authors'
    });
  }

  searchAuthors(): void {
    const query = this.searchQuery.trim() || undefined;
    this.authorService.getAuthors(query).subscribe({
      next: authors => this.authors = authors,
      error: () => this.errorMessage = 'Search failed'
    });
  }

  openCreateModal(): void {
    this.editingAuthor = null;
    this.authorData = { name: '', birthYear: 2024, nationality: '', biography: '' };
    this.errorMessage = '';
    this.showModal = true;
  }

  editAuthor(author: Author): void {
    this.editingAuthor = author;
    this.authorData = { ...author };
    this.errorMessage = '';
    this.showModal = true;
  }

  closeModal(): void {
    this.showModal = false;
  }

  saveAuthor(): void {
    this.errorMessage = '';
    const payload = this.editingAuthor ? { id: this.editingAuthor.id, ...this.authorData } : this.authorData;
    const operation = this.editingAuthor 
      ? this.authorService.updateAuthor(this.editingAuthor.id, payload)
      : this.authorService.createAuthor(payload);
    
    operation.subscribe({
      next: () => {
        this.closeModal();
        this.loadAuthors();
      },
      error: () => this.errorMessage = 'Save failed'
    });
  }

  deleteAuthor(id: number, name: string): void {
    if (confirm(`Delete "${name}"?`)) {
      this.authorService.deleteAuthor(id).subscribe({
        next: () => this.loadAuthors(),
        error: () => this.errorMessage = 'Delete failed'
      });
    }
  }
}
```

```html
<div class="container mt-4">
  <div class="d-flex justify-content-between mb-4">
    <h2>Authors</h2>
    <button class="btn btn-primary" (click)="openCreateModal()">Add Author</button>
  </div>
  
  @if (errorMessage) {
    <div class="alert alert-danger">{{ errorMessage }}</div>
  }
  
  <div class="row mb-3">
    <div class="col-6">
      <input type="text" class="form-control" placeholder="Search..." [(ngModel)]="searchQuery" (keyup.enter)="searchAuthors()">
    </div>
    <div class="col-auto">
      <button class="btn btn-secondary" (click)="searchAuthors()">Search</button>
    </div>
  </div>

  <table class="table">
    <thead>
      <tr>
        <th>Name</th>
        <th>Birth Year</th>
        <th>Nationality</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      @for (author of authors; track author.id) {
        <tr>
          <td>{{ author.name }}</td>
          <td>{{ author.birthYear }}</td>
          <td>{{ author.nationality }}</td>
          <td>
            <button class="btn btn-sm btn-primary me-1" (click)="editAuthor(author)">Edit</button>
            <button class="btn btn-sm btn-danger" (click)="deleteAuthor(author.id, author.name)">Delete</button>
          </td>
        </tr>
      }
    </tbody>
  </table>
</div>

@if (showModal) {
  <div class="modal show d-block">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5>{{ editingAuthor ? 'Edit Author' : 'Add Author' }}</h5>
          <button type="button" class="btn-close" (click)="closeModal()"></button>
        </div>
        <form (ngSubmit)="saveAuthor()">
          <div class="modal-body">
            <div class="mb-3">
              <label class="form-label">Name</label>
              <input type="text" class="form-control" [(ngModel)]="authorData.name" name="name" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Birth Year</label>
              <input type="number" class="form-control" [(ngModel)]="authorData.birthYear" name="birthYear" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Nationality</label>
              <input type="text" class="form-control" [(ngModel)]="authorData.nationality" name="nationality" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Biography</label>
              <textarea class="form-control" [(ngModel)]="authorData.biography" name="biography" rows="3" required></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" (click)="closeModal()">Cancel</button>
            <button type="submit" class="btn btn-primary">{{ editingAuthor ? 'Update' : 'Create' }}</button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <div class="modal-backdrop show"></div>
}
```

**src/app/pages/books/books.component.ts**

```ts
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Book, Author } from '../../models/book.model';
import { BookService } from '../../services/book.service';
import { AuthorService } from '../../services/author.service';
import { forkJoin } from 'rxjs';

@Component({
  selector: 'app-books',
  imports: [CommonModule, FormsModule],
  templateUrl: './books.component.html',
  styleUrl: './books.component.scss'
})
export class BooksComponent implements OnInit {
  books: Book[] = [];
  authors: Author[] = [];
  errorMessage = '';
  searchQuery = '';
  showModal = false;
  editingBook: Book | null = null;
  bookData = { title: '', authorId: 0, publishedYear: 2024, genre: '', synopsis: '' };

  constructor(
    private bookService: BookService,
    private authorService: AuthorService
  ) { }

  ngOnInit(): void {
    this.loadData();
  }

  loadData(): void {
    this.errorMessage = '';
    forkJoin({
      books: this.bookService.getBooks(),
      authors: this.authorService.getAuthors()
    }).subscribe({
      next: ({ books, authors }) => {
        this.authors = authors;
        this.books = books;
      },
      error: () => this.errorMessage = 'Failed to load data'
    });
  }

  getAuthorName(authorId: number): string {
    const author = this.authors.find(a => a.id === authorId);
    return author?.name || 'Unknown';
  }

  searchBooks(): void {
    const query = this.searchQuery.trim() || undefined;
    this.bookService.getBooks(query).subscribe({
      next: books => this.books = books,
      error: () => this.errorMessage = 'Search failed'
    });
  }

  openCreateModal(): void {
    this.editingBook = null;
    this.bookData = { title: '', authorId: 0, publishedYear: 2024, genre: '', synopsis: '' };
    this.errorMessage = '';
    this.showModal = true;
  }

  editBook(book: Book): void {
    this.editingBook = book;
    this.bookData = { ...book };
    this.errorMessage = '';
    this.showModal = true;
  }

  closeModal(): void {
    this.showModal = false;
  }

  saveBook(): void {
    this.errorMessage = '';
    const payload = this.editingBook ? { id: this.editingBook.id, ...this.bookData } : this.bookData;
    const operation = this.editingBook
      ? this.bookService.updateBook(this.editingBook.id, payload)
      : this.bookService.createBook(payload);

    operation.subscribe({
      next: () => {
        this.closeModal();
        this.loadData();
      },
      error: () => this.errorMessage = 'Save failed'
    });
  }

  deleteBook(id: number, title: string): void {
    if (confirm(`Delete "${title}"?`)) {
      this.bookService.deleteBook(id).subscribe({
        next: () => this.loadData(),
        error: () => this.errorMessage = 'Delete failed'
      });
    }
  }
}
```

```html
<div class="container mt-4">
  <div class="d-flex justify-content-between mb-4">
    <h2>Books</h2>
    <button class="btn btn-primary" (click)="openCreateModal()">Add Book</button>
  </div>

  @if (errorMessage) {
    <div class="alert alert-danger">{{ errorMessage }}</div>
  }

  <div class="row mb-3">
    <div class="col-6">
      <input type="text" class="form-control" placeholder="Search..." [(ngModel)]="searchQuery" (keyup.enter)="searchBooks()">
    </div>
    <div class="col-auto">
      <button class="btn btn-secondary" (click)="searchBooks()">Search</button>
    </div>
  </div>

  <table class="table">
    <thead>
      <tr>
        <th>Title</th>
        <th>Author</th>
        <th>Year</th>
        <th>Genre</th>
        <th>Synopsis</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      @for (book of books; track book.id) {
        <tr>
          <td>{{ book.title }}</td>
          <td>{{ getAuthorName(book.authorId) }}</td>
          <td>{{ book.publishedYear }}</td>
          <td>{{ book.genre }}</td>
          <td>{{ book.synopsis }}</td>
          <td>
            <button class="btn btn-sm btn-primary me-1" (click)="editBook(book)">Edit</button>
            <button class="btn btn-sm btn-danger" (click)="deleteBook(book.id, book.title)">Delete</button>
          </td>
        </tr>
      }
    </tbody>
  </table>
</div>

@if (showModal) {
  <div class="modal show d-block">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5>{{ editingBook ? 'Edit Book' : 'Add Book' }}</h5>
          <button type="button" class="btn-close" (click)="closeModal()"></button>
        </div>
        <form (ngSubmit)="saveBook()">
          <div class="modal-body">
            <div class="mb-3">
              <label class="form-label">Title</label>
              <input type="text" class="form-control" [(ngModel)]="bookData.title" name="title" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Author</label>
              <select class="form-select" [(ngModel)]="bookData.authorId" name="authorId" required>
                <option value="">Select author</option>
                @for (author of authors; track author.id) {
                  <option [value]="author.id">{{ author.name }}</option>
                }
              </select>
            </div>
            <div class="mb-3">
              <label class="form-label">Year</label>
              <input type="number" class="form-control" [(ngModel)]="bookData.publishedYear" name="year" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Genre</label>
              <input type="text" class="form-control" [(ngModel)]="bookData.genre" name="genre" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Synopsis</label>
              <textarea class="form-control" [(ngModel)]="bookData.synopsis" name="synopsis" rows="3" required></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" (click)="closeModal()">Cancel</button>
            <button type="submit" class="btn btn-primary">{{ editingBook ? 'Update' : 'Create' }}</button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <div class="modal-backdrop show"></div>
}
```

## Docker

**Dockerfile**

```Dockerfile
# Dockerfile for kozy-client (Angular)
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build -- --configuration=production --output-path=dist/kozy-client
RUN ls -l dist/kozy-client

FROM nginx:alpine
COPY --from=build /app/dist/kozy-client/browser /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**.dockerignore**

```dockerignore
node_modules
npm-debug.log
dist
.git
.gitignore
README.md
.env
.nyc_output
coverage
.coverage
.coverage.*
*.log
.DS_Store
Thumbs.db
```

**docker-compose.yml**

```yml
services:
  kozy-client:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:80"
    environment:
    - NODE_ENV=production
    container_name: kozy-client
    restart: unless-stopped

```

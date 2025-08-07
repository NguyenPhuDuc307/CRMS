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























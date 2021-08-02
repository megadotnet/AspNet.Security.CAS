using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.Security.CAS;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CookieSample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            //https://stackoverflow.com/questions/50262561/correlation-failed-in-net-core-asp-net-identity-openid-connect
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.Secure = CookieSecurePolicy.Always;
            });

            // Setup based on https://github.com/aspnet/Security/tree/rel/2.0.0/samples/SocialSample
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o =>
                {
                    o.LoginPath = new PathString("/login");

                    o.AccessDeniedPath = new PathString("/access-denied");

                    o.Cookie = new CookieBuilder
                    {
                        Name = ".AspNetCore.CasSample"
                    };

                    o.Events = new CookieAuthenticationEvents
                    {
                        // Add user roles to the existing identity.  
                        // This example is giving every user "User" and "Admin" roles.
                        // You can use services or other logic here to determine actual roles for your users.
                        OnSigningIn = context =>
                        {
                            // Use `GetRequiredService` if you have a service that is using DI or an EF Context.
                            // var username = context.Principal.Identity.Name;
                            // var userSvc = context.HttpContext.RequestServices.GetRequiredService<UserService>();
                            // var roles = userSvc.GetRoles(username);
                            
                            // Hard coded roles.
                            var roles = new[] { "User", "Admin" };

                            // `AddClaim` is not available directly from `context.Principal.Identity`.
                            // We can add a new empty identity with the roles we want to the principal. 
                            var identity = new ClaimsIdentity();
                            
                            foreach (var role in roles)
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                            }

                            context.Principal.AddIdentity(identity);

                            return Task.FromResult(0);
                        }
                    };
                })
                .AddCAS(o =>
                {
                    o.CasServerUrlBase = Configuration["CasBaseUrl"];   // Set in `appsettings.json` file.
                    o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                });

            services.AddControllersWithViews();

  
            //// You can make the site require Authorization on all endpoints by default:
            //var globalAuthPolicy = new AuthorizationPolicyBuilder()
            //    .RequireAuthenticatedUser()
            //    .Build();

            //services.AddMvc(options =>
            //{
            //    options.Filters.Add(new AuthorizeFilter(globalAuthPolicy));
            //});
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseRouting();
            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}");
            });
        }
    }
}

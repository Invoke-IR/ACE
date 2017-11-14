using ACEWebService.Services;
using ACEWebService.Entities;
using ACEWebService.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Text;
using VTIProxy.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNet.Identity.EntityFramework;
using System;

namespace ACEWebService
{
    public class Startup
    {
        private IHostingEnvironment _currentEnvironment { get; set; }

        public Startup(IHostingEnvironment env)
        {
            _currentEnvironment = env;

            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            services.AddDbContext<ACEWebServiceDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddAuthorization(
                options =>
                {
                    options.AddPolicy("ApiKey", policy => policy.Requirements.Add(new ApiKeyRequirement()));
                }
            );

            services.AddSingleton<IAuthorizationHandler, ApiKeyHandler>();

            services.AddScoped<IAceConfiguration, AceConfiguration>(
                provider =>
                {
                    return new AceConfiguration(Configuration);
                }
            );

            services.AddScoped<ICryptographyService, AESCryptographyService>(
                provider =>
                {
                    return new AESCryptographyService(Configuration);
                }
            );

            services.AddScoped<IDiscoveryService, DiscoveryActiveDirectoryService>();

            /*
            services.AddScoped<ISweepResultProcessorService, SweepResultFileWriterService>(
                provider =>
                {
                    return new SweepResultFileWriterService(@"C:\test\scans");
                }
            );
            */

            services.AddScoped<ISweepResultProcessorService, ScanResultRabbitMQService>(
                provider =>
                {
                    return new ScanResultRabbitMQService(Configuration);
                }
            );

            services.AddScoped<ISweepExecutionService, SweepExecutionService>();

            services.AddScoped<ISchedulingService, SchedulingQuartzService>(
                provider =>
                {
                    return new SchedulingQuartzService();
                }
            );

            services.AddApiVersioning(
                o =>
                {
                    o.ApiVersionReader = new HeaderApiVersionReader("X-API-Version");
                    o.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);

                    if (_currentEnvironment.IsDevelopment())
                    {
                        o.AssumeDefaultVersionWhenUnspecified = true;
                    }
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            var provider = new FileExtensionContentTypeProvider();
            provider.Mappings[".ps1"] = "text/plain";
            provider.Mappings[".py"] = "text/plain";
            provider.Mappings[".ace"] = "text/plain";

            app.UseStaticFiles(); // For the wwwroot folder

            app.UseStaticFiles(new StaticFileOptions()
            {
                FileProvider = new PhysicalFileProvider(
                    Path.Combine(Directory.GetCurrentDirectory(), "scripts")),
                RequestPath = new PathString("/scripts"),
                ContentTypeProvider = provider
            });

            app.UseExceptionHandler(GlobalExceptionHandler);
            app.UseMvc();
        }

        public void GlobalExceptionHandler(IApplicationBuilder builder)
        {
            builder.Run(async context =>
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json; charset=utf-8";

                var error = context.Features.Get<IExceptionHandlerFeature>();
                var excpetion = error.Error;
                if (error != null)
                {
                    await context.Response.WriteAsync(new ErrorViewModel()
                    {
                        Message = excpetion.Message,
                        StackTrace = excpetion.StackTrace
                    }.ToString(), Encoding.UTF8);
                }
            });
        }
    }
}
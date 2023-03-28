using System;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace PlanningToolSSOServer.Data.Migrations.IdentityServer
{
    public static class IdentityServerDatabaseInitialization
    {
        public static void InitializeDatabase(IServiceProvider services)
        {
            PerformMigrations(services);
            SeedData(services);
        }

        private static void PerformMigrations(IServiceProvider services)
        {
            //services.GetRequiredService<ApplicationDbContext>().Database.Migrate();
            services.GetRequiredService<ConfigurationDbContext>().Database.Migrate();
            services.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
        }

        private static void SeedData(IServiceProvider services)
        {
            var context = services.GetRequiredService<ConfigurationDbContext>();
            var config = services.GetRequiredService<IConfiguration>();

            var clients = Config.GetClients(config);
            clients = clients.Where(x => !context.Clients.Select(y => y.ClientId).Contains(x.ClientId));
            if (clients.Count() > 0)
            {
                foreach (var client in clients) { 
                    context.Clients.Add(client.ToEntity());
                }

                context.SaveChanges();
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in Config.GetIdentityResources())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            var apiResource = Config.GetApiResources();
            apiResource = apiResource.Where(x => !context.ApiResources.Select(y => y.Name).Contains(x.Name));
            if (apiResource.Count() > 0)
            {
                foreach (var resource in Config.GetApiResources())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
        }
    }
}
using System.Collections.Generic;
using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;

namespace PlanningToolSSOServer
{
    public class Config
    {
        public const string loginLocalRedirectUri = "http://localhost:4200/";
        public const string loginLocalPostLogoutRedirectUri = "http://localhost:4200/";
        public const string loginLocalAllowedCorsOrigin = "http://localhost:4200";

        public const string facilityStaffAllowedCorsOrigin = "https://msh2facilityfe.azurewebsites.net";

        public const string staffRolemanagrRedirectUri = "https://msh2sso.azurewebsites.net/Account/RoleManager";
        // scopes define the resources in your system
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("nsh", "NorthStarHub API", new List<string> { "role" })
            };
        }

        // clients want to access resources (aka scopes)
        public static IEnumerable<Client> GetClients(IConfiguration configuration)
        {
            // client credentials client
            return new List<Client>
            {
                new Client
                {
                    ClientId = "ng",
                    ClientName = "Angular Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,
                    RequireConsent = false,
                    AccessTokenLifetime=36000,

                    RedirectUris = {loginLocalRedirectUri},
                    PostLogoutRedirectUris = {loginLocalPostLogoutRedirectUri},
                    AllowedCorsOrigins = {loginLocalAllowedCorsOrigin},
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "nsh"
                    },
                }
            };
        }
    }
}
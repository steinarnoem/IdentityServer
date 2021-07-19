// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using FluentAssertions;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using IntegrationTests.Common;
using Xunit;
using IdentityModel;

namespace IntegrationTests.Endpoints.Token
{
    public class TokenEndpointTests
    {
        private const string Category = "Token endpoint";

        private string client_id = "client";
        private string client_secret = "secret";

        private string scope_name = "api";
        private string scope_secret = "api_secret";

        private IdentityServerPipeline _mockPipeline = new IdentityServerPipeline();

        public TokenEndpointTests()
        {
            _mockPipeline.Clients.Add(new Client
            {
                ClientId = client_id,
                ClientSecrets = new List<Secret> { new Secret(client_secret.Sha256()) },
                AllowedGrantTypes = { GrantType.ClientCredentials, GrantType.ResourceOwnerPassword },
                AllowedScopes = new List<string> { "api" },
            });


            _mockPipeline.Users.Add(new TestUser
            {
                SubjectId = "bob",
                Username = "bob",
                Password = "password",
                Claims = new Claim[]
                {
                    new Claim("name", "Bob Loblaw"),
                    new Claim("email", "bob@loblaw.com"),
                    new Claim("role", "Attorney")
                }
            });

            _mockPipeline.IdentityScopes.AddRange(new IdentityResource[] {
                new IdentityResources.OpenId()
            });

            _mockPipeline.ApiResources.AddRange(new ApiResource[] {
                new ApiResource
                {
                    Name = "api",
                    ApiSecrets = new List<Secret> { new Secret(scope_secret.Sha256()) },
                    Scopes = {scope_name}
                }
            });

            _mockPipeline.ApiScopes.AddRange(new[] {
                new ApiScope
                {
                    Name = scope_name
                }
            });

            _mockPipeline.Initialize();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task client_credentials_request_with_funny_headers_should_not_hang()
        {
            var data = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", client_id },
                { "client_secret", client_secret },
                { "scope", scope_name },
            };
            var form = new FormUrlEncodedContent(data);
            _mockPipeline.BackChannelClient.DefaultRequestHeaders.Add("Referer", "http://127.0.0.1:33086/appservice/appservice?t=1564165664142?load");
            var response = await _mockPipeline.BackChannelClient.PostAsync(IdentityServerPipeline.TokenEndpoint, form);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result.ContainsKey("error").Should().BeFalse();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task resource_owner_request_with_funny_headers_should_not_hang()
        {
            var data = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "username", "bob" },
                { "password", "password" },
                { "client_id", client_id },
                { "client_secret", client_secret },
                { "scope", scope_name },
            };
            var form = new FormUrlEncodedContent(data);
            _mockPipeline.BackChannelClient.DefaultRequestHeaders.Add("Referer", "http://127.0.0.1:33086/appservice/appservice?t=1564165664142?load");
            var response = await _mockPipeline.BackChannelClient.PostAsync(IdentityServerPipeline.TokenEndpoint, form);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result.ContainsKey("error").Should().BeFalse();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task client_credentials_request_with_DPoP_headers_should_not_fail()
        {
            var data = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", client_id },
                { "client_secret", client_secret },
                { "scope", scope_name },
            };
            var form = new FormUrlEncodedContent(data);
            _mockPipeline.BackChannelClient.DefaultRequestHeaders.Add("DPoP", "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg");
            var response = await _mockPipeline.BackChannelClient.PostAsync(IdentityServerPipeline.TokenEndpoint, form);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result.ContainsKey("error").Should().BeFalse();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task client_credentials_request_with_DPoP_headers_should_result_in_cnf_claim_in_AT()
        {
            var data = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", client_id },
                { "client_secret", client_secret },
                { "scope", scope_name },
            };
            var form = new FormUrlEncodedContent(data);
            _mockPipeline.BackChannelClient.DefaultRequestHeaders.Add("DPoP", "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg");
            var response = await _mockPipeline.BackChannelClient.PostAsync(IdentityServerPipeline.TokenEndpoint, form);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

            result.ContainsKey("access_token").Should().BeTrue();

            var payloadBase64 = result["access_token"].ToString().Split(".")[1];
            var payloadJson = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64Url.Decode(payloadBase64));            

            payloadJson.ContainsKey("cnf").Should().BeTrue();

            var jkt = payloadJson["cnf"].GetProperty("jkt");
            jkt.Should().NotBeNull();
        }
    }
}

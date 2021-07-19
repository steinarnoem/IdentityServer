// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using IdentityModel;
using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityServer.Endpoints.Results;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Hosting;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using System.Text;
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Duende.IdentityServer.Endpoints
{
    /// <summary>
    /// The token endpoint
    /// </summary>
    /// <seealso cref="IEndpointHandler" />
    internal class TokenEndpoint : IEndpointHandler
    {
        private readonly IClientSecretValidator _clientValidator;
        private readonly ITokenRequestValidator _requestValidator;
        private readonly ITokenResponseGenerator _responseGenerator;
        private readonly IEventService _events;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenEndpoint" /> class.
        /// </summary>
        /// <param name="clientValidator">The client validator.</param>
        /// <param name="requestValidator">The request validator.</param>
        /// <param name="responseGenerator">The response generator.</param>
        /// <param name="events">The events.</param>
        /// <param name="logger">The logger.</param>
        public TokenEndpoint(
            IClientSecretValidator clientValidator, 
            ITokenRequestValidator requestValidator, 
            ITokenResponseGenerator responseGenerator, 
            IEventService events, 
            ILogger<TokenEndpoint> logger)
        {
            _clientValidator = clientValidator;
            _requestValidator = requestValidator;
            _responseGenerator = responseGenerator;
            _events = events;
            _logger = logger;
        }

        /// <summary>
        /// Processes the request.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <returns></returns>
        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            _logger.LogTrace("Processing token request.");

            // validate HTTP
            if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasApplicationFormContentType())
            {
                _logger.LogWarning("Invalid HTTP request for token endpoint");
                return Error(OidcConstants.TokenErrors.InvalidRequest);
            }

           


            return await ProcessTokenRequestAsync(context);
        }

        private async Task<IEndpointResult> ProcessTokenRequestAsync(HttpContext context)
        {
            _logger.LogDebug("Start token request.");

            // validate client
            var clientResult = await _clientValidator.ValidateAsync(context);

            if (clientResult.Client == null)
            {
                return Error(OidcConstants.TokenErrors.InvalidClient);
            }

            // validate request
            var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
            _logger.LogTrace("Calling into token request validator: {type}", _requestValidator.GetType().FullName);
            var requestResult = await _requestValidator.ValidateRequestAsync(form, clientResult);

            if (requestResult.IsError)
            {
                await _events.RaiseAsync(new TokenIssuedFailureEvent(requestResult));
                return Error(requestResult.Error, requestResult.ErrorDescription, requestResult.CustomResponse);
            }

            //https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-03
            var dpopHeader = context.Request.Headers["DPoP"];
            var dpopHeaderString = dpopHeader[0];
            try
            {
                var tokenAsString = new StringBuilder();
                var parts = dpopHeaderString.Split(".");
                var joseHeader = parts[0];
                var decodedJoseHeader = Base64Url.Decode(joseHeader);
                
                var jwtHeader = Encoding.UTF8.GetString(decodedJoseHeader);

                var jwk = @"{""kty"":""EC"", ""x"":""l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"",""y"":""9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"",""crv"":""P-256""}";

                var key = new JsonWebKey(jwk);
                
                var thumb = key.ComputeJwkThumbprint();
                var thumbString = Base64Url.Encode(thumb);                               


                    /*To check if a string that was received as part of an HTTP Request is
       a valid DPoP proof, the receiving server MUST ensure that

       1.  the string value is a well-formed JWT,

       2.  all required claims per Section 4.2 are contained in the JWT,

       3.  the "typ" field in the header has the value "dpop+jwt",

       4.  the algorithm in the header of the JWT indicates an asymmetric
           digital signature algorithm, is not "none", is supported by the
           application, and is deemed secure,

       5.  the JWT signature verifies with the public key contained in the
           "jwk" header of the JWT,

       6.  the "htm" claim matches the HTTP method value of the HTTP request
           in which the JWT was received,

       7.  the "htu" claims matches the HTTPS URI value for the HTTP request
           in which the JWT was received, ignoring any query and fragment
           parts,

       8.  the token was issued within an acceptable timeframe and, within a
           reasonable consideration of accuracy and resource utilization, a
           proof JWT with the same "jti" value has not previously been
           received at the same resource during that time period (see
           Section 8.1).

       Servers SHOULD employ Syntax-Based Normalization and Scheme-Based
       Normalization in accordance with Section 6.2.2. and Section 6.2.3. of
       [RFC3986] before comparing the "htu" claim.*/

                    JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
                SecurityToken validatedToken;
                var validationParameters = new TokenValidationParameters();
                validationParameters.IssuerSigningKey = key;
                validationParameters.ValidateIssuerSigningKey = true;
                validationParameters.RequireAudience = false;
                validationParameters.ValidateIssuer = false;
                validationParameters.ValidateAudience = false;         
                validationParameters.RequireExpirationTime = false;
                
                //For å validere med JWK i tokenet: hent ut JWK - https://stackoverflow.com/questions/58601556/how-to-validate-jwt-token-using-jwks-in-dot-net-core

                jwtHandler.ValidateToken(dpopHeaderString, validationParameters, out validatedToken);

                if (validatedToken == null)
                    return Error("DPoP Error", "DPoP validation failed", requestResult.CustomResponse);

                requestResult.ValidatedRequest.DPoPThumbprint = thumbString;
            }
            catch (Exception ex)
            {                
                return Error("DPoP Error", ex.Message, requestResult.CustomResponse);
            }

            // create response
            _logger.LogTrace("Calling into token request response generator: {type}", _responseGenerator.GetType().FullName);
            var response = await _responseGenerator.ProcessAsync(requestResult);

            await _events.RaiseAsync(new TokenIssuedSuccessEvent(response, requestResult));
            LogTokens(response, requestResult);

            // return result
            _logger.LogDebug("Token request success.");
            return new TokenResult(response);
        }

        private TokenErrorResult Error(string error, string errorDescription = null, Dictionary<string, object> custom = null)
        {
            var response = new TokenErrorResponse
            {
                Error = error,
                ErrorDescription = errorDescription,
                Custom = custom
            };

            return new TokenErrorResult(response);
        }

        private void LogTokens(TokenResponse response, TokenRequestValidationResult requestResult)
        {
            var clientId = $"{requestResult.ValidatedRequest.Client.ClientId} ({requestResult.ValidatedRequest.Client?.ClientName ?? "no name set"})";
            var subjectId = requestResult.ValidatedRequest.Subject?.GetSubjectId() ?? "no subject";

            if (response.IdentityToken != null)
            {
                _logger.LogTrace("Identity token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.IdentityToken);
            }
            if (response.RefreshToken != null)
            {
                _logger.LogTrace("Refresh token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.RefreshToken);
            }
            if (response.AccessToken != null)
            {
                _logger.LogTrace("Access token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.AccessToken);
            }
        }
    }
}
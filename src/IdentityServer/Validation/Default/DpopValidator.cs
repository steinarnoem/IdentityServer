using Duende.IdentityServer.Extensions;
using IdentityModel;

using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Duende.IdentityServer.Validation
{
    /// <summary>
    /// 
    /// </summary>
    public class DpopValidator : IDpopValidator
    {
        ValidatedDpopProof _proof;

        #region validation rules for dpop
        /*To check if a string that was received as part of an HTTP Request is
a valid DPoP proof, the receiving server MUST ensure that

X - 1.  the string value is a well-formed JWT,

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

        #endregion

        /// <summary>
        /// 
        /// </summary>
        public DpopValidator()
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task<DpopValidationResult> ValidateAsync(HttpContext context)
        {
            _proof = new ValidatedDpopProof(context);           

            if (_proof.DpopHeader == null)
                return null;

            //1. check for claims presence - e.g. jwk?

            //2. check "typ"
            if (!_proof.JoseHeader.ContainsKey("typ"))
            {
                return Invalid("DPoP proof does not contain \"typ\" claim", null, null);              
            }

            if (_proof.JoseHeader["typ"].GetString() != "dpop+jwt")
            {
                return Invalid("DPoP proof is not correct type");
            }

            //3. check algorithm
            if (!_proof.JoseHeader.ContainsKey("alg"))
            {
                return Invalid("DPoP proof is not well formed", "JOSE header does not contain \"alg\" claim", null);
            }

            var algorithms = new string[] { "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" };
            var joseAlg = _proof.JoseHeader["alg"].GetString();

            if (joseAlg == "none")
                return Invalid("DPoP jose header cannot contain \"none\" as value");

            if (!Array.Exists(algorithms, alg => alg == joseAlg))
            {
                return Invalid("DPoP jose header contains invalid algorithm", null, null);
            }


            //4. Validate jwt signature using key in jose handler
            var jwtHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = _proof.Jwk,
                ValidateIssuerSigningKey = true,
                RequireAudience = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false
            };

            jwtHandler.ValidateToken(_proof.DpopHeader, validationParameters, out var validatedToken);

            if (validatedToken == null)
                return Invalid("DPoP Error", "DPoP validation failed", null);
            
            return new DpopValidationResult(_proof, null, null);
        }


        private DpopValidationResult Invalid(string error, string errorDescription = null, Dictionary<string, object> customResponse = null)
        {
            return new DpopValidationResult(_proof, error, errorDescription, customResponse);
        }


        private Task<DpopValidationResult> Error(string v, string message, object customResponse)
        {
            throw new NotImplementedException();
        }

       



        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="clientValidationResult"></param>
        /// <returns></returns>
        public Task ValidateDpopProofAsync(NameValueCollection parameters, string DpopProof)
        {

            return null;
        }
    }
}

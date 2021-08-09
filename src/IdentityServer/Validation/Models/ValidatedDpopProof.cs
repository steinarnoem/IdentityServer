using Duende.IdentityServer.Extensions;
using IdentityModel;
using IdentityModel.Jwk;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;

namespace Duende.IdentityServer.Validation
{
    /// <summary>
    /// 
    /// </summary>
    public class ValidatedDpopProof
    {

        /// <summary>
        /// 
        /// </summary>
        private HttpContext _context;

        /// <summary>
        /// 
        /// </summary>
        public string DpopHeader { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public Dictionary<string, JsonElement> JoseHeader { get; }
        public Dictionary<string, JsonElement> Payload { get; }

        /// <summary>
        /// 
        /// </summary>
        public Microsoft.IdentityModel.Tokens.JsonWebKey Jwk { get; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] Thumbprint { get; }

        /// <summary>
        /// 
        /// </summary>
        public string ThumbprintBase64Url { get; }
        public bool RequestContainsDpopProof { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public ValidatedDpopProof(HttpContext context)
        {
            _context = context;
            DpopHeader = GetDpopHeader();
            JoseHeader = GetJoseHeader();
            Payload = GetJwtPayload();

            Jwk = GetJWK();
            Thumbprint = Jwk.ComputeJwkThumbprint();
            ThumbprintBase64Url = Base64Url.Encode(Thumbprint);
        }

        private Microsoft.IdentityModel.Tokens.JsonWebKey GetJWK()
        {
            if (JoseHeader.ContainsKey("jwk"))
            {
                var key = new Microsoft.IdentityModel.Tokens.JsonWebKey(JoseHeader["jwk"].GetRawText());
                return key;
            }
            else
                throw new System.Exception("jwk element missing in DPoP proof");
        }

        private Dictionary<string, JsonElement> GetJoseHeader()
        {
            if (DpopHeader == null)
                throw new System.Exception("Missing DPoP header");

            var joseHeader = DpopHeader.Split(".")[0];

            var jwtHeader = Encoding.UTF8.GetString(Base64Url.Decode(joseHeader));

            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jwtHeader);

            if (result == null || result.Count == 0)
                throw new System.Exception("Missing jose header in DPoP proof");

            return result;
        }

        private Dictionary<string, JsonElement> GetJwtPayload()
        {
            if (DpopHeader == null)
                throw new System.Exception("Missing DPoP header");

            var encodedPayload = DpopHeader.Split(".")[1];

            var payload = Encoding.UTF8.GetString(Base64Url.Decode(encodedPayload));

            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload);

            if (result == null || result.Count == 0)
                throw new System.Exception("Missing payload in DPoP proof");

            return result;
        }

        private string GetDpopHeader()
        {
            var dpopHeader = _context.Request.Headers["DPoP"];
            if (!dpopHeader.IsNullOrEmpty())
            {
                var dpopHeaderString = dpopHeader[0];
                return dpopHeaderString;
            }
            return null;
        }
    }
}

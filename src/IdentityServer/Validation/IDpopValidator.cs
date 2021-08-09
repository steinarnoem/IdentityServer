using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Duende.IdentityServer.Validation
{
    /// <summary>
    /// Validates the DpopProof
    /// </summary>
    public interface IDpopValidator
    {        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="DpopProof"></param>
        /// <returns></returns>
        Task ValidateDpopProofAsync(NameValueCollection parameters, string DpopProof);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        Task<DpopValidationResult> ValidateAsync(HttpContext context);
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Duende.IdentityServer.Validation
{
    /// <summary>
    /// 
    /// </summary>
    public class DpopValidationResult : ValidationResult
    {
        private ValidatedDpopProof _proof;
        private string _error;
        private string _errorDescription;
        private Dictionary<string, object> _customResponse;

        /// <summary>
        /// 
        /// </summary>
        public Dictionary<string, object> CustomResponse { get; }

        /// <summary>
        /// 
        /// </summary>
        public ValidatedDpopProof ValidatedDpopProof { get; }

        /// <summary>
        /// 
        /// </summary>
        public string Thumbprint { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedDpopProof"></param>
        /// <param name="customResponse"></param>
        public DpopValidationResult(ValidatedDpopProof validatedDpopProof, string error, Dictionary<string, object> customResponse = null)
        {
            IsError = false;

            CustomResponse = customResponse;
            ValidatedDpopProof = validatedDpopProof;
        }

        /// <summary>
        /// /
        /// </summary>
        /// <param name="proof"></param>
        /// <param name="error"></param>
        /// <param name="errorDescription"></param>
        /// <param name="customResponse"></param>
        public DpopValidationResult(ValidatedDpopProof proof, string error, string errorDescription, Dictionary<string, object> customResponse)
        {
            _proof = proof;
            _error = error;
            _errorDescription = errorDescription;
            _customResponse = customResponse;
        }
    }
}

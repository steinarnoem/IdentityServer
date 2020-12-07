using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Duende.IdentityServer.Logging
{
    public class TimedOperation : IDisposable
    {
        private readonly ILogger _logger;
        private readonly string _name;
        private readonly Stopwatch _stopwatch;

        public TimedOperation(ILogger logger, string name)
        {
            _logger = logger;
            _name = name;
            _stopwatch = new Stopwatch();
            _stopwatch.Start();
        }
        
        public void Dispose()
        {
            var elapsed = _stopwatch.Elapsed.TotalMilliseconds;

            _logger.LogTrace("Operation {operation} completed in {elapsed} milliseconds.", _name, elapsed);
            _stopwatch.Stop();
        }
    }
}
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal interface IProcessEnricher
    {
        Dictionary<int, ProcessInfo> CaptureProcesses();
    }
}

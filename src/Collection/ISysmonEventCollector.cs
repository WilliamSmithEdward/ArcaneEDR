namespace ArcaneEDR
{
    internal interface ISysmonEventCollector
    {
        SysmonTelemetry Capture();
    }
}

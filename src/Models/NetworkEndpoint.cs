using System;
using System.Globalization;
using System.Collections.Generic;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class NetworkEndpoint
    {
        public string Protocol;
        public IPAddress LocalAddress;
        public int LocalPort;
        public IPAddress RemoteAddress;
        public int RemotePort;
        public string State;
        public int ProcessId;
        public string ProcessName;
        public string RemoteHost;
        public string RemoteRdns = "";
        public List<string> RemoteDnsNames = new List<string>();
        public string SniHostname = "";
        public string ResolvedDomain = "";
        public string RegistrableDomain = "";
        public string RemoteAsn = "";
        public string RemoteAsnOrg = "";
        public string RemoteOwner = "";
        public string RemoteCountry = "";
        public bool RemoteCountryLookupAttempted;
        public string RemoteCountryLookupStatus = "";
        public string RemoteEnrichmentSource = "";
        public ProcessInfo Process;
        public string Source;

        public bool IsTcpListener
        {
            get { return Protocol == "TCP" && State == "LISTENING"; }
        }

        public bool IsUdpSocket
        {
            get { return Protocol == "UDP"; }
        }

        public bool IsEstablishedTcp
        {
            get { return Protocol == "TCP" && (State == "ESTABLISHED" || State == "SYSMON") && RemotePort > 0; }
        }

        public string ConnectionKey
        {
            get
            {
                return Protocol + "|" + LocalAddress + "|" + LocalPort.ToString(CultureInfo.InvariantCulture) + "|" +
                    RemoteAddress + "|" + RemotePort.ToString(CultureInfo.InvariantCulture) + "|" +
                    ProcessId.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "process=" + ProcessName +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " protocol=" + Protocol +
                    " local=" + LocalAddress + ":" + LocalPort.ToString(CultureInfo.InvariantCulture) +
                    " remote=" + RemoteAddress + ":" + RemotePort.ToString(CultureInfo.InvariantCulture) +
                    " remote_ip=" + RemoteAddress +
                    " remote_host=" + TextFormatting.EmptyIfNull(RemoteHost) +
                    " rdns=" + TextFormatting.EmptyIfNull(RemoteRdns) +
                    " dns_names=" + TextFormatting.EmptyIfNull(String.Join(";", RemoteDnsNames.ToArray())) +
                    " sni_hostname=" + TextFormatting.EmptyIfNull(SniHostname) +
                    " resolved_domain=" + TextFormatting.EmptyIfNull(ResolvedDomain) +
                    " registrable_domain=" + TextFormatting.EmptyIfNull(RegistrableDomain) +
                    " asn=" + TextFormatting.EmptyIfNull(RemoteAsn) +
                    " asn_org=" + TextFormatting.EmptyIfNull(RemoteAsnOrg) +
                    " remote_owner=" + TextFormatting.EmptyIfNull(RemoteOwner) +
                    " country=" + TextFormatting.EmptyIfNull(RemoteCountry) +
                    " country_lookup=" + TextFormatting.EmptyIfNull(RemoteCountryLookupStatus) +
                    " enrichment_source=" + TextFormatting.EmptyIfNull(RemoteEnrichmentSource) +
                    " state=" + State +
                    " source=" + TextFormatting.EmptyIfNull(Source) +
                    " process_path=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.ExecutablePath) +
                    " command_line=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.CommandLine) +
                    " parent=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.ParentProcessName) +
                    " parent_pid=" + (Process == null ? "" : Process.ParentProcessId.ToString(CultureInfo.InvariantCulture)) +
                    " sha256=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.Sha256) +
                    " signer=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.Signer);
            }
        }

        public override string ToString()
        {
            return Protocol + " " + LocalAddress + ":" + LocalPort.ToString(CultureInfo.InvariantCulture) +
                " -> " + RemoteAddress + ":" + RemotePort.ToString(CultureInfo.InvariantCulture) +
                " " + State +
                " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                " process=" + ProcessName +
                " remote_context=" + TextFormatting.EmptyIfNull(RemoteContextSummary()) +
                " path=" + TextFormatting.EmptyIfNull(Process == null ? "" : Process.ExecutablePath);
        }

        public string RemoteContextText()
        {
            return TextFormatting.EmptyIfNull(RemoteHost) + " " +
                TextFormatting.EmptyIfNull(RemoteRdns) + " " +
                TextFormatting.EmptyIfNull(String.Join(" ", RemoteDnsNames.ToArray())) + " " +
                TextFormatting.EmptyIfNull(SniHostname) + " " +
                TextFormatting.EmptyIfNull(ResolvedDomain) + " " +
                TextFormatting.EmptyIfNull(RegistrableDomain) + " " +
                TextFormatting.EmptyIfNull(RemoteAsn) + " " +
                TextFormatting.EmptyIfNull(RemoteAsnOrg) + " " +
                TextFormatting.EmptyIfNull(RemoteOwner) + " " +
                TextFormatting.EmptyIfNull(RemoteCountry);
        }

        public string RemoteContextSummary()
        {
            string summary = "";
            Append(ref summary, "domain", AlertEntityTokens.FirstNonEmpty(SniHostname, ResolvedDomain, RemoteHost, RemoteRdns));
            Append(ref summary, "registrable_domain", RegistrableDomain);
            Append(ref summary, "asn", RemoteAsn);
            Append(ref summary, "asn_org", RemoteAsnOrg);
            Append(ref summary, "owner", RemoteOwner);
            Append(ref summary, "country", RemoteCountry);
            Append(ref summary, "country_lookup", RemoteCountryLookupStatus);
            return summary;
        }

        private static void Append(ref string summary, string name, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            if (summary.Length > 0) summary += " ";
            summary += name + "=" + value;
        }

    }
}

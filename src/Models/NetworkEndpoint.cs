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
                    " remote_host=" + Safe(RemoteHost) +
                    " rdns=" + Safe(RemoteRdns) +
                    " dns_names=" + Safe(String.Join(";", RemoteDnsNames.ToArray())) +
                    " sni_hostname=" + Safe(SniHostname) +
                    " resolved_domain=" + Safe(ResolvedDomain) +
                    " registrable_domain=" + Safe(RegistrableDomain) +
                    " asn=" + Safe(RemoteAsn) +
                    " asn_org=" + Safe(RemoteAsnOrg) +
                    " remote_owner=" + Safe(RemoteOwner) +
                    " country=" + Safe(RemoteCountry) +
                    " country_lookup=" + Safe(RemoteCountryLookupStatus) +
                    " enrichment_source=" + Safe(RemoteEnrichmentSource) +
                    " state=" + State +
                    " source=" + Safe(Source) +
                    " process_path=" + Safe(Process == null ? "" : Process.ExecutablePath) +
                    " command_line=" + Safe(Process == null ? "" : Process.CommandLine) +
                    " parent=" + Safe(Process == null ? "" : Process.ParentProcessName) +
                    " parent_pid=" + (Process == null ? "" : Process.ParentProcessId.ToString(CultureInfo.InvariantCulture)) +
                    " sha256=" + Safe(Process == null ? "" : Process.Sha256) +
                    " signer=" + Safe(Process == null ? "" : Process.Signer);
            }
        }

        public override string ToString()
        {
            return Protocol + " " + LocalAddress + ":" + LocalPort.ToString(CultureInfo.InvariantCulture) +
                " -> " + RemoteAddress + ":" + RemotePort.ToString(CultureInfo.InvariantCulture) +
                " " + State +
                " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                " process=" + ProcessName +
                " remote_context=" + Safe(RemoteContextSummary()) +
                " path=" + Safe(Process == null ? "" : Process.ExecutablePath);
        }

        public string RemoteContextText()
        {
            return Safe(RemoteHost) + " " +
                Safe(RemoteRdns) + " " +
                Safe(String.Join(" ", RemoteDnsNames.ToArray())) + " " +
                Safe(SniHostname) + " " +
                Safe(ResolvedDomain) + " " +
                Safe(RegistrableDomain) + " " +
                Safe(RemoteAsn) + " " +
                Safe(RemoteAsnOrg) + " " +
                Safe(RemoteOwner) + " " +
                Safe(RemoteCountry);
        }

        public string RemoteContextSummary()
        {
            string summary = "";
            Append(ref summary, "domain", FirstNonEmpty(SniHostname, ResolvedDomain, RemoteHost, RemoteRdns));
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

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}

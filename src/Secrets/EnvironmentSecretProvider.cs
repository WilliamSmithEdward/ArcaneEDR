using System;

namespace ArcaneEDR
{
    internal sealed class EnvironmentSecretProvider : ISecretProvider
    {
        public string GetSecret(string name)
        {
            if (String.IsNullOrWhiteSpace(name)) return "";

            string value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
            if (!String.IsNullOrWhiteSpace(value)) return value.Trim();

            value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User);
            if (!String.IsNullOrWhiteSpace(value)) return value.Trim();

            value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine);
            return String.IsNullOrWhiteSpace(value) ? "" : value.Trim();
        }
    }
}

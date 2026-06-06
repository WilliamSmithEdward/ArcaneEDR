namespace ArcaneEDR
{
    internal interface ISecretProvider
    {
        string GetSecret(string name);
    }
}

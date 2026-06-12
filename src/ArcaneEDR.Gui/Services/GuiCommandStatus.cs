using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml.Controls;

namespace ArcaneEDR_Gui.Services;

internal static class GuiCommandStatus
{
    public static async Task RunAsync(Button? button, TextBlock output, string status, Func<Task<string>> action)
    {
        bool previousEnabled = button?.IsEnabled ?? true;
        if (button != null) button.IsEnabled = false;
        output.Text = status;

        try
        {
            output.Text = await action();
        }
        catch (Exception ex)
        {
            output.Text = "Command failed: " + ex.Message;
        }
        finally
        {
            if (button != null) button.IsEnabled = previousEnabled;
        }
    }
}

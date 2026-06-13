// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class SettingsPage : Page
{
    private bool loading;

    public SettingsPage()
    {
        InitializeComponent();
        SettingsPathText.Text = ArcaneStateReader.BuildPathSummary();
        LoadStartupSettings();
    }

    private void LoadStartupSettings()
    {
        loading = true;
        try
        {
            GuiUserSettings settings = GuiStartupSettings.Load();
            StartOnLoginSwitch.IsOn = settings.StartOnWindowsLogin;
            StartMinimizedSwitch.IsOn = settings.StartMinimizedOnWindowsLogin;
            StartMinimizedSwitch.IsEnabled = StartOnLoginSwitch.IsOn;
            StartupStatusText.Text = GuiStartupSettings.BuildStatusText();
        }
        finally
        {
            loading = false;
        }
    }

    private void StartupSwitch_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (loading || StartOnLoginSwitch == null || StartMinimizedSwitch == null)
        {
            return;
        }

        StartMinimizedSwitch.IsEnabled = StartOnLoginSwitch.IsOn;

        try
        {
            GuiUserSettings settings = GuiStartupSettings.Load();
            settings.StartOnWindowsLogin = StartOnLoginSwitch.IsOn;
            settings.StartMinimizedOnWindowsLogin = StartMinimizedSwitch.IsOn;
            GuiStartupSettings.SaveAndApply(settings);
            StartupStatusText.Text = GuiStartupSettings.BuildStatusText();
        }
        catch (System.Exception ex)
        {
            GuiDiagnostics.LogException("gui-settings-save", ex);
            StartupStatusText.Text = "Startup settings were not saved: " + ex.Message;
        }
    }

    private void ThemeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (XamlRoot == null || ThemeBox == null) return;

        string selected = (ThemeBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Default";
        if (selected.Equals("Light", System.StringComparison.OrdinalIgnoreCase))
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Light;
        }
        else if (selected.Equals("Dark", System.StringComparison.OrdinalIgnoreCase))
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Dark;
        }
        else
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Default;
        }
    }
}

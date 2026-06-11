using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Pages;
using ArcaneEDR_Gui.Services;
using WinRT.Interop;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace ArcaneEDR_Gui;

public sealed partial class MainWindow : Window
{
    private AppWindow? _appWindow;
    private bool _exitRequested;
    private bool _updatingNavigationSelection;

    public MainWindow()
    {
        InitializeComponent();

        ApplyWindowIcon();
        NavigateTo("home");
        Closed += MainWindow_Closed;
    }

    private void ApplyWindowIcon()
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (!File.Exists(iconPath))
        {
            return;
        }

        var windowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(windowHandle);
        _appWindow = AppWindow.GetFromWindowId(windowId);
        _appWindow.SetIcon(iconPath);
    }

    public void ShowAndActivate()
    {
        if (_appWindow?.Presenter is OverlappedPresenter presenter)
        {
            presenter.Restore();
        }

        _appWindow?.Show();
        Activate();
    }

    public void NavigateTo(string tag)
    {
        Type pageType = tag switch
        {
            "home" => typeof(HomePage),
            "alerts" => typeof(AlertsPage),
            "policy" => typeof(PolicyPage),
            "reports" => typeof(ReportsPage),
            "configuration" => typeof(ConfigurationPage),
            "maintenance" => typeof(MaintenancePage),
            "about" => typeof(AboutPage),
            "settings" => typeof(SettingsPage),
            _ => typeof(HomePage)
        };

        _updatingNavigationSelection = true;
        try
        {
            SelectNavigationItem(tag);
        }
        finally
        {
            _updatingNavigationSelection = false;
        }

        if (NavFrame.CurrentSourcePageType != pageType)
        {
            try
            {
                NavFrame.Navigate(pageType);
            }
            catch (Exception ex)
            {
                GuiDiagnostics.LogException("navigation:" + tag, ex);
                throw;
            }
        }
    }

    public void ExitFromTray()
    {
        _exitRequested = true;
        Close();
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (_updatingNavigationSelection)
        {
            return;
        }

        if (args.IsSettingsSelected)
        {
            NavigateTo("settings");
        }
        else if (args.SelectedItem is NavigationViewItem item)
        {
            NavigateTo(item.Tag?.ToString() ?? "home");
        }
    }

    private void MainWindow_Closed(object sender, WindowEventArgs args)
    {
        if (_exitRequested)
        {
            return;
        }

        args.Handled = true;
        _appWindow?.Hide();
    }

    private void SelectNavigationItem(string tag)
    {
        if (tag == "settings")
        {
            NavView.SelectedItem = NavView.SettingsItem;
            return;
        }

        foreach (object item in NavView.MenuItems)
        {
            if (item is NavigationViewItem navigationItem &&
                navigationItem.Tag?.ToString() == tag)
            {
                NavView.SelectedItem = navigationItem;
                return;
            }
        }
    }
}

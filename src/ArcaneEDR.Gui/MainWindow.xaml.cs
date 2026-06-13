using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using ArcaneEDR_Gui.Pages;
using ArcaneEDR_Gui.Services;
using Windows.Graphics;
using WinRT.Interop;

namespace ArcaneEDR_Gui;

public sealed partial class MainWindow : Window
{
    private const int DefaultWindowWidth = 1680;
    private const int DefaultWindowHeight = 1050;
    private const int MinimumInitialWindowWidth = 960;
    private const int MinimumInitialWindowHeight = 680;
    private const int DisplayPadding = 80;

    private AppWindow? _appWindow;
    private bool _exitRequested;
    private bool _updatingNavigationSelection;

    public MainWindow()
    {
        InitializeComponent();

        ApplyWindowChrome();
        NavFrame.NavigationFailed += NavFrame_NavigationFailed;
        NavigateTo("home");
        Closed += MainWindow_Closed;
    }

    private void ApplyWindowChrome()
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");

        var windowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(windowHandle);
        _appWindow = AppWindow.GetFromWindowId(windowId);
        ApplyInitialWindowBounds(windowId);
        if (File.Exists(iconPath))
        {
            _appWindow.SetIcon(iconPath);
        }

        ApplyTitleBarColors();
    }

    private void ApplyInitialWindowBounds(WindowId windowId)
    {
        if (_appWindow == null)
        {
            return;
        }

        try
        {
            DisplayArea displayArea = DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Primary);
            RectInt32 workArea = displayArea.WorkArea;
            int width = Math.Min(DefaultWindowWidth, Math.Max(MinimumInitialWindowWidth, workArea.Width - DisplayPadding));
            int height = Math.Min(DefaultWindowHeight, Math.Max(MinimumInitialWindowHeight, workArea.Height - DisplayPadding));
            int x = workArea.X + Math.Max(0, (workArea.Width - width) / 2);
            int y = workArea.Y + Math.Max(0, (workArea.Height - height) / 2);
            _appWindow.MoveAndResize(new RectInt32(x, y, width, height));
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("initial-window-bounds", ex);
            _appWindow.Resize(new SizeInt32(DefaultWindowWidth, DefaultWindowHeight));
        }
    }

    private void ApplyTitleBarColors()
    {
        if (_appWindow == null)
        {
            return;
        }

        try
        {
            AppWindowTitleBar titleBar = _appWindow.TitleBar;
            titleBar.BackgroundColor = Colors.Black;
            titleBar.ForegroundColor = Colors.White;
            titleBar.InactiveBackgroundColor = Colors.Black;
            titleBar.InactiveForegroundColor = Colors.LightGray;
            titleBar.ButtonBackgroundColor = Colors.Black;
            titleBar.ButtonForegroundColor = Colors.White;
            titleBar.ButtonInactiveBackgroundColor = Colors.Black;
            titleBar.ButtonInactiveForegroundColor = Colors.LightGray;
            titleBar.ButtonHoverBackgroundColor = ColorHelper.FromArgb(255, 32, 32, 32);
            titleBar.ButtonHoverForegroundColor = Colors.White;
            titleBar.ButtonPressedBackgroundColor = ColorHelper.FromArgb(255, 48, 48, 48);
            titleBar.ButtonPressedForegroundColor = Colors.White;
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("titlebar-colors", ex);
        }
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

    private void NavFrame_NavigationFailed(object sender, NavigationFailedEventArgs args)
    {
        GuiDiagnostics.LogException("navigation-failed", args.Exception);
        args.Handled = true;
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

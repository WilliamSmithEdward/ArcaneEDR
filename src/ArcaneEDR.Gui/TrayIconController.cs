using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using ArcaneEDR_Gui.Services;
using WinRT.Interop;

namespace ArcaneEDR_Gui;

internal sealed class TrayIconController : IDisposable
{
    private const int IconId = 1;
    private const uint WmNull = 0x0000;
    private const uint WmUser = 0x0400;
    private const uint WmApp = 0x8000;
    private const uint WmTrayIcon = WmApp + 1;
    private const uint WmContextMenu = 0x007B;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmLButtonDblClk = 0x0203;
    private const uint WmRButtonUp = 0x0205;
    private const uint NinSelect = WmUser;
    private const uint NinKeySelect = WmUser + 1;
    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;
    private const uint NimSetVersion = 0x00000004;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;
    private const uint NifInfo = 0x00000010;
    private const uint NotifyIconVersion4 = 4;
    private const uint NiifInfo = 0x00000001;
    private const uint NiifWarning = 0x00000002;
    private const uint ImageIcon = 1;
    private const uint LrLoadFromFile = 0x00000010;
    private const uint LrDefaultSize = 0x00000040;
    private const uint MfString = 0x00000000;
    private const uint MfSeparator = 0x00000800;
    private const uint TpmRightButton = 0x00000002;
    private const uint TpmReturnCmd = 0x00000100;

    private static readonly IntPtr HwndMessage = new(-3);
    private static readonly IntPtr IdiApplication = new(32512);

    private const int CmdOpen = 100;
    private const int CmdOverview = 101;
    private const int CmdAlerts = 102;
    private const int CmdReports = 103;
    private const int CmdConfiguration = 104;
    private const int CmdMaintenance = 105;
    private const int CmdValidate = 106;
    private const int CmdAdminValidate = 107;
    private const int CmdRestart = 108;
    private const int CmdOpenLogs = 109;
    private const int CmdOpenConfig = 110;
    private const int CmdExit = 111;

    private readonly MainWindow _window;
    private readonly TrayWndProc _wndProc;
    private readonly string _className;
    private readonly IntPtr _instance;
    private readonly IntPtr _ownerWindow;
    private IntPtr _messageWindow;
    private IntPtr _iconHandle;
    private bool _ownsIcon;
    private bool _disposed;

    public TrayIconController(MainWindow window)
    {
        _window = window;
        _wndProc = WndProc;
        _className = "ArcaneEDRTrayWindow-" + Environment.ProcessId.ToString();
        _instance = GetModuleHandle(null);
        _ownerWindow = WindowNative.GetWindowHandle(window);

        RegisterMessageWindow();
        AddIcon();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        RemoveIcon();

        if (_messageWindow != IntPtr.Zero)
        {
            DestroyWindow(_messageWindow);
            _messageWindow = IntPtr.Zero;
        }

        if (_ownsIcon && _iconHandle != IntPtr.Zero)
        {
            DestroyIcon(_iconHandle);
            _iconHandle = IntPtr.Zero;
        }

        UnregisterClass(_className, _instance);
    }

    private void RegisterMessageWindow()
    {
        var windowClass = new WndClassEx
        {
            cbSize = (uint)Marshal.SizeOf<WndClassEx>(),
            lpfnWndProc = _wndProc,
            hInstance = _instance,
            lpszClassName = _className
        };

        if (RegisterClassEx(ref windowClass) == 0)
        {
            throw new InvalidOperationException("Could not register the Arcane EDR tray window.");
        }

        _messageWindow = CreateWindowEx(
            0,
            _className,
            _className,
            0,
            0,
            0,
            0,
            0,
            HwndMessage,
            IntPtr.Zero,
            _instance,
            IntPtr.Zero);

        if (_messageWindow == IntPtr.Zero)
        {
            throw new InvalidOperationException("Could not create the Arcane EDR tray window.");
        }
    }

    private void AddIcon()
    {
        _iconHandle = LoadTrayIcon();

        var data = CreateNotifyIconData(NifMessage | NifIcon | NifTip);
        data.uCallbackMessage = WmTrayIcon;
        data.hIcon = _iconHandle;
        data.szTip = "Arcane EDR";

        Shell_NotifyIcon(NimAdd, ref data);

        data = CreateNotifyIconData(0);
        data.uVersion = NotifyIconVersion4;
        Shell_NotifyIcon(NimSetVersion, ref data);
    }

    private void RemoveIcon()
    {
        var data = CreateNotifyIconData(0);
        Shell_NotifyIcon(NimDelete, ref data);
    }

    private NotifyIconData CreateNotifyIconData(uint flags)
    {
        return new NotifyIconData
        {
            cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
            hWnd = _messageWindow,
            uID = IconId,
            uFlags = flags
        };
    }

    private IntPtr LoadTrayIcon()
    {
        string iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(iconPath))
        {
            IntPtr loadedIcon = LoadImage(IntPtr.Zero, iconPath, ImageIcon, 0, 0, LrLoadFromFile | LrDefaultSize);
            if (loadedIcon != IntPtr.Zero)
            {
                _ownsIcon = true;
                return loadedIcon;
            }
        }

        return LoadIcon(IntPtr.Zero, IdiApplication);
    }

    private IntPtr WndProc(IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == WmTrayIcon)
        {
            uint notification = LowWord(lParam);
            uint iconId = HighWord(lParam);
            if (iconId != 0 && iconId != IconId)
            {
                return IntPtr.Zero;
            }

            if (notification is NinSelect or NinKeySelect or WmLButtonUp or WmLButtonDblClk)
            {
                ShowWindow();
                return IntPtr.Zero;
            }

            if (notification is WmContextMenu or WmRButtonUp)
            {
                ShowContextMenu(NotificationPoint(wParam));
                return IntPtr.Zero;
            }
        }

        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    private void ShowContextMenu(Point point)
    {
        IntPtr menu = CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        try
        {
            AppendMenu(menu, MfString, new UIntPtr(CmdOpen), "Open Arcane EDR");
            AppendMenu(menu, MfSeparator, UIntPtr.Zero, null);
            AppendMenu(menu, MfString, new UIntPtr(CmdOverview), "Overview");
            AppendMenu(menu, MfString, new UIntPtr(CmdAlerts), "Alerts");
            AppendMenu(menu, MfString, new UIntPtr(CmdReports), "Reports");
            AppendMenu(menu, MfString, new UIntPtr(CmdConfiguration), "Configuration");
            AppendMenu(menu, MfString, new UIntPtr(CmdMaintenance), "Maintenance");
            AppendMenu(menu, MfSeparator, UIntPtr.Zero, null);
            AppendMenu(menu, MfString, new UIntPtr(CmdValidate), "Validate Config");
            AppendMenu(menu, MfString, new UIntPtr(CmdAdminValidate), "Run Admin Validation");
            AppendMenu(menu, MfString, new UIntPtr(CmdRestart), "Restart Service (UAC)");
            AppendMenu(menu, MfSeparator, UIntPtr.Zero, null);
            AppendMenu(menu, MfString, new UIntPtr(CmdOpenLogs), "Open Logs Folder");
            AppendMenu(menu, MfString, new UIntPtr(CmdOpenConfig), "Open Config Folder");
            AppendMenu(menu, MfSeparator, UIntPtr.Zero, null);
            AppendMenu(menu, MfString, new UIntPtr(CmdExit), "Exit Tray");

            if (point.X == 0 && point.Y == 0)
            {
                GetCursorPos(out point);
            }

            IntPtr owner = _ownerWindow == IntPtr.Zero ? _messageWindow : _ownerWindow;
            SetForegroundWindow(owner);
            int command = TrackPopupMenuEx(menu, TpmRightButton | TpmReturnCmd, point.X, point.Y, owner, IntPtr.Zero);
            PostMessage(owner, WmNull, IntPtr.Zero, IntPtr.Zero);
            ExecuteCommand(command);
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private void ExecuteCommand(int command)
    {
        switch (command)
        {
            case CmdOpen:
            case CmdOverview:
                ShowWindow("home");
                break;
            case CmdAlerts:
                ShowWindow("alerts");
                break;
            case CmdReports:
                ShowWindow("reports");
                break;
            case CmdConfiguration:
                ShowWindow("configuration");
                break;
            case CmdMaintenance:
                ShowWindow("maintenance");
                break;
            case CmdValidate:
                _ = RunArcaneCommandAsync("Validating Arcane config...", "--validate-config");
                break;
            case CmdAdminValidate:
                _ = RunAdminTaskAsync("ValidateAdmin");
                break;
            case CmdRestart:
                RestartServiceElevated();
                break;
            case CmdOpenLogs:
                OpenLogsFolder();
                break;
            case CmdOpenConfig:
                OpenConfigFolder();
                break;
            case CmdExit:
                Exit();
                break;
        }
    }

    private void ShowWindow(string tag = "home")
    {
        _window.DispatcherQueue.TryEnqueue(() =>
        {
            _window.ShowAndActivate();
            _window.NavigateTo(tag);
        });
    }

    private async Task RunArcaneCommandAsync(string startMessage, params string[] arguments)
    {
        ShowNotification(startMessage, false);
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), arguments);
        ShowNotification(SummarizeResult(result), result.ExitCode != 0);
    }

    private async Task RunAdminTaskAsync(string taskName)
    {
        ShowNotification("Starting " + taskName + "...", false);
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", taskName);
        ShowNotification(SummarizeResult(result), result.ExitCode != 0);
    }

    private void RestartServiceElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command \"Restart-Service -Name ArcaneEDR; Get-Service -Name ArcaneEDR\"",
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch (Exception ex)
        {
            ShowNotification("Restart was not started: " + ex.Message, true);
        }
    }

    private void OpenLogsFolder()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        ArcaneScriptRunner.OpenPath(paths.LogDirectory);
    }

    private void OpenConfigFolder()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        string configDirectory = Path.GetDirectoryName(paths.ConfigFile) ?? Path.Combine(paths.ProductRoot, "config");
        ArcaneScriptRunner.OpenPath(configDirectory);
    }

    private void Exit()
    {
        Dispose();
        _window.DispatcherQueue.TryEnqueue(_window.ExitFromTray);
    }

    private void ShowNotification(string message, bool warning)
    {
        if (_disposed)
        {
            return;
        }

        var data = CreateNotifyIconData(NifInfo);
        data.szInfoTitle = "Arcane EDR";
        data.szInfo = Truncate(message, 255);
        data.dwInfoFlags = warning ? NiifWarning : NiifInfo;
        Shell_NotifyIcon(NimModify, ref data);
    }

    private static string SummarizeResult(ArcaneCommandResult result)
    {
        string text = result.CombinedText();
        if (String.IsNullOrWhiteSpace(text))
        {
            text = result.ExitCode == 0 ? "Completed successfully." : "Command failed.";
        }

        text = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return Truncate(text, 220);
    }

    private static string Truncate(string value, int maxLength)
    {
        if (String.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value.Substring(0, maxLength - 3) + "...";
    }

    private static uint LowWord(IntPtr value)
    {
        return unchecked((uint)value.ToInt64()) & 0xFFFF;
    }

    private static uint HighWord(IntPtr value)
    {
        return (unchecked((uint)value.ToInt64()) >> 16) & 0xFFFF;
    }

    private static Point NotificationPoint(IntPtr wParam)
    {
        int value = unchecked((int)wParam.ToInt64());
        return new Point
        {
            X = (short)(value & 0xFFFF),
            Y = (short)((value >> 16) & 0xFFFF)
        };
    }

    private delegate IntPtr TrayWndProc(IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClassEx
    {
        public uint cbSize;
        public uint style;
        public TrayWndProc lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WndClassEx lpwcx);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool UnregisterClass(string lpClassName, IntPtr hInstance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint dwExStyle,
        string lpClassName,
        string lpWindowName,
        uint dwStyle,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr param);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Shell_NotifyIcon(uint message, ref NotifyIconData data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr iconName);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool AppendMenu(IntPtr hMenu, uint flags, UIntPtr id, string? item);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetCursorPos(out Point point);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int TrackPopupMenuEx(IntPtr hMenu, uint flags, int x, int y, IntPtr hWnd, IntPtr tpm);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}

using System;
using System.Runtime.CompilerServices;
using ArcaneEDR_Gui.Services;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace ArcaneEDR_Gui.Controls;

public static class PageScrollBehavior
{
    private const double OffsetTolerance = 2.0;
    private const double WheelDelta = 120.0;
    private const double MinimumWheelStep = 48.0;
    private const double ViewportWheelStepRatio = 0.12;
    private const long EdgeLockDurationTicks = 160 * TimeSpan.TicksPerMillisecond;
    private const int NoEdge = 0;
    private const int TopEdge = -1;
    private const int BottomEdge = 1;

    public static readonly DependencyProperty UseReliableWheelProperty =
        DependencyProperty.RegisterAttached(
            "UseReliableWheel",
            typeof(bool),
            typeof(PageScrollBehavior),
            new PropertyMetadata(false, OnUseReliableWheelChanged));

    private static readonly PointerEventHandler WheelHandler = HandlePointerWheelChanged;
    private static readonly ConditionalWeakTable<ScrollViewer, EdgeLockState> EdgeLocks = new();

    private static readonly DependencyProperty HookedContentProperty =
        DependencyProperty.RegisterAttached(
            "HookedContent",
            typeof(UIElement),
            typeof(PageScrollBehavior),
            new PropertyMetadata(null));

    private static readonly DependencyProperty OwnerScrollViewerProperty =
        DependencyProperty.RegisterAttached(
            "OwnerScrollViewer",
            typeof(ScrollViewer),
            typeof(PageScrollBehavior),
            new PropertyMetadata(null));

    public static bool GetUseReliableWheel(DependencyObject element)
    {
        return (bool)element.GetValue(UseReliableWheelProperty);
    }

    public static void SetUseReliableWheel(DependencyObject element, bool value)
    {
        element.SetValue(UseReliableWheelProperty, value);
    }

    private static void OnUseReliableWheelChanged(DependencyObject element, DependencyPropertyChangedEventArgs args)
    {
        if (element is not ScrollViewer scrollViewer)
        {
            return;
        }

        scrollViewer.Loaded -= ScrollViewer_Loaded;
        scrollViewer.Unloaded -= ScrollViewer_Unloaded;
        DetachFromCurrentContent(scrollViewer);

        if (args.NewValue is true)
        {
            scrollViewer.Loaded += ScrollViewer_Loaded;
            scrollViewer.Unloaded += ScrollViewer_Unloaded;
            AttachToCurrentContent(scrollViewer);
        }
    }

    private static void ScrollViewer_Loaded(object sender, RoutedEventArgs args)
    {
        if (sender is ScrollViewer scrollViewer)
        {
            AttachToCurrentContent(scrollViewer);
        }
    }

    private static void ScrollViewer_Unloaded(object sender, RoutedEventArgs args)
    {
        if (sender is ScrollViewer scrollViewer)
        {
            DetachFromCurrentContent(scrollViewer);
        }
    }

    private static void AttachToCurrentContent(ScrollViewer scrollViewer)
    {
        if (!IsUsable(scrollViewer))
        {
            return;
        }

        if (scrollViewer.Content is not UIElement content)
        {
            return;
        }

        if (ReferenceEquals(scrollViewer.GetValue(HookedContentProperty), content))
        {
            return;
        }

        DetachFromCurrentContent(scrollViewer);
        EnsureHitTestableContent(content);
        content.SetValue(OwnerScrollViewerProperty, scrollViewer);
        content.AddHandler(UIElement.PointerWheelChangedEvent, WheelHandler, true);
        scrollViewer.SetValue(HookedContentProperty, content);
    }

    private static void DetachFromCurrentContent(ScrollViewer scrollViewer)
    {
        if (scrollViewer.GetValue(HookedContentProperty) is not UIElement content)
        {
            return;
        }

        try
        {
            content.RemoveHandler(UIElement.PointerWheelChangedEvent, WheelHandler);
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("scroll-detach", ex);
        }
        finally
        {
            content.ClearValue(OwnerScrollViewerProperty);
            scrollViewer.ClearValue(HookedContentProperty);
        }
    }

    private static void HandlePointerWheelChanged(object sender, PointerRoutedEventArgs args)
    {
        try
        {
            if (sender is not DependencyObject hookSource ||
                hookSource.GetValue(OwnerScrollViewerProperty) is not ScrollViewer pageScrollViewer ||
                !IsUsable(pageScrollViewer))
            {
                return;
            }

            int delta = args.GetCurrentPoint(pageScrollViewer).Properties.MouseWheelDelta;
            if (delta == 0)
            {
                return;
            }

            if (pageScrollViewer.ScrollableHeight <= 0)
            {
                args.Handled = true;
                return;
            }

            ScrollViewer? nestedScrollViewer = FindNearestNestedScrollViewer(
                pageScrollViewer,
                args.OriginalSource as DependencyObject);
            if (nestedScrollViewer != null &&
                IsUsable(nestedScrollViewer) &&
                CanScrollInDirection(nestedScrollViewer, delta))
            {
                return;
            }

            RoutePageWheel(pageScrollViewer, args, delta);
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("scroll-wheel", ex);
        }
    }

    private static ScrollViewer? FindNearestNestedScrollViewer(ScrollViewer owner, DependencyObject? current)
    {
        while (current != null && current != owner)
        {
            if (current is ScrollViewer scrollViewer)
            {
                return scrollViewer;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private static void RoutePageWheel(ScrollViewer scrollViewer, PointerRoutedEventArgs args, int delta)
    {
        if (ShouldSuppressForEdgeLock(scrollViewer))
        {
            args.Handled = true;
            return;
        }

        double targetOffset = GetWheelTargetOffset(scrollViewer, delta);
        if (Math.Abs(targetOffset - scrollViewer.VerticalOffset) >= 0.5)
        {
            scrollViewer.ChangeView(null, targetOffset, null, disableAnimation: true);
        }

        UpdateEdgeLock(scrollViewer, targetOffset);
        args.Handled = true;
    }

    private static void EnsureHitTestableContent(UIElement content)
    {
        if (content is Panel { Background: null } panel)
        {
            panel.Background = new SolidColorBrush(Colors.Transparent);
        }

        if (content is Border { Background: null } border)
        {
            border.Background = new SolidColorBrush(Colors.Transparent);
        }
    }

    private static bool IsAtDirectionalEdge(ScrollViewer scrollViewer, int delta)
    {
        if (delta > 0)
        {
            return scrollViewer.VerticalOffset <= OffsetTolerance;
        }

        return scrollViewer.ScrollableHeight - scrollViewer.VerticalOffset <= OffsetTolerance;
    }

    private static bool CanScrollInDirection(ScrollViewer scrollViewer, int delta)
    {
        return scrollViewer.ScrollableHeight > OffsetTolerance && !IsAtDirectionalEdge(scrollViewer, delta);
    }

    private static bool ShouldSuppressForEdgeLock(ScrollViewer scrollViewer)
    {
        EdgeLockState state = EdgeLocks.GetValue(scrollViewer, _ => new EdgeLockState());
        if (state.Edge == NoEdge)
        {
            return false;
        }

        long now = DateTime.UtcNow.Ticks;
        if (state.UntilTicks <= now)
        {
            state.Edge = NoEdge;
            return false;
        }

        if (!IsAtEdge(scrollViewer, state.Edge))
        {
            state.Edge = NoEdge;
            return false;
        }

        return true;
    }

    private static void UpdateEdgeLock(ScrollViewer scrollViewer, double targetOffset)
    {
        EdgeLockState state = EdgeLocks.GetValue(scrollViewer, _ => new EdgeLockState());
        if (targetOffset <= OffsetTolerance)
        {
            state.Edge = TopEdge;
            state.UntilTicks = DateTime.UtcNow.Ticks + EdgeLockDurationTicks;
            return;
        }

        if (scrollViewer.ScrollableHeight - targetOffset <= OffsetTolerance)
        {
            state.Edge = BottomEdge;
            state.UntilTicks = DateTime.UtcNow.Ticks + EdgeLockDurationTicks;
            return;
        }

        state.Edge = NoEdge;
    }

    private static bool IsAtEdge(ScrollViewer scrollViewer, int edge)
    {
        return edge switch
        {
            TopEdge => scrollViewer.VerticalOffset <= OffsetTolerance,
            BottomEdge => scrollViewer.ScrollableHeight - scrollViewer.VerticalOffset <= OffsetTolerance,
            _ => false
        };
    }

    private static double GetWheelTargetOffset(ScrollViewer scrollViewer, int delta)
    {
        double notches = Math.Abs(delta) / WheelDelta;
        double step = Math.Max(MinimumWheelStep, scrollViewer.ViewportHeight * ViewportWheelStepRatio);
        double direction = delta > 0 ? -1.0 : 1.0;
        return Clamp(scrollViewer.VerticalOffset + (direction * step * notches), 0, scrollViewer.ScrollableHeight);
    }

    private static double Clamp(double value, double min, double max)
    {
        if (value < min)
        {
            return min;
        }

        return value > max ? max : value;
    }

    private static bool IsUsable(ScrollViewer scrollViewer)
    {
        return scrollViewer.XamlRoot != null;
    }

    private sealed class EdgeLockState
    {
        public int Edge;
        public long UntilTicks;
    }
}

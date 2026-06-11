using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ArcaneEDR_Gui.Controls;

public sealed class AlertTableColumnWidths : INotifyPropertyChanged
{
    private const double MinColumnWidth = 56;
    private const double MaxColumnWidth = 520;

    private double time = 180;
    private double rule = 180;
    private double category = 110;
    private double score = 70;
    private double country = 90;
    private double process = 150;
    private double company = 190;
    private double title = 340;

    public event PropertyChangedEventHandler? PropertyChanged;

    public double Time
    {
        get => time;
        set => Set(ref time, value);
    }

    public double Rule
    {
        get => rule;
        set => Set(ref rule, value);
    }

    public double Category
    {
        get => category;
        set => Set(ref category, value);
    }

    public double Score
    {
        get => score;
        set => Set(ref score, value);
    }

    public double Country
    {
        get => country;
        set => Set(ref country, value);
    }

    public double Process
    {
        get => process;
        set => Set(ref process, value);
    }

    public double Company
    {
        get => company;
        set => Set(ref company, value);
    }

    public double Title
    {
        get => title;
        set => Set(ref title, value);
    }

    public double TotalWidth => Time + Rule + Category + Score + Country + Process + Company + Title;

    public void Resize(string column, double delta)
    {
        switch (column)
        {
            case "Time":
                Time += delta;
                break;
            case "Rule":
                Rule += delta;
                break;
            case "Category":
                Category += delta;
                break;
            case "Score":
                Score += delta;
                break;
            case "Country":
                Country += delta;
                break;
            case "Process":
                Process += delta;
                break;
            case "Company":
                Company += delta;
                break;
            case "Title":
                Title += delta;
                break;
        }
    }

    private void Set(ref double field, double value, [CallerMemberName] string? propertyName = null)
    {
        double constrained = Math.Max(MinColumnWidth, Math.Min(MaxColumnWidth, value));
        if (Math.Abs(field - constrained) < 0.1)
        {
            return;
        }

        field = constrained;
        OnPropertyChanged(propertyName);
        OnPropertyChanged(nameof(TotalWidth));
    }

    private void OnPropertyChanged(string? propertyName)
    {
        if (propertyName != null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CEMCP.Models;

namespace CEMCP.Views
{
    public partial class ConfigWindow : Window
    {
        private readonly ConfigurationModel _viewModel;
        private readonly McpPlugin _plugin;

        public ConfigWindow(McpPlugin plugin)
        {
            _plugin = plugin;
            _viewModel = new ConfigurationModel();
            DataContext = _viewModel;

            _viewModel.LoadFromServerConfig();

            bool isDarkMode = ThemeHelper.IsInDarkMode();
            _viewModel.IsDarkMode = isDarkMode;

            InitializeComponent();
            ApplyTheme(isDarkMode);
            UpdateServerStatus();
        }

        private static bool IsServerRunning(McpPlugin? plugin)
        {
            var wrapper = plugin?.GetServerWrapper();
            return wrapper is not null && wrapper.IsRunning;
        }

        private void UpdateServerStatus()
        {
            bool running = IsServerRunning(_plugin);
            _viewModel.ServerStatus = running ? "Running" : "Stopped";
            openApiButton.IsEnabled = running;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _viewModel.SaveToServerConfig();
                _viewModel.TestResult = "Configuration saved successfully.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error saving configuration: {ex.Message}";
            }
        }

        private async void TestButton_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.TestResult = "Testing connection...";
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                // Streamable HTTP requires Accept: application/json, text/event-stream
                client.DefaultRequestHeaders.Add("Accept", "application/json, text/event-stream");
                var content = new StringContent(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}",
                    System.Text.Encoding.UTF8, "application/json");
                var response = await client.PostAsync(_viewModel.BaseUrl, content);
                _viewModel.TestResult = response.IsSuccessStatusCode
                    ? "✓ Connection successful! MCP Server is responding."
                    : $"✗ Server responded with status: {response.StatusCode}";
            }
            catch (HttpRequestException ex)
            {
                _viewModel.TestResult = $"✗ Connection failed: {ex.Message}";
            }
            catch (TaskCanceledException)
            {
                _viewModel.TestResult = "✗ Connection timed out. Server may not be running.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"✗ Error testing connection: {ex.Message}";
            }
        }

        private void StartStopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (IsServerRunning(_plugin))
                {
                    _plugin.StopServer();
                    _viewModel.TestResult = "Server stopped.";
                }
                else
                {
                    _viewModel.SaveToServerConfig();
                    _plugin?.StartServer();
                    _viewModel.TestResult = "Server started.";
                }
                UpdateServerStatus();
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error: {ex.Message}";
            }
        }

        private void CopyUrlButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = _viewModel.BaseUrl;
                Clipboard.SetText(url);
                _viewModel.TestResult = $"Copied to clipboard: {url}";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error copying URL: {ex.Message}";
            }
        }

        private void ApplyTheme(bool isDarkMode)
        {
            string prefix = isDarkMode ? "Dark" : "Light";
            var brushes = ResolveThemeBrushes(prefix);

            Background = brushes.Background;
            Resources["BtnHoverBrush"] = brushes.BtnHover;
            Resources["BtnDisabledBgBrush"] = brushes.BtnDisabledBg;
            Resources["BtnDisabledFgBrush"] = brushes.BtnDisabledFg;

            ApplyThemeToChildren((Grid)Content, brushes);
        }

        private ThemeBrushes ResolveThemeBrushes(string prefix)
        {
            return new ThemeBrushes
            {
                Background = new SolidColorBrush((Color)FindResource($"{prefix}Bg")),
                Foreground = new SolidColorBrush((Color)FindResource($"{prefix}Fg")),
                TextBoxBg = new SolidColorBrush((Color)FindResource($"{prefix}TextBoxBg")),
                TextBoxBorder = new SolidColorBrush((Color)FindResource($"{prefix}TextBoxBorder")),
                BtnBg = new SolidColorBrush((Color)FindResource($"{prefix}BtnBg")),
                BtnBorder = new SolidColorBrush((Color)FindResource($"{prefix}BtnBorder")),
                BtnHover = new SolidColorBrush((Color)FindResource($"{prefix}BtnHover")),
                BtnDisabledBg = new SolidColorBrush((Color)FindResource($"{prefix}BtnDisabledBg")),
                BtnDisabledFg = new SolidColorBrush((Color)FindResource($"{prefix}BtnDisabledFg")),
            };
        }

        private static void ApplyThemeToChildren(Grid grid, ThemeBrushes brushes)
        {
            foreach (var child in grid.Children)
            {
                switch (child)
                {
                    case TextBlock tb:
                        tb.Foreground = brushes.Foreground;
                        break;
                    case TextBox box:
                        box.Background = brushes.TextBoxBg;
                        box.Foreground = brushes.Foreground;
                        box.BorderBrush = brushes.TextBoxBorder;
                        break;
                    case WrapPanel panel:
                        ApplyThemeToButtons(panel, brushes);
                        break;
                }
            }
        }

        private static void ApplyThemeToButtons(WrapPanel panel, ThemeBrushes brushes)
        {
            foreach (var child in panel.Children)
            {
                if (child is Button button)
                {
                    button.Background = brushes.BtnBg;
                    button.Foreground = brushes.Foreground;
                    button.BorderBrush = brushes.BtnBorder;
                }
            }
        }

        private sealed class ThemeBrushes
        {
            public required SolidColorBrush Background { get; init; }
            public required SolidColorBrush Foreground { get; init; }
            public required SolidColorBrush TextBoxBg { get; init; }
            public required SolidColorBrush TextBoxBorder { get; init; }
            public required SolidColorBrush BtnBg { get; init; }
            public required SolidColorBrush BtnBorder { get; init; }
            public required SolidColorBrush BtnHover { get; init; }
            public required SolidColorBrush BtnDisabledBg { get; init; }
            public required SolidColorBrush BtnDisabledFg { get; init; }
        }
    }
}

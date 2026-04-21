using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace CEMCP.Models
{
    public class ConfigurationModel : INotifyPropertyChanged
    {
        private string _host = "127.0.0.1";
        private int _port = 6300;
        private string _serverName = "Cheat Engine MCP Server";
        private string _serverStatus = "Stopped";
        private Brush _serverStatusColor = new SolidColorBrush(Color.FromRgb(255, 0, 0));
        private string _testResult = "";
        private bool _isServerRunning = false;
        private bool _isDarkMode = false;
        private readonly string _version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";

        public string Host
        {
            get => _host;
            set
            {
                if (_host != value)
                {
                    _host = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(BaseUrl));
                }
            }
        }

        public int Port
        {
            get => _port;
            set
            {
                if (_port != value)
                {
                    _port = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(BaseUrl));
                }
            }
        }

        public string ServerName
        {
            get => _serverName;
            set
            {
                if (_serverName != value)
                {
                    _serverName = value;
                    OnPropertyChanged();
                }
            }
        }

        public string BaseUrl => $"http://{Host}:{Port}";

        public string SseUrl => $"{BaseUrl}/sse";

        public string Version => _version;

        public string StartStopButtonText => ServerStatus.Equals("running", System.StringComparison.CurrentCultureIgnoreCase) ? "Stop Server" : "Start Server";

        public bool IsServerRunning
        {
            get => _isServerRunning;
            set
            {
                if (_isServerRunning != value)
                {
                    _isServerRunning = value;
                    OnPropertyChanged();
                }
            }
        }

        public bool IsDarkMode
        {
            get => _isDarkMode;
            set
            {
                if (_isDarkMode != value)
                {
                    _isDarkMode = value;
                    OnPropertyChanged();
                    UpdateStatusColor();
                }
            }
        }

        public string ServerStatus
        {
            get => _serverStatus;
            set
            {
                if (_serverStatus != value)
                {
                    _serverStatus = value;
                    OnPropertyChanged();

                    UpdateStatusColor();

                    IsServerRunning = value.Equals("running", System.StringComparison.CurrentCultureIgnoreCase);
                    OnPropertyChanged(nameof(StartStopButtonText));
                }
            }
        }

        public Brush ServerStatusColor
        {
            get => _serverStatusColor;
            private set
            {
                if (_serverStatusColor != value)
                {
                    _serverStatusColor = value;
                    OnPropertyChanged();
                }
            }
        }

        public string TestResult
        {
            get => _testResult;
            set
            {
                if (_testResult != value)
                {
                    _testResult = value;
                    OnPropertyChanged();
                }
            }
        }

        public void LoadFromServerConfig()
        {
            Host = ServerConfig.ConfigHost;
            Port = ServerConfig.ConfigPort;
            ServerName = ServerConfig.ConfigServerName;
        }

        public void SaveToServerConfig()
        {
            ServerConfig.ConfigHost = Host;
            ServerConfig.ConfigPort = Port;
            ServerConfig.ConfigServerName = ServerName;
            ServerConfig.SaveToFile();
        }

        private void UpdateStatusColor()
        {
            string lowerStatus = _serverStatus.ToLower();

            if (lowerStatus == "running")
            {
                // Light green for dark mode, standard green for light mode
                ServerStatusColor = _isDarkMode ?
                    new SolidColorBrush(Color.FromRgb(76, 175, 80)) :
                    new SolidColorBrush(Color.FromRgb(0, 128, 0));
            }
            else if (lowerStatus == "stopped")
            {
                // Light red for dark mode, standard red for light mode
                ServerStatusColor = _isDarkMode ?
                    new SolidColorBrush(Color.FromRgb(244, 67, 54)) :
                    new SolidColorBrush(Color.FromRgb(255, 0, 0));
            }
            else if (lowerStatus == "starting" || lowerStatus == "stopping")
            {
                // Light orange for dark mode, standard orange for light mode
                ServerStatusColor = _isDarkMode ?
                    new SolidColorBrush(Color.FromRgb(255, 152, 0)) :
                    new SolidColorBrush(Color.FromRgb(255, 165, 0));
            }
            else
            {
                // Light gray for dark mode, standard gray for light mode
                ServerStatusColor = _isDarkMode ?
                    new SolidColorBrush(Color.FromRgb(158, 158, 158)) :
                    new SolidColorBrush(Color.FromRgb(128, 128, 128));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
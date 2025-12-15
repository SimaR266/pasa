using System;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.IO;
using ZitrontsScanner.Services;
using ZitrontsScanner.Models;

namespace ZitrontsScanner
{
    public partial class MainWindow : Window
    {
        private ScannerService _scannerService;

        public MainWindow()
        {
            InitializeComponent();
            _scannerService = new ScannerService();
            SetupEventHandlers();
            SetupUI();
        }

        private void SetupUI()
        {
            txtStatus.Text = "🚀 Zitronts Proxy Scanner V12 - Hazır";
            txtProxyInfo.Text = "🔄 Güncel Proxy Sistemi\n═══════════════════════════════\nDurum: Hazır\n\nℹ️ 'Her Zaman Güncel Proxy' butonuna tıklayarak\n   proxy güncelleme işlemini başlatabilirsiniz.";

            // Test için örnek log
            AddLog("🚀 Zitronts Proxy Scanner V12 başlatıldı", LogType.Info);
            AddLog("✅ Tüm sistemler hazır", LogType.Success);
            AddLog("⚙️ Sol panelde ayarlarınızı yapılandırın", LogType.Info);

            // Başlangıç istatistikleri
            UpdateStatistics(0, 100, 0, 0, 0, 0.0, "00:00:00", "00:00:00");
        }

        private void SetupEventHandlers()
        {
            // ScannerService event'lerini bağla
            _scannerService.ProgressChanged += OnScannerProgressChanged;
            _scannerService.HitFound += OnScannerHitFound;
            _scannerService.BotStatusChanged += OnScannerBotStatusChanged;
            _scannerService.LogMessage += OnScannerLogMessage;

            // UI event'lerini bağla
            btnStart.Click += BtnStart_Click;
            btnStop.Click += BtnStop_Click;
            btnBrowseCombo.Click += BtnBrowseCombo_Click;
            btnBrowseProxy.Click += BtnBrowseProxy_Click;
            btnClearLog.Click += BtnClearLog_Click;
            btnCopyLog.Click += BtnCopyLog_Click;

            // Diğer araç butonları
            btnProxyScraper.Click += (s, e) => ShowToolMessage("Proxy Scraper");
            btnProxyUpdate.Click += (s, e) => ShowToolMessage("Güncel Proxy");
            btnDNSFinder.Click += (s, e) => ShowToolMessage("DNS Bul");
            btnIPTVPlayer.Click += (s, e) => ShowToolMessage("IPTV Player");
            btnSpider.Click += (s, e) => ShowToolMessage("Örümcek");
            btnTelegramTools.Click += (s, e) => ShowToolMessage("Telegram Tools");
            btnSettings.Click += (s, e) => ShowToolMessage("Ayarlar");
            btnUpdateProxy.Click += (s, e) => ShowToolMessage("Proxy Güncelleme");
        }

        // ========== SCANNER SERVICE EVENT HANDLERS ==========

        private void OnScannerProgressChanged(object sender, ScanProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateStatistics(e);
            });
        }

        private void OnScannerHitFound(object sender, HitFoundEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                // SADECE BURADA LOG EKLE (ScannerService'deki OnHitFound'da log ekleme)
                AddLog($"🎯 YENİ HIT: {e.Result.Username}:{e.Result.Password} ({e.Result.ChannelCount} kanal)", LogType.Hit);

                // Update hits count
                int currentHits = 0;
                if (int.TryParse(txtHits.Text, out currentHits))
                {
                    txtHits.Text = (currentHits + 1).ToString();
                }
                else
                {
                    txtHits.Text = "1";
                }
            });
        }

        private void OnScannerBotStatusChanged(object sender, BotStatusEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateBotActivity($"Bot #{e.BotId}", e.Credential, e.Status, e.Proxy);
            });
        }

        private void OnScannerLogMessage(object sender, string message)
        {
            Dispatcher.Invoke(() =>
            {
                AddLog(message, LogType.Info);
            });
        }

        // ========== TARAMA KONTROLLERİ ==========

        private async void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = GetCurrentConfig();

                // Validation
                if (string.IsNullOrWhiteSpace(config.Target))
                {
                    AddLog("❌ Hedef DNS boş olamaz!", LogType.Error);
                    return;
                }

                if (string.IsNullOrWhiteSpace(config.ComboFilePath) || !File.Exists(config.ComboFilePath))
                {
                    AddLog("❌ Geçerli bir combo dosyası seçin!", LogType.Error);
                    return;
                }

                if (config.UseProxy && (string.IsNullOrWhiteSpace(config.ProxyFilePath) || !File.Exists(config.ProxyFilePath)))
                {
                    AddLog("❌ Proxy kullanımı seçildi ama proxy dosyası bulunamadı!", LogType.Error);
                    return;
                }

                AddLog("🚀 Tarama başlatılıyor...", LogType.Info);
                AddLog($"🎯 Hedef: {config.Target}", LogType.Info);
                AddLog($"🤖 Bot Sayısı: {config.ThreadCount}", LogType.Info);
                AddLog($"⏱️ Timeout: {config.TimeoutSeconds}s", LogType.Info);

                if (config.UseProxy)
                {
                    AddLog($"🔗 Proxy: {config.ProxyType} ({config.ProxyFilePath})", LogType.Info);
                }

                btnStart.IsEnabled = false;
                btnStop.IsEnabled = true;
                txtStatus.Text = "▶️ Tarama aktif - Botlar çalışıyor";

                await _scannerService.StartScanAsync(config);
            }
            catch (Exception ex)
            {
                AddLog($"❌ Başlatma hatası: {ex.Message}", LogType.Error);
                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;
                txtStatus.Text = "❌ Hata oluştu";
            }
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _scannerService.StopScan();
                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;
                txtStatus.Text = "⏹️ Tarama durduruldu";
                AddLog("🛑 Tarama durduruldu", LogType.Warning);
            }
            catch (Exception ex)
            {
                AddLog($"❌ Durdurma hatası: {ex.Message}", LogType.Error);
            }
        }

        private ScanConfig GetCurrentConfig()
        {
            return new ScanConfig
            {
                Target = txtTarget.Text,
                ComboFilePath = txtComboFile.Text,
                ThreadCount = GetIntValue(txtThreadCount.Text, 10),
                StartLine = GetIntValue(txtStartLine.Text, 0),
                TimeoutSeconds = GetIntValue(txtTimeout.Text, 7),
                GetCategories = chkGetCategories.IsChecked == true,
                UseProxy = chkUseProxy.IsChecked == true,
                ProxyFilePath = txtProxyFile.Text,
                ProxyType = (cmbProxyType.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "HTTP"
            };
        }

        private int GetIntValue(string text, int defaultValue)
        {
            if (int.TryParse(text, out int result))
                return result;
            return defaultValue;
        }

        // ========== DOSYA İŞLEMLERİ ==========

        private void BtnBrowseCombo_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            dialog.Title = "Combo Dosyası Seç";

            if (dialog.ShowDialog() == true)
            {
                txtComboFile.Text = dialog.FileName;
                string fileName = Path.GetFileName(dialog.FileName);
                AddLog($"📁 Combo dosyası seçildi: {fileName}", LogType.Success);

                // Dosya bilgilerini göster
                try
                {
                    int lineCount = File.ReadAllLines(dialog.FileName).Length;
                    AddLog($"📊 Dosyada {lineCount} satır bulundu", LogType.Info);
                }
                catch (Exception ex)
                {
                    AddLog($"⚠️ Satır sayısı alınamadı: {ex.Message}", LogType.Warning);
                }
            }
        }

        private void BtnBrowseProxy_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            dialog.Title = "Proxy Dosyası Seç";

            if (dialog.ShowDialog() == true)
            {
                txtProxyFile.Text = dialog.FileName;
                string fileName = Path.GetFileName(dialog.FileName);
                AddLog($"📁 Proxy dosyası seçildi: {fileName}", LogType.Success);
            }
        }

        // ========== LOG FONKSİYONLARI ==========

        public enum LogType { Info, Success, Warning, Error, Hit }

        private void AddLog(string message, LogType type = LogType.Info)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string icon = GetLogIcon(type);

                string logEntry = $"[{timestamp}] {icon} {message}\n";

                txtRealTimeLog.AppendText(logEntry);

                // Otomatik scroll
                if (chkAutoScroll != null && chkAutoScroll.IsChecked == true)
                {
                    txtRealTimeLog.ScrollToEnd();
                }

                // Status bar'a da yaz
                if (type == LogType.Hit || type == LogType.Error)
                {
                    txtStatus.Text = message.Length > 50 ? message.Substring(0, 50) + "..." : message;
                }
            }
            catch (Exception ex)
            {
                // Log ekleme hatasını görmezden gel
                Console.WriteLine($"Log ekleme hatası: {ex.Message}");
            }
        }

        private string GetLogIcon(LogType type)
        {
            if (type == LogType.Success)
                return "✅";
            else if (type == LogType.Error)
                return "❌";
            else if (type == LogType.Warning)
                return "⚠️";
            else if (type == LogType.Hit)
                return "🎯";
            else
                return "ℹ️";
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            txtRealTimeLog.Clear();
            AddLog("Log temizlendi", LogType.Info);
        }

        private void BtnCopyLog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(txtRealTimeLog.Text);
                AddLog("Log panoya kopyalandı", LogType.Success);
            }
            catch (Exception ex)
            {
                AddLog($"❌ Kopyalama hatası: {ex.Message}", LogType.Error);
            }
        }

        // ========== İSTATİSTİK GÜNCELLEME ==========

        private void UpdateStatistics(ScanProgressEventArgs stats)
        {
            try
            {
                double percentage = stats.TotalLines > 0 ? (double)stats.CheckedLines / stats.TotalLines * 100 : 0;

                txtProgress.Text = $"{stats.CheckedLines}/{stats.TotalLines} ({percentage:F1}%)";
                progressBar.Value = percentage;

                txtSpeed.Text = $"{stats.CPM} CPM";
                txtSuccess.Text = $"{stats.SuccessRate:F1}%";
                txtHits.Text = $"{stats.SuccessfulHits}";
                txtTime.Text = stats.ElapsedTime.ToString(@"hh\:mm\:ss");
                txtActiveBots.Text = $"{stats.ActiveBots}";
                txtTested.Text = $"{stats.CheckedLines}";
                txtRate.Text = $"{stats.SuccessRate:F2}%";

                // Calculate remaining time
                if (stats.CPM > 0)
                {
                    int remainingLines = stats.TotalLines - stats.CheckedLines;
                    int remainingMinutes = remainingLines / stats.CPM;
                    txtRemaining.Text = TimeSpan.FromMinutes(remainingMinutes).ToString(@"hh\:mm\:ss");
                }
                else
                {
                    txtRemaining.Text = "∞";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"İstatistik güncelleme hatası: {ex.Message}");
            }
        }

        private void UpdateStatistics(int current, int total, int speed, int hits,
                                    int activeBots, double successRate,
                                    string elapsed, string remaining)
        {
            try
            {
                double percentage = total > 0 ? (double)current / total * 100 : 0;
                txtProgress.Text = $"{current}/{total} ({percentage:F1}%)";
                progressBar.Value = percentage;

                txtSpeed.Text = $"{speed} CPM";
                txtHits.Text = $"{hits}";
                txtSuccess.Text = $"{successRate:F1}%";
                txtTime.Text = elapsed;
                txtActiveBots.Text = $"{activeBots}/10";
                txtTested.Text = $"{current}";
                txtRate.Text = $"{successRate:F2}%";
                txtRemaining.Text = remaining;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"İstatistik güncelleme hatası: {ex.Message}");
            }
        }

        private void UpdateBotActivity(string botId, string credential, string status, string proxy)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string logEntry = $"[{timestamp}] {botId} | {credential} | {status} | Proxy: {proxy}\n";
                txtBotActivity.AppendText(logEntry);

                // Otomatik scroll
                txtBotActivity.ScrollToEnd();

                // Maximum 100 satır tut
                if (txtBotActivity.LineCount > 100)
                {
                    txtBotActivity.Text = txtBotActivity.Text.Substring(txtBotActivity.Text.IndexOf('\n') + 1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Bot aktivite güncelleme hatası: {ex.Message}");
            }
        }

        // ========== YARDIMCI FONKSİYONLAR ==========

        private void ShowToolMessage(string toolName)
        {
            AddLog($"🔧 {toolName} aracı açılıyor...", LogType.Info);
            MessageBox.Show($"{toolName} penceresi yakında eklenecek!",
                          "Yakında",
                          MessageBoxButton.OK,
                          MessageBoxImage.Information);
        }

        // ========== CONTEXT MENU HANDLERS ==========

        private void CopyLog_Click(object sender, RoutedEventArgs e)
        {
            BtnCopyLog_Click(sender, e);
        }

        private void SelectAllLog_Click(object sender, RoutedEventArgs e)
        {
            txtRealTimeLog.SelectAll();
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            BtnClearLog_Click(sender, e);
        }

        private void SaveLog_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog dialog = new SaveFileDialog();
            dialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            dialog.FileName = $"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(dialog.FileName, txtRealTimeLog.Text);
                    AddLog($"💾 Log kaydedildi: {Path.GetFileName(dialog.FileName)}", LogType.Success);
                }
                catch (Exception ex)
                {
                    AddLog($"❌ Kaydetme hatası: {ex.Message}", LogType.Error);
                }
            }
        }

        // ========== WINDOW EVENT HANDLERS ==========

        protected override void OnClosed(EventArgs e)
        {
            // ScannerService'i temizle
            if (_scannerService != null)
            {
                try
                {
                    _scannerService.StopScan();
                }
                catch { }
            }

            base.OnClosed(e);
        }
    }
}
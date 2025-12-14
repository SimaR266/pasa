using MahApps.Metro.Controls;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;
using Microsoft.Win32;
using System.Linq;

namespace ZitrontsScannerPro
{
    public partial class MainWindow : MetroWindow
    {
        private DispatcherTimer timer;
        private DateTime startTime;
        private bool isScanning = false;
        private Random random = new Random();
        private int totalHits = 0;

        public MainWindow()
        {
            InitializeComponent();
            InitializeTimer();
            UpdateDateTime();
        }

        private void InitializeTimer()
        {
            timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(1);
            timer.Tick += Timer_Tick;
            timer.Start();
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            UpdateDateTime();
        }

        private void UpdateDateTime()
        {
            lblDateTime.Text = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
        }

        private void StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (!isScanning)
            {
                if (string.IsNullOrWhiteSpace(txtTarget.Text))
                {
                    MessageBox.Show("Lütfen hedef DNS/M3U giriniz!", "Hata",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (string.IsNullOrWhiteSpace(txtComboFile.Text) || !File.Exists(txtComboFile.Text))
                {
                    MessageBox.Show("Geçerli bir combo dosyası seçiniz!", "Hata",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                isScanning = true;
                startTime = DateTime.Now;
                totalHits = 0;

                btnStart.IsEnabled = false;
                btnStop.IsEnabled = true;
                pbProgress.Value = 0;
                lblHits.Text = "0";
                txtLog.Clear();

                AddLog("🚀 Tarama başlatıldı!", LogType.Success);
                lblStatus.Text = "🔍 Tarama devam ediyor...";

                SimulateProgress();
            }
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            if (isScanning)
            {
                isScanning = false;
                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;

                AddLog("⏹️ Tarama durduruldu!", LogType.Warning);
                lblStatus.Text = "🛑 Tarama durduruldu";
            }
        }

        private void BrowseCombo_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Combo Dosyası Seç"
            };

            if (dialog.ShowDialog() == true)
            {
                txtComboFile.Text = dialog.FileName;
                AddLog($"📁 Combo dosyası seçildi: {Path.GetFileName(dialog.FileName)}", LogType.Info);
            }
        }

        // Araç butonları
        private void ProxyScraper_Click(object sender, RoutedEventArgs e)
        {
            AddLog("🔧 Proxy Scraper açılıyor...", LogType.Info);
            ShowToolWindow("Proxy Scraper");
        }

        private void ProxyUpdate_Click(object sender, RoutedEventArgs e)
        {
            AddLog("🔄 Proxy Güncelleme açılıyor...", LogType.Info);
            ShowToolWindow("Proxy Güncelleme");
        }

        private void DNSFinder_Click(object sender, RoutedEventArgs e)
        {
            AddLog("🔍 DNS Bulucu açılıyor...", LogType.Info);
            ShowToolWindow("DNS Bulucu");
        }

        private void IPTVPlayer_Click(object sender, RoutedEventArgs e)
        {
            AddLog("📺 IPTV Player açılıyor...", LogType.Info);
            ShowToolWindow("IPTV Player");
        }

        private void Orumcek_Click(object sender, RoutedEventArgs e)
        {
            AddLog("🕷️ Örümcek aracı açılıyor...", LogType.Info);
            ShowToolWindow("Örümcek");
        }

        private void TelegramTools_Click(object sender, RoutedEventArgs e)
        {
            AddLog("📱 Telegram araçları açılıyor...", LogType.Info);
            ShowToolWindow("Telegram Tools");
        }

        private void ShowToolWindow(string toolName)
        {
            MessageBox.Show($"{toolName} özelliği yakında eklenecek!", "Bilgi",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void AddLog(string message, LogType type = LogType.Info)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logEntry = $"[{timestamp}] {message}";

            txtLog.AppendText(logEntry + Environment.NewLine);
            txtLog.ScrollToEnd();
        }

        private void SimulateProgress()
        {
            if (!isScanning) return;

            if (pbProgress.Value < 100)
            {
                pbProgress.Value += 0.5;
                lblProgress.Text = $"{pbProgress.Value:F1}/100 ({pbProgress.Value:F1}%)";

                lblSpeed.Text = $"{random.Next(50, 250)} CPM";
                lblSuccess.Text = $"{random.Next(1, 20)}%";

                var elapsed = DateTime.Now - startTime;
                lblTime.Text = elapsed.ToString(@"hh\:mm\:ss");

                if (random.Next(0, 4) == 0)
                {
                    string[] statuses = { "✅ Başarılı", "❌ Timeout", "🔄 Yeniden deniyor" };
                    string status = statuses[random.Next(0, statuses.Length)];

                    AddLog($"Bot-{random.Next(1, GetThreadCount())} | user:pass | {status}");

                    if (status.Contains("✅") && random.Next(0, 15) == 0)
                    {
                        totalHits++;
                        lblHits.Text = totalHits.ToString();
                        AddLog($"🎯 HIT BULUNDU! user{random.Next(1000, 9999)}:pass{random.Next(1000, 9999)}");
                    }
                }

                DispatcherTimer progressTimer = new DispatcherTimer();
                progressTimer.Interval = TimeSpan.FromMilliseconds(100);
                progressTimer.Tick += (s, args) =>
                {
                    progressTimer.Stop();
                    SimulateProgress();
                };
                progressTimer.Start();
            }
            else
            {
                AddLog("✅ Tarama tamamlandı!");
                AddLog($"📊 Sonuç: {totalHits} hit bulundu");
                lblStatus.Text = "✅ Tarama tamamlandı";

                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;
                isScanning = false;
            }
        }

        private int GetThreadCount()
        {
            if (int.TryParse(txtThreadCount.Text, out int count))
                return Math.Max(1, Math.Min(count, 100));
            return 10;
        }

        private enum LogType
        {
            Info,
            Success,
            Warning,
            Error
        }
    }
}
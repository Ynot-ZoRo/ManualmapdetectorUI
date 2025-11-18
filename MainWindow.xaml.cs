using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Windows;

namespace ManualMapDetectorWPF
{
    public partial class MainWindow : Window
    {
        public List<SuspiciousEntry> SuspiciousList = new();

        public MainWindow()
        {
            InitializeComponent();
            ScanBtn.Click += ScanBtn_Click;
            ExportBtn.Click += ExportBtn_Click;
        }

        private void ScanBtn_Click(object sender, RoutedEventArgs e)
        {
            SuspiciousList.Clear();
            ResultsGrid.ItemsSource = null;

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4) continue;
                    var entries = ManualMapScanner.ScanProcess(proc);
                    SuspiciousList.AddRange(entries);
                }
                catch { }
            }

            ResultsGrid.ItemsSource = SuspiciousList;
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"ManualMapScan_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

            using var w = new StreamWriter(path);
            w.WriteLine("PID,ProcessName,BaseAddress,SizeOfImage,InPEB,HasOnDisk,OnDiskPath,PEHeaderOK,MemoryProtect,SizeMismatch");

            foreach (var s in SuspiciousList)
                w.WriteLine(s.ToCsv());

            MessageBox.Show($"Saved to: {path}");
        }
    }
}

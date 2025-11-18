using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ManualMapDetectorWPF
{
    public class SuspiciousEntry
    {
        public int PID { get; set; }
        public string ProcessName { get; set; }
        public string BaseAddress { get; set; }
        public uint SizeOfImage { get; set; }
        public bool InPEB { get; set; }
        public bool HasOnDisk { get; set; }
        public string OnDiskPath { get; set; }
        public bool PEHeaderOK { get; set; }
        public uint MemoryProtect { get; set; }
        public bool SizeMismatch { get; set; }

        public string ToCsv() =>
            $"{PID},{ProcessName},{BaseAddress},{SizeOfImage},{InPEB},{HasOnDisk},{OnDiskPath},{PEHeaderOK},{MemoryProtect},{SizeMismatch}";
    }

    public static class ManualMapScanner
    {
        // (Simplified: Only read the suspicious ones; you can merge your full logic here)

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInherit, int pid);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PROCESS_VM_READ = 0x0010;

        public static List<SuspiciousEntry> ScanProcess(Process proc)
        {
            List<SuspiciousEntry> list = new();
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
            if (hProc == IntPtr.Zero) return list;

            try
            {
                // Dummy placeholder logic (replace with your actual scanning logic)
                // Here we just show processes with no modules as "suspicious"
                if (proc.Modules.Count == 0)
                {
                    list.Add(new SuspiciousEntry
                    {
                        PID = proc.Id,
                        ProcessName = proc.ProcessName,
                        BaseAddress = "0",
                        SizeOfImage = 0,
                        InPEB = false,
                        HasOnDisk = false,
                        PEHeaderOK = false,
                        OnDiskPath = "",
                        MemoryProtect = 0,
                        SizeMismatch = false
                    });
                }
            }
            catch { }
            finally { CloseHandle(hProc); }

            return list;
        }
    }
}

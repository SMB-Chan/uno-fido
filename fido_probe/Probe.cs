using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

class Probe {
  const uint GENERIC_READ = 0x80000000;
  const uint GENERIC_WRITE = 0x40000000;
  const uint FILE_SHARE_READ = 1;
  const uint FILE_SHARE_WRITE = 2;
  const uint OPEN_EXISTING = 3;
  const uint FILE_FLAG_OVERLAPPED = 0x40000000;
  const int DIGCF_PRESENT = 0x02;
  const int DIGCF_DEVICEINTERFACE = 0x10;

  [StructLayout(LayoutKind.Sequential)]
  struct SP_DEVICE_INTERFACE_DATA {
    public int cbSize;
    public Guid InterfaceClassGuid;
    public int Flags;
    public IntPtr Reserved;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
  struct SP_DEVICE_INTERFACE_DETAIL_DATA {
    public int cbSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string DevicePath;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct HIDD_ATTRIBUTES {
    public int Size;
    public ushort VendorID;
    public ushort ProductID;
    public ushort VersionNumber;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct HIDP_CAPS {
    public ushort Usage;
    public ushort UsagePage;
    public ushort InputReportByteLength;
    public ushort OutputReportByteLength;
    public ushort FeatureReportByteLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
    public ushort[] Reserved;
    public ushort NumberLinkCollectionNodes;
    public ushort NumberInputButtonCaps;
    public ushort NumberInputValueCaps;
    public ushort NumberInputDataIndices;
    public ushort NumberOutputButtonCaps;
    public ushort NumberOutputValueCaps;
    public ushort NumberOutputDataIndices;
    public ushort NumberFeatureButtonCaps;
    public ushort NumberFeatureValueCaps;
    public ushort NumberFeatureDataIndices;
  }

  [DllImport("hid.dll")] static extern void HidD_GetHidGuid(out Guid g);
  [DllImport("hid.dll", SetLastError = true)] static extern bool HidD_GetAttributes(SafeFileHandle h, ref HIDD_ATTRIBUTES a);
  [DllImport("hid.dll", SetLastError = true)] static extern bool HidD_GetPreparsedData(SafeFileHandle h, out IntPtr p);
  [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr p);
  [DllImport("hid.dll", SetLastError = true)] static extern int HidP_GetCaps(IntPtr p, out HIDP_CAPS c);
  [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
  static extern IntPtr SetupDiGetClassDevs(ref Guid g, string e, IntPtr h, int flags);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr dev, ref Guid g, int idx, ref SP_DEVICE_INTERFACE_DATA data);
  [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
  static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set, ref SP_DEVICE_INTERFACE_DATA data, ref SP_DEVICE_INTERFACE_DETAIL_DATA detail, int size, out int req, IntPtr dev);
  [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
  [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
  static extern SafeFileHandle CreateFile(string name, uint acc, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool WriteFile(SafeFileHandle h, byte[] buf, int n, out int written, IntPtr ov);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool ReadFile(SafeFileHandle h, byte[] buf, int n, out int read, ref NativeOverlapped ov);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CancelIo(SafeFileHandle h);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool GetOverlappedResult(SafeFileHandle h, ref NativeOverlapped ov, out int transferred, bool wait);

  static string Hex(byte[] b, int n) {
    var s = "";
    for (int i = 0; i < n && i < b.Length; i++) s += b[i].ToString("X2") + (i == 3 || i == 6 ? " " : "");
    return s;
  }

  static void Main() {
    Guid g;
    HidD_GetHidGuid(out g);
    IntPtr set = SetupDiGetClassDevs(ref g, null, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    string path = null;
    for (int i = 0; i < 64; i++) {
      var data = new SP_DEVICE_INTERFACE_DATA();
      data.cbSize = Marshal.SizeOf(data);
      if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref g, i, ref data)) break;
      var detail = new SP_DEVICE_INTERFACE_DETAIL_DATA();
      detail.cbSize = IntPtr.Size == 8 ? 8 : 6;
      int req;
      if (!SetupDiGetDeviceInterfaceDetail(set, ref data, ref detail, Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DETAIL_DATA)), out req, IntPtr.Zero))
        continue;
      var h = CreateFile(detail.DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
      if (h.IsInvalid) { Console.WriteLine("open fail " + detail.DevicePath + " err=" + Marshal.GetLastWin32Error()); continue; }
      var attr = new HIDD_ATTRIBUTES();
      attr.Size = Marshal.SizeOf(attr);
      HidD_GetAttributes(h, ref attr);
      IntPtr prep;
      ushort page = 0, usage = 0;
      if (HidD_GetPreparsedData(h, out prep)) {
        HIDP_CAPS caps;
        if (HidP_GetCaps(prep, out caps) == 0x00110000) { page = caps.UsagePage; usage = caps.Usage; }
        HidD_FreePreparsedData(prep);
      }
      Console.WriteLine(string.Format("VID={0:X4} PID={1:X4} page={2:X4} usage={3:X4} {4}", attr.VendorID, attr.ProductID, page, usage, detail.DevicePath));
      if (attr.VendorID == 0x1209 && attr.ProductID == 0xF1D0 && page == 0xF1D0) path = detail.DevicePath;
      h.Close();
    }
    SetupDiDestroyDeviceInfoList(set);
    if (path == null) { Console.WriteLine("NO FIDO HID"); return; }

    var dev = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
    if (dev.IsInvalid) { Console.WriteLine("reopen fail " + Marshal.GetLastWin32Error()); return; }

    byte[] init = new byte[65];
    init[0] = 0x00;
    init[1] = init[2] = init[3] = init[4] = 0xFF;
    init[5] = 0x86;
    init[6] = 0x00; init[7] = 0x08;
    var rnd = new Random();
    for (int i = 0; i < 8; i++) init[8 + i] = (byte)rnd.Next(256);
    Console.WriteLine("TX INIT " + Hex(init, 16));
    int wr;
    if (!WriteFile(dev, init, 65, out wr, IntPtr.Zero)) Console.WriteLine("write err " + Marshal.GetLastWin32Error());
    var resp = ReadPkt(dev, 2000);
    if (resp == null) { Console.WriteLine("no INIT resp"); return; }
    Console.WriteLine("RX " + Hex(resp, 32));
    byte[] cid = new byte[4];
    Array.Copy(resp, 15, cid, 0, 4); // after report id? resp[0] is report id from ReadFile
    // ReadFile HID: first byte is report ID. Packet starts at index 1.
    // CID of assigned channel is at payload offset: bytes 1-4 are echo CID (ffffffff), cmd at 5.
    // new CID is at offset 7+8 = 15 if report id is byte 0... 
    // If ReadFile returns 64 bytes WITHOUT report id, CID is at 0.
    Console.WriteLine("len guess, dump 64");

    // Determine layout: look for 0x86
    int cmdAt = -1;
    for (int i = 0; i < 10; i++) if (resp[i] == 0x86) { cmdAt = i; break; }
    Console.WriteLine("cmd 0x86 at " + cmdAt);
    int baseOff = cmdAt - 4;
    Array.Copy(resp, baseOff + 15, cid, 0, 4);
    Console.WriteLine("assigned CID " + Hex(cid, 4));

    SendCbor(dev, cid, new byte[] { 0x04 }, "GetInfo");
    SendCbor(dev, cid, new byte[] { 0x07 }, "Reset");
    SendCbor(dev, cid, new byte[] { 0x04 }, "GetInfoAfter");
    dev.Close();
  }

  static void SendCbor(SafeFileHandle dev, byte[] cid, byte[] payload, string name) {
    byte[] pkt = new byte[65];
    pkt[1] = cid[0]; pkt[2] = cid[1]; pkt[3] = cid[2]; pkt[4] = cid[3];
    pkt[5] = 0x90;
    pkt[6] = (byte)(payload.Length >> 8);
    pkt[7] = (byte)(payload.Length & 0xFF);
    Array.Copy(payload, 0, pkt, 8, payload.Length);
    Console.WriteLine("TX " + name);
    int wr;
    if (!WriteFile(dev, pkt, 65, out wr, IntPtr.Zero)) Console.WriteLine("write err " + Marshal.GetLastWin32Error());
    var sw = DateTime.UtcNow;
    for (int n = 0; n < 40; n++) {
      var r = ReadPkt(dev, 3000);
      if (r == null) { Console.WriteLine("  timeout"); return; }
      int cmdAt = -1;
      for (int i = 0; i < 10; i++) if ((r[i] & 0x80) != 0) { cmdAt = i; break; }
      byte cmd = cmdAt >= 0 ? r[cmdAt] : (byte)0;
      int data = cmdAt + 3;
      byte st = data >= 0 && data < r.Length ? r[data] : (byte)0;
      double ms = (DateTime.UtcNow - sw).TotalMilliseconds;
      Console.WriteLine(string.Format("  {0,6:0}ms cmd={1:X2} st={2:X2} {3}", ms, cmd, st, Hex(r, 20)));
      if (cmd != 0xBB) return;
    }
  }

  static byte[] ReadPkt(SafeFileHandle dev, int timeoutMs) {
    byte[] buf = new byte[65];
    var ov = new NativeOverlapped();
    var ev = new ManualResetEvent(false);
    ov.EventHandle = ev.SafeWaitHandle.DangerousGetHandle();
    int read;
    bool ok = ReadFile(dev, buf, buf.Length, out read, ref ov);
    if (!ok) {
      int err = Marshal.GetLastWin32Error();
      if (err != 997) { Console.WriteLine("read err " + err); ev.Close(); return null; }
      if (WaitForSingleObject(ov.EventHandle, (uint)timeoutMs) != 0) {
        CancelIo(dev);
        ev.Close();
        return null;
      }
      if (!GetOverlappedResult(dev, ref ov, out read, false)) { ev.Close(); return null; }
    }
    ev.Close();
    return buf;
  }
}

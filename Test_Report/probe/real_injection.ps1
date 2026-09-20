$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class RI {
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Explicit)] public struct INPUT { [FieldOffset(0)] public uint type; [FieldOffset(8)] public MOUSEINPUT mi; [FieldOffset(8)] public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] p, int cb);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  public static void Uni(char c, bool up) {
    INPUT[] i = new INPUT[1];
    i[0].type = 1; i[0].ki.wVk = 0; i[0].ki.wScan = (ushort)c;
    i[0].ki.dwFlags = up ? (uint)(0x0004|0x0002) : (uint)0x0004;
    SendInput(1, i, Marshal.SizeOf(typeof(INPUT)));
  }
}
"@
[void][RI]::SetProcessDPIAware()

function SleepP([double]$ms) {
  if ($ms -gt 22) { Start-Sleep -Milliseconds ([int]($ms - 14)) }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $t = if ($ms -gt 22) { 14 } else { $ms }
  while ($sw.Elapsed.TotalMilliseconds -lt $t) {}
}

function TypeHuman([string]$text) {
  foreach ($c in $text.ToCharArray()) {
    [RI]::Uni($c, $false)
    SleepP (Get-Random -Minimum 18 -Maximum 47)
    [RI]::Uni($c, $true)
    $d = Get-Random -Minimum 42 -Maximum 191
    if ($c -eq ' ' -and (Get-Random -Minimum 0 -Maximum 100) -lt 35) { $d += Get-Random -Minimum 90 -Maximum 420 }
    if ((Get-Random -Minimum 0 -Maximum 100) -lt 7) { $d += Get-Random -Minimum 150 -Maximum 700 }
    SleepP $d
  }
}

function MoveHuman([int]$x2, [int]$y2) {
  $p = New-Object RI+POINT
  [void][RI]::GetCursorPos([ref]$p)
  $x1 = $p.X; $y1 = $p.Y
  $dx = $x2 - $x1; $dy = $y2 - $y1
  $dist = [Math]::Sqrt($dx * $dx + $dy * $dy)
  if ($dist -lt 3) { return }
  $steps = [int][Math]::Max(16, [Math]::Min(48, $dist / 8))
  $mx = ($x1 + $x2) / 2.0; $my = ($y1 + $y2) / 2.0
  $px = -$dy / $dist; $py = $dx / $dist
  $sign = @(-1, 1) | Get-Random
  $bow = (Get-Random -Minimum 25 -Maximum 85) * $sign
  $cx = $mx + $px * $bow; $cy = $my + $py * $bow
  for ($i = 1; $i -le $steps; $i++) {
    $t = $i / [double]$steps
    $te = $t * $t * (3 - 2 * $t) + (Get-Random -Minimum -25 -Maximum 25) / 1000.0
    if ($te -lt 0) { $te = 0 }; if ($te -gt 1) { $te = 1 }
    $u = 1 - $te
    $bx = $u * $u * $x1 + 2 * $u * $te * $cx + $te * $te * $x2
    $by = $u * $u * $y1 + 2 * $u * $te * $cy + $te * $te * $y2
    [void][RI]::SetCursorPos([int][Math]::Round($bx), [int][Math]::Round($by))
    SleepP (Get-Random -Minimum 6 -Maximum 27)
  }
  [void][RI]::SetCursorPos($x2, $y2)
  SleepP (Get-Random -Minimum 60 -Maximum 220)
}

function ClickHuman {
  [RI]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
  SleepP (Get-Random -Minimum 48 -Maximum 118)
  [RI]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
  SleepP (Get-Random -Minimum 120 -Maximum 380)
}

$sb = New-Object System.Text.StringBuilder 512
$h = [RI]::GetForegroundWindow()
[void][RI]::GetWindowText($h, $sb, 512)
$title = $sb.ToString()
if ($title -notlike "*bot-signal*") { Write-Output "WRONG_WINDOW::$title"; exit 1 }

$r = New-Object RI+RECT
[void][RI]::GetWindowRect($h, [ref]$r)
Write-Output ("RECT=" + $r.L + "," + $r.T + "," + $r.R + "," + $r.B)

$fields = $env:BS_FIELDS -split ';'
foreach ($f in $fields) {
  $parts = $f -split ','
  MoveHuman ([int]$parts[0]) ([int]$parts[1])
  ClickHuman
  TypeHuman $parts[2]
  SleepP (Get-Random -Minimum 250 -Maximum 700)
}

$submit = $env:BS_SUBMIT -split ','
MoveHuman ([int]$submit[0] - 120) ([int]$submit[1] - 60)
MoveHuman ([int]$submit[0]) ([int]$submit[1])
SleepP (Get-Random -Minimum 300 -Maximum 800)
ClickHuman
Start-Sleep -Seconds 3
Write-Output "SEQUENCE_DONE"

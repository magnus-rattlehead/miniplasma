"""Generate self-contained PowerShell loader with shellcode embedded as base64."""
import base64, sys, os

tmpl = sys.argv[1]   # tools/run_sc.ps1
bin  = sys.argv[2]   # build/miniplasma_2_sc.bin
out  = sys.argv[3]   # build/run_miniplasma.ps1

with open(bin, 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

with open(tmpl) as f:
    s = f.read()

s = s.replace('$B64 = ""', '$B64 = "' + b64 + '"', 1)

with open(out, 'w') as f:
    f.write(s)

print(f"Wrote {out} ({os.path.getsize(out)} bytes)")

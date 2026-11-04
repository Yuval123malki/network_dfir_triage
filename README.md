# network_dfir_triage

Offline, read-only DFIR triage tool for a secondary Windows drive mounted on
an investigation workstation (e.g. a drive letter such as `E:\`, or a mount
point that represents the root of a dead system).

The script never opens a file on the target drive for writing. Every
artifact is copied (read-only) into the output folder first, then parsed
from that local copy, so the evidence drive is never touched after the
initial copy pass.

## What it collects

1. Process Creation — Security EVTX (EventID 4688) + Sysmon Operational (EventID 1)
2. Network Events — NetworkProfile / WLAN-AutoConfig / Windows Firewall operational logs
3. DHCP — DHCP-Client operational/admin logs + per-interface DHCP lease registry values
4. DNS — DNS-Client operational log, hosts file, interface configuration
5. Recycle Bin — `$I` / `$R` enumeration across all user SIDs (original path, size, deletion time)
6. USB Device History — SetupAPI logs + `USBSTOR` / `Enum\USB` / `DeviceClasses` registry keys
7. Authentication — Security EVTX 4624 / 4625 / 4648 / 4720
8. Persistence — Run/RunOnce keys (SOFTWARE + all NTUSER.DAT), Services, Scheduled Tasks
9. Execution artifacts — Prefetch (run count/last run), Amcache, Shimcache (best effort)
10. User Activity — LNK files, Jump Lists, Shellbags (best effort)

Every module is wrapped in its own error handling: a missing log, locked
file, or corrupted artifact is recorded in the execution log and skipped —
it never aborts the rest of the run.

## Running it

### Standalone executable (no Python required)

Download `dfir_triage.exe` from the [Releases](../../releases) page and run:

```
dfir_triage.exe --target E:\ --output D:\Cases\Case001 --name VICTIM-PC
```

### From source

```
pip install -r requirements.txt
python dfir_triage.py --target E:\ --output D:\Cases\Case001 --name VICTIM-PC
```

Optional dependencies (`python-evtx`, `regipy`, `olefile`) are each
independent — if one isn't installed, only the modules that need it are
skipped; everything else still runs.

### Arguments

| Flag | Description |
|---|---|
| `--target` | Root of the offline/mounted drive to triage (required) |
| `--output` | Base folder where the `Investigation_Output_*` folder is created |
| `--name` | Label for the target system (default: derived from `--target`) |
| `--max-evtx-records` | Optional cap on records parsed per EVTX log (useful for a quick test pass) |
| `--no-copy-raw` | Skip copying raw artifact files (Prefetch/LNK/JumpList); CSV/JSON output is still produced |

The tool refuses to run if `--output` resolves to a path inside `--target`,
to avoid ever writing into the evidence drive.

## Output structure

```
Investigation_Output_<Name>_<Timestamp>/
  Investigation_Summary.txt       Notepad-friendly executive summary
  _script_execution.log           every skip/warning/error, per artifact
  Raw_Data/
    01_ProcessCreation/
    02_Network/
    03_DHCP/
    04_DNS/
    05_RecycleBin/
    06_USBHistory/
    07_Authentication/
    08_Persistence/
    09_Execution/
    10_UserActivity/
      (each category folder has CSV + JSON output, plus a Raw_Copies/
       subfolder with the copied source artifacts)
```

## Honesty about limitations

Amcache, Shimcache, and Shellbags use genuinely complex, version-dependent
binary formats. This tool always preserves the raw hive/value for a
dedicated parser (AmcacheParser / AppCompatCacheParser / SBECmd), and
clearly labels its own decode of them as *best effort* rather than
presenting unverified data as fact. Validate against a known-good test
image before relying on this tool for a real case.

## Building the standalone exe yourself

```
pip install -r requirements.txt pyinstaller
python -m PyInstaller dfir_triage.spec --clean --noconfirm
```

The resulting `dist\dfir_triage.exe` is self-contained (built x64, tested on
Windows Server 2019 / Windows 10/11 x64).

---
**Author:** Yuval Malki ([Yuval123malki](https://github.com/Yuval123malki))

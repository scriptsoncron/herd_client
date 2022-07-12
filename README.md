# HERD CLI Tool 

The script (Python 3.8+) simplifies interacting with the HERD API for uploading files, searching by SHA256 hashes, and downloading reports. **ONLY SHA256 SUPPORTED**.

DM for API access [@HerdSecurity](https://twitter.com/HerdSecurity)

---
## Install
```
git clone https://github.com/scriptsoncron/cli_tool

python3 -m pip install -r requirements.txt
```
---
## Flags
```
Arguments:
  -h, --help        show this help message and exit
  -x , --detonate   Input: file, directory
  -s , --search     Search by a single SHA, list of SHAs, file of SHAs newline delimited, or by 'last' for last uploaded files
  -t , --type       Output options: all, static, dynamic, emulation; Default: all
  -o, --output      Writes results into separate json files (<sha>.json)
  -k , --key        REQUIRED API Key
  -f, --force       Force re-upload
```
---

## Examples
**Detonate File**
```
herding.py -k <key> -x Installer.exe
```

**Force Re-Detonation File**
```
herding.py -k <key> -x Installer.exe -f
```

**Detonate Directory (of files)**
```
herding.py -k <key> -x samples/ 
```

**Check Results**
```
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f
```

**Download (All) Results**
```
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f -o
```

**Download ONLY Static Results**
```
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f -o -t static
```

**Download ONLY Dynamic Results**
```
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f -o -t dynamic
```

**Download ONLY Emulation Results**
```
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f -o -t emulation
```

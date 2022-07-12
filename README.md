# HERD CLI Tool

The commandline tool makes it easy to interact with the HERD API by uploading files, searching by SHA256, and downloading reports.

DM for API access [@HerdSecurity](https://twitter.com/HerdSecurity)

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

## Examples

**Detonate File**
```
python herding.py -k <key> -x Installer.exe
```

**Detonate Directory (of files)**
```
python herding.py -k <key> -x samples/ 
```

**Check Results**
```
python herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f
```

**Download Results**
```
python herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f -o
```
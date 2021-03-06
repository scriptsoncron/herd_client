# HERD Python (3.8+) Client

The script simplifies interacting with the HERD API for detonating files within the high volume, scalable HERD sandbox, searching for results by a SHA256 hash, and downloading sandbox reports. **ONLY SHA256 SUPPORTED**.

Slide into our DMs [@HerdSecurity](https://twitter.com/HerdSecurity) for API access 


## Install
```
git clone https://github.com/scriptsoncron/herd_client

python3 -m venv herd_client && cd $_

python3 -m pip install -r requirements.txt
```

## Flags
```
Arguments:
  -h, --help        show this help message and exit
  -x , --detonate   Input: file, directory
  -s , --search     Search by a single SHA, list of SHAs, file of SHAs newline delimited, or by 'last' for last uploaded files
  -t , --type       Output options: all, static, dynamic, emulation; Default: all
  -o, --output      Writes results into separate json files (<sha>.json)
  -k , --key        REQUIRED API Key
```

## Examples
**Detonate File**
```
herding.py -k <key> -x Installer.exe
```

**Detonate Directory (of files)**
```
herding.py -k <key> -x samples/ 
```

**Search Results**
```
# single sha256
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f

# list of sha256
herding.py -k <key> -s 23aa3b623889c24203dc75cc3512288bc723e2747e5913bf86a559a25ae7ea3f, 19b0a8993f4c64d143fa7f4e254064cb305612199e531635e864eda60e5fa83

# file containing sha256 (newline delimited)
herding.py -k <key> -s hashes.txt
```

**Download (All) Results**
> All output goes to a json file
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

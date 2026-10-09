# Collect DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

It will also create a report about a checklist of most common questions.

# How to execute:

```bash
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh
```

# Notes 
- The script must run as root (use `sudo`).
- The script will not stop/start or touch any service, and it does not install packages. Installing `smartmontools` (for storage health), `nice-dcv-gl` (if you use a GPU) and `nice-dcv-gltest` makes the report more complete.
- In the end the script uploads the log bundle over HTTPS to NI SP and requests an automatic AI analysis from Deep NI SP. It prints a private link where the report will be ready within ~30 minutes. The bundle itself is not encrypted, because the analysis needs to read it. Values of environment variables that look like secrets (tokens, passwords, keys, proxy credentials) are masked before collection.
- If you can not upload due to missing internet access or internal WAF rules, the bundle is kept locally so you can upload it manually to https://upload.ni-sp.com/ and send the link to NI SP Support.
- Supported systems: RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux 7 to 10, and Ubuntu 18.04, 20.04, 22.04 and 24.04 LTS. If your OS is not supported, you can force the log collection with the `--force` parameter.

# Advanced parameters

You can execute the script without interaction using the parameters below. Use `-h` or `--help` to see all available options.

```bash
# For report-only mode
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --report-only

# Collect logs without upload (the bundle is kept locally)
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --without-upload

# Fully non-interactive example
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --name "John Doe - ACME Corp" --email john@acme.com --problem "Black screen after login"
```

| Parameter | Description |
|---|---|
| `-h`, `--help` | Show help message with all available options and exit |
| `--force` | Skip Linux distribution compatibility check. Use this if your OS is not officially supported |
| `--report-only` | Only generate the report without collecting logs. Ideal for quickly checking common issues. **No logs are collected** from your server, so the report can be shared without concern |
| `--collect-logs` | Collect most relevant logs and also create the report. This is the default mode, best when you need help from NI SP support |
| `--without-upload` | Skip the automatic upload to NI SP. The file is preserved locally. You can then manually upload it to https://upload.ni-sp.com/ and send the generated link to NISP Support Team |
| `--without-compression` | Skip compression and keep the collected logs as a directory (`dcv_logs_collection/`). Implies `--without-upload` |
| `--proxy "url"` | Use a proxy for uploading the file. Supports HTTP, HTTPS, and SOCKS proxies (e.g. `http://proxy:8080`, `socks5://proxy:1080`) |
| `--name "text"` | Your name or company, sent with the AI analysis request |
| `--email "addr"` | Your e-mail, so NI SP Support can reach you |
| `--problem "text"` | Short description of the problem you are seeing |
| `--message "text"` | Deprecated alias of `--problem` |
| `--without-encryption` | Deprecated, has no effect (the bundle is not encrypted) |

`--name`, `--email` and `--problem` are asked interactively when missing. When the script runs without a terminal (cron, Ansible, SSM...), they are mandatory unless `--without-upload` is used. Unknown parameters stop the script with an error.

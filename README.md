# Collect DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

It will also create a report about a checklist of most common questions.

# How to execute:

```bash
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh
```

# Notes 
- The script will not stop/start or touch any service without your permission.
- In the end the script will try to upload your logs automatically to our cloud. The logs will be encrypted and also be sent through HTTPS, with total security. If you can not send due internal WAF rules, in the end of the execution you can save the log collection file and send to us.
- If your OS is not supported, you can force the log collect with --force parameter

# Advanced parameters

You can execute the script without interaction using the parameters below. Use `-h` or `--help` to see all available options.

```bash
# For report-only mode
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --report-only

# For collect-logs mode
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --collect-logs

# Collect logs without encryption and without upload
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --collect-logs --without-encryption --without-upload

# Fully non-interactive example
wget --no-check-certificate -O Collect-DCV-Logs.sh https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh && sudo bash Collect-DCV-Logs.sh --collect-logs --message "John Doe - ACME Corp"
```

| Parameter | Description |
|---|---|
| `-h`, `--help` | Show help message with all available options and exit |
| `--force` | Skip Linux distribution compatibility check. Use this if your OS is not officially supported |
| `--report-only` | Only generate the report without collecting logs. Ideal for quickly checking common issues. **No logs are collected** from your server, so the report can be shared without concern |
| `--collect-logs` | Collect most relevant logs and also create the report. Best mode when you need help from NI-SP support. Skips the interactive menu |
| `--without-encryption` | Create the compressed file without GPG encryption. The `.tar.gz` file will not be encrypted with a passphrase |
| `--without-upload` | Skip the automatic upload to NI-SP. The file is preserved locally. You can then manually upload it to https://ni-sp.com:9443/ and send the generated link to NISP Support Team |
| `--without-compression` | Skip compression and keep the collected logs as a directory (`dcv_logs_collection/`). Implies `--without-encryption` and `--without-upload` |
| `--message "text"` | Provide the identifier text for NISP Support Team (e.g. e-mail, name, company name). Skips the interactive prompt that asks for this information |

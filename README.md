# Collect DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

It will also create a report about a checklist of most common questions.

How to execute:

```bash
# For interactive mode
sudo bash Collect-DCV-Logs.sh

# For report-only mode
sudo bash Collect-DCV-Logs.sh --report-only

# For collect-logs mode
sudo bash Collect-DCV-Logs.sh --collect-logs
```

or

```bash
# For interactive mode
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh)"

# For report-only mode
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh) -- --report-only"

# For collect-logs mode
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh) -- --collect-logs"
```

**Important:** The script will not stop/start or touch any service without your permission. When needed, the script will ask and you can say no if you do not agree.


If your OS is not supported, you can force the log collect with --force parameter:

```bash
sudo bash Collect-DCV-Logs.sh --force
```
or 

```bash
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh)" -- --force
```

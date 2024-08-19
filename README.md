# Collect DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

How to execute:

```bash
sudo bash Collect-DCV-Logs.sh
```

or

```bash
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh)"
```

Important: The script will not stop/start or touch any service without your permission. When needed, the script will ask and you can say no if you do not agree.


If your OS is not supported, you can force the log collect with --force parameter:

```bash
sudo bash Collect-DCV-Logs.sh --force
# or
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh)" -- --force
```

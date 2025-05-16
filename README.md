# Collect DCV Logs

This script was created to help you collect all relevant logs to troubleshoot any DCV issue.

It will also create a report about a checklist of most common questions.

# How to execute:

You can execute the script in the interactive mode or without interaction.

There are two modes:
- **--report-only :** It will just create a report. This is ideal if you want to fastly discover most common questions. This mode it **it will not collect** any log from your server, which means that you can share without concern. All issues found will point to a possible causes and solutions.
- **--collect-logs:** It will collect most relevant logs and it will also create the report. This is the best mode when you need help from NI-SP support, as we need to check deeply your logs.

To execute:

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

**Important:** 
- The script will not stop/start or touch any service without your permission.
- In the end the script will try to upload your logs automatically to our cloud. The logs will be encrypted and also be sent through HTTPS, with total security. If you can not send due internal WAF rules, in the end of the execution you can save the log collection file and send to us.

- If your OS is not supported, you can force the log collect with --force parameter:

```bash
sudo bash Collect-DCV-Logs.sh --force
```
or 

```bash
sudo bash -c "$(wget --no-check-certificate -qO- https://raw.githubusercontent.com/NISP-GmbH/Collect-DCV-Logs/main/Collect-DCV-Logs.sh)" -- --force
```

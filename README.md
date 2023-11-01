## Okta Session Analyzer

The Okta Session Analyzer allows security teams to analyze Okta event logs for security insights.

### New Detection Features (Version 1.0)

As part of our ongoing commitment to security, we've rolled out the following features to enhance the detection capabilities of the Okta Session Analyzer:

- **High-Frequency Push MFA Requests Detection**: Tracks the occurrence of multiple MFA push requests and failures within a user's session. This pattern can be indicative of bypassing security mechanisms. The threshold for "high frequency" is configurable in the tool settings.

- **Delegate IDP Configuration Change Alert**: Monitors and alerts on any changes to delegate identity providers configurations within an Okta instance. Essential for maintaining the integrity of your IDP configurations.

- **Multiple User-Agents Detection**: Flags sessions that show activity from multiple user-agents, potentially indicating cookie hijacking incidents.

- **Fast-Travel Activity Analysis**: Implements checks for geographically improbable travel activity within sessions, which could be indicative of compromised account credentials.

- **Unauthorized Application Access Attempts Monitoring**: Identifies and alerts on repeated attempts to access unauthorized applications, signaling potential malicious intent or compromised accounts.

# Quickstart

1. `pip install pandas`
2. `python okta_session_analyzer.py <okta_events.csv>`

## Prerequisites

Before using the Okta Session Analyzer, ensure that you have Python installed on your system. This tool is compatible with Python 3.x.

## Step 1: Downloading Okta Event Logs

1. **Log in to your Okta Console**: Access your Okta admin console by navigating to your Okta domain (e.g., `yourcompany.okta.com`).

2. **Access the System Log**:

   - Navigate to **Reports** on the dashboard.
   - Select **System Log** from the drop-down menu.

3. **Select a Date Range (Optional)**:

   - To filter the logs for a specific period, select a date range at the top of the System Log page.

4. **Download the Logs**:
   - Click on the **Download CSV** button to download the event logs.
   - Save the CSV file to a known location on your system.

## Step 2: Running the Okta Session Analyzer

After downloading the CSV file with your Okta event logs, you are ready to use the analyzer tool.

1. **Open a Terminal or Command Prompt**:

   - Navigate to the folder where you saved the Okta Session Analyzer script (`okta_session_analyzer.py`).

2. **Install Dependencies**

   - Install the pandas dependency:
     ```
     pip install pandas
     ```

3. **Run the Tool**:

   - Execute the tool by typing the following command and replacing `syslog_query.csv` with the path to your downloaded CSV file:
     ```sh
     python okta_session_analyzer.py syslog_query.csv
     ```
   - Press `Enter` to run the script.

4. **Review the Analysis**:
   - The tool will process the event logs and output the analysis to your terminal or command prompt.
   - Review the output for any security insights or alerts. The output from the Session Analyzer will provide a list of session IDs that can be further queried from Okta's System Log. An example of query would be `authenticationContext.externalSessionId eq "zqxNPAJAK5J25SystR3iydyTg"` or `uuid eq "87dcd170-78db-11ee-9797-c718a50aa4d3"`

## Additional Configuration

The Okta Session Analyzer offers various configuration options to tailor the analysis to your specific needs. Refer to the `python okta_session_analyzer.py --help` command for detailed information on setting analysis thresholds and customizing alert conditions.

## Support

For any issues or questions regarding the use of the Okta Session Analyzer, please open an issue on the repository or contact our support team at `support@beyondidentity.com`.

Thank you for using the Okta Session Analyzer to secure your Okta environment.

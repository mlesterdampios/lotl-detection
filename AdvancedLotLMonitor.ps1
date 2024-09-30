# LotL Detection Script with Command Line Auditing and Handling Missing CommandLine
# This script monitors for Living off the Land (LotL) executions on Windows systems.
# It enables command line auditing, logs events, sends syslog messages, emails alerts,
# and blocks execution based on severity.

# Define the log file path
$LogFilePath = 'C:\LotL_detection_log.txt'

# Function to write to log file and console
function Write-Log {
    param([string]$Message)
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $LogMessage = "$TimeStamp - $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFilePath -Value $LogMessage
}

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "This script must be run as an administrator."
    exit
}

# Enable process creation auditing
try {
    Write-Log "Enabling process creation auditing..."
    AuditPol.exe /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Write-Log "Process creation auditing enabled. If this is your first time running this script, please restart to apply the Process Creation policy modification."
} catch {
    Write-Log "Error enabling process creation auditing: $_"
}

# Enable command line auditing
try {
    Write-Log "Enabling command line auditing..."
    $RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    New-ItemProperty -Path $RegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Log "Command line auditing enabled."
} catch {
    Write-Log "Error enabling command line auditing: $_"
}

# Define LotL executables with severity levels
$LotLExecutables = @{
    'powershell.exe'   = 'High'
    'cmd.exe'          = 'Medium'
    'regsvr32.exe'     = 'High'
    'mshta.exe'        = 'High'
    'wmic.exe'         = 'Medium'
    'certutil.exe'     = 'High'
    'rundll32.exe'     = 'High'
    'bitsadmin.exe'    = 'Medium'
    'msbuild.exe'      = 'High'
    'msiexec.exe'      = 'Medium'
    'installutil.exe'  = 'High'
    'reg.exe'          = 'Medium'
    'schtasks.exe'     = 'Medium'
    'sc.exe'           = 'Medium'
    'net.exe'          = 'Medium'
    'net1.exe'         = 'Medium'
    'mavinject.exe'    = 'High'
    'forfiles.exe'     = 'High'
    'cscript.exe'      = 'Medium'
    'wscript.exe'      = 'Medium'
}

# Define Parent Process Whitelist
$ParentProcessWhitelist = @(
    "Docker Desktop.exe"# Add more parent process names as needed
)

# Function to send syslog message
function Send-Syslog {
    param(
        [string]$Message,
        [string]$SyslogServer = '127.0.0.1', # Replace with your syslog server IP
        [int]$Port = 514
    )
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($SyslogServer, $Port)
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
        $udpClient.Send($bytes, $bytes.Length) | Out-Null
        $udpClient.Close()
        Write-Log "Syslog message sent."
    } catch {
        Write-Log "Error sending syslog message: $_"
    }
}

# Function to send email with enhanced error handling
function Send-Email {
    param(
        [string]$_Subject,
        [string]$_Body
    )
    try {
        # SMTP server details for Gmail
        $smtpServer = "smtp.gmail.com"
        $smtpPort = 587

        # Your Gmail credentials
        $gmailUsername = "example@gmail.com"
        $gmailPassword = "password"

        # Email details
        $from = "example@gmail.com"
        $to = "example@gmail.com"
        $subject = $_Subject
        $body = $_Body

        # Create a secure string for the password
        $securePassword = ConvertTo-SecureString $gmailPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($gmailUsername, $securePassword)

        # Send the email
        Send-MailMessage -SmtpServer $smtpServer -Port $smtpPort -UseSsl -Credential $credential -From $from -To $to -Subject $subject -Body $body -ErrorAction 'Stop'
        Write-Log "Email alert sent."
    } catch {
        Write-Log "Error sending email: $_"
    }
}

# Get the last RecordId and TimeCreated to start with
$FilterHashTable = @{
    LogName = 'Security'
    ID      = 4688
}

$LastEvent = Get-WinEvent -FilterHashtable $FilterHashTable -MaxEvents 1 -ErrorAction SilentlyContinue
if ($LastEvent) {
    $LastRecordId = $LastEvent.RecordId
    $LastEventTime = $LastEvent.TimeCreated
} else {
    $LastRecordId = 0
    $LastEventTime = (Get-Date).AddSeconds(-5)
}

Write-Log "Starting LotL Detection script. Initial Record ID: $LastRecordId, Initial Event Time: $LastEventTime"

# Main monitoring loop
while ($true) {
    try {
        # Fetch new events with Event ID 4688 and TimeCreated >= $LastEventTime
        $FilterHashTable = @{
            LogName   = 'Security'
            ID        = 4688
            StartTime = $LastEventTime.AddMilliseconds(-1)
        }

        $Events = Get-WinEvent -FilterHashtable $FilterHashTable -ErrorAction SilentlyContinue

        if ($Events) {
            # Initialize variables to track the maximum RecordId and TimeCreated
            $MaxRecordIdProcessed = $LastRecordId
            $MaxEventTimeProcessed = $LastEventTime

            foreach ($Event in $Events | Where-Object { $_.RecordId -gt $LastRecordId }) {

                # Process event
                # Parse event data
                $EventData = [xml]$Event.ToXml()
                $EventDataItems = $EventData.Event.EventData.Data

                $DataDictionary = @{}
                foreach ($DataItem in $EventDataItems) {
                    $DataDictionary[$DataItem.Name] = $DataItem.'#text'
                }

                $NewProcessName    = $DataDictionary['NewProcessName']
                $ProcessID         = $DataDictionary['NewProcessId']
                $ParentProcessName = $DataDictionary['ParentProcessName']
                $UserName          = $DataDictionary['SubjectUserName']
                $DomainName        = $DataDictionary['SubjectDomainName']
                $User              = "$DomainName\\$UserName"
                $CommandLine       = $DataDictionary['CommandLine']

                # Handle missing CommandLine field
                if (-not $CommandLine -or [string]::IsNullOrWhiteSpace($CommandLine)) {
                    $CommandLine = "N/A"
                }

                $ExeName = [System.IO.Path]::GetFileName($NewProcessName).ToLower()
                $ParentExeName = [System.IO.Path]::GetFileName($ParentProcessName).ToLower()

                # Check if parent process is in the whitelist
                if ($ParentProcessWhitelist -contains $ParentExeName) {
                    #Write-Log "Process $ExeName (PID: $ProcessID) launched by whitelisted parent process $ParentExeName. Ignoring."
                }
                else {
                    if ($LotLExecutables.ContainsKey($ExeName)) {
                        $Severity = $LotLExecutables[$ExeName]
                        $Message = "Detected LotL execution: $NewProcessName by $User (PID: $ProcessID, Parent: $ParentProcessName). Severity: $Severity. CommandLine: $CommandLine"
                        Write-Log $Message

                        # Send syslog message
                        Send-Syslog -Message $Message

                        # Send email alert
                        Send-Email -_Subject "Alert: LotL execution detected ($Severity)" -_Body "Detected LotL execution: $NewProcessName`nUser: $User`nPID: $ProcessID`nParent: $ParentProcessName`nSeverity: $Severity."

                        # Block execution depending on severity
                        if ($Severity -eq 'High') {
                            # Kill the process with enhanced error handling
                            try {
                                Stop-Process -Id $ProcessID -Force -ErrorAction Stop
                                Write-Log "Process $ProcessID ($NewProcessName) has been terminated due to high severity."
                            } catch [System.Management.Automation.RuntimeException] {
                                if ($_.Exception.Message -like "*Cannot find a process with the process identifier*") {
                                    Write-Log "Process $ProcessID ($NewProcessName) is already terminated."
                                } else {
                                    Write-Log "Error terminating process ${ProcessID}: $_"
                                }
                            } catch {
                                Write-Log "Unexpected error terminating process ${ProcessID}: $_"
                            }
                        } else {
                            Write-Log "Process $ProcessID ($NewProcessName) allowed to continue."
                        }
                    } else {
                        #Write-Log "Process created: $NewProcessName by $User (PID: $ProcessID, Parent: $ParentProcessName)"
                    }
                }

                # Update the max RecordId and TimeCreated
                if ($Event.RecordId -gt $MaxRecordIdProcessed) {
                    $MaxRecordIdProcessed = $Event.RecordId
                }
                if ($Event.TimeCreated -gt $MaxEventTimeProcessed) {
                    $MaxEventTimeProcessed = $Event.TimeCreated
                }
            }

            # After processing all events, update the last processed RecordId and TimeCreated
            $LastRecordId = $MaxRecordIdProcessed
            $LastEventTime = $MaxEventTimeProcessed
        }

        # Sleep for a short interval before checking again
        Start-Sleep -Seconds 2
    } catch {
        Write-Log "Error in main monitoring loop: $_"
    }
}

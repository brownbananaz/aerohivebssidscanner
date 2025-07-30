# Aerohive AP Information Extractor

A Python GUI application for extracting BSSID, SSID, and hostname information from Aerohive access points via SSH.

## Features

- **GUI Interface**: User-friendly Tkinter-based interface
- **Multi-IP Support**: Extract from single IPs, IP ranges, or CIDR networks
- **SSH Connection**: Secure connection to Aerohive access points
- **Data Export**: Export results to CSV format
- **Real-time Display**: View raw command output and formatted results in separate tabs

## Requirements

- Python 3.x
- paramiko library (for SSH connections)

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage

### Running the Application

**Option 1: Using the run script**
```bash
./run.sh
```

**Option 2: Direct Python execution**
```bash
python3 aerohive_extractor.py
```

### Using the GUI

1. **Connection Settings**:
   - **IP Address/Range**: Enter single IP, range (192.168.1.1-10), or CIDR (192.168.1.0/24)
   - **Username**: SSH username for the access points
   - **Password**: SSH password for the access points
   - **Timeout**: Connection timeout in seconds (default: 30)

2. **Extract Information**: Click to start the extraction process

3. **View Results**:
   - **Raw Data Tab**: Shows complete SSH command output
   - **Formatted Data Tab**: Displays structured results in a table

4. **Export**: Save results to CSV file with timestamp

## Supported Input Formats

- Single IP: `192.168.1.100`
- IP Range: `192.168.1.1-10`
- CIDR Network: `192.168.1.0/24`
- Multiple IPs: `192.168.1.100, 192.168.1.200`

## Output Information

The application extracts the following information for each access point:

- **IP Address**: The IP address of the access point
- **Hostname**: The configured hostname of the device
- **Interface**: WiFi interface name (wifi0.1, wifi0.2, etc.)
- **BSSID**: Basic Service Set Identifier (MAC address)
- **SSID**: Service Set Identifier (network name)

## Technical Details

- Connects to access points via SSH using paramiko
- Queries multiple WiFi interfaces: wifi0.1-wifi0.5, wifi1.1-wifi1.5, and wifi2.1-wifi2.5
- Uses regex parsing to extract MAC addresses and SSID information
- Multi-threaded operation to prevent GUI freezing during extraction
- Automatic CSV export with timestamp formatting

## Interface Limitations

**Supported Interfaces**: The tool currently supports up to 5 SSIDs per radio band:
- **Radio 0**: wifi0.1, wifi0.2, wifi0.3, wifi0.4, wifi0.5
- **Radio 1**: wifi1.1, wifi1.2, wifi1.3, wifi1.4, wifi1.5  
- **Radio 2**: wifi2.1, wifi2.2, wifi2.3, wifi2.4, wifi2.5

**Note**: Only active interfaces with configured SSIDs will appear in the results. Unused interface slots on APs with fewer than 5 SSIDs per radio will be automatically filtered out of the report.

## Security Notes

- Credentials are handled in memory only
- SSH connections use paramiko with auto-accept host key policy
- Application is intended for authorized network administration use only

## Troubleshooting

- Ensure SSH is enabled on target access points
- Verify correct credentials and network connectivity
- Check firewall settings if connections fail
- Increase timeout value for slow network connections
## Requirements

- Go 1.26.2+ (or compatible)
- libpcap-dev
- Linux environment (tested on Xubuntu CORE)
- Root/Admin privileges for packet capture

## Installation

### Ubuntu / Xubuntu CORE

```bash
sudo apt update
sudo apt install golang-go libpcap-dev
```

**Clone the repository:**

```bash
git clone https://github.com/MiguelP307/Packet-Sniffer-RC.git
cd rc-sniffer
```

**Download dependencies:**

```bash
go mod download
```


## Build

```bash
go build -o sniffer ./cmd/sniffer
```

## RUN

```bash
sudo ./sniffer
```


## Selecting an interface

After launching the app:

1. Select "Start Capture"
2. Select "Interface"
3. Choose between all the available interfaces, selecting the desired one


## Selecting a filter

**After launching the app:**

1. Select "Start Capture"
2. Select "Filter"
3. Choose between all the available filter or select "Custom..." if you want to give a filter as an input

#### Note: 
Filters have a similar format to the ones used on `tcpdump`


## Controls

The footer displays all available keybindings during execution.

**Example controls:**
- q → quit application
- p → pause capture
- ↑/↓ → navigate menus
- enter → confirm selection
- esc → navigate to the last menu
- c → Show available connections 

## Logging

Captured packets can will be automatically logged, you can find the logs inside a directory on the root of the project named **"logs"**.
Log's file name will be on the following formate: `<interface>_<date>_<time>.log`


## Running on CORE

1. Open a terminal on the desired CORE node
2. Transfer/build the application
3. Run with root privileges:

```bash
sudo ./sniffer
```


## Running on PC

The application can also capture traffic from real interfaces such as:
- Ethernet (eth0)
- Wi-Fi (wlan0)

Administrator/root privileges are required. (sudo)
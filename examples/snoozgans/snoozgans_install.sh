#!/bin/bash

# Variables
SCRIPT_NAME="celular.py"
SCRIPT_DEST="/usr/local/bin/celular"
CONFIG_FILE="celular.json"
CONFIG_DEST="/usr/local/etc/celular.json"
SERVICE_FILE="snoozgans.service"
TIMER_FILE="snoozgans.timer"
#TEST_SERVICE_FILE="snoozgans-test.service"
#TEST_TIMER_FILE="snoozgans-test.timer"
SYSTEMD_PATH="/etc/systemd/system"
VENV_PATH="/usr/local/bin/celular_venv"

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Check if sudo available
if ! command -v sudo &> /dev/null; then
    echo "sudo not found. Please install sudo and try again."
    exit 1
fi

# Check if sudo available
if ! command -v /sbin/shutdown &> /dev/null; then
    echo "shutdown not found. Will attempt install."
    sleep 5
    apt update
    apt install systemd-sysv || exit 1
    if ! command -v /sbin/shutdown &> /dev/null; then
        exit
    fi
fi

# Install python dependencies
if ! command -v virtualenv &> /dev/null; then
    echo "virtualenv not found. Will attempt install."
    sleep 5
    apt update
    apt install python3-virtualenv || exit 1
fi;

virtualenv $VENV_PATH 
source $VENV_PATH/bin/activate
pip install lark-parser cel-python psutil
deactivate

# Create destination directories if they do not exist
mkdir -p $(dirname $SCRIPT_DEST)
mkdir -p $(dirname $CONFIG_DEST)

# Copy the Python script to the destination
cp $SCRIPT_NAME $SCRIPT_DEST

# Set ownership and executable permissions
chown root:root $SCRIPT_DEST
chmod 755 $SCRIPT_DEST

# Copy the configuration file to the destination
cp $CONFIG_FILE $CONFIG_DEST

# Set ownership and appropriate permissions for the config file
chown root:root $CONFIG_DEST
chmod 644 $CONFIG_DEST

# Copy the service and timer unit files to the systemd directory
cp $SERVICE_FILE $SYSTEMD_PATH
cp $TIMER_FILE $SYSTEMD_PATH
#cp $TEST_SERVICE_FILE $SYSTEMD_PATH
#cp $TEST_TIMER_FILE $SYSTEMD_PATH

# Set ownership for service and timer unit files
chown root:root $SYSTEMD_PATH/$SERVICE_FILE
chown root:root $SYSTEMD_PATH/$TIMER_FILE
#chown root:root $SYSTEMD_PATH/$TEST_SERVICE_FILE
#chown root:root $SYSTEMD_PATH/$TEST_TIMER_FILE

# Reload systemd to recognize the new unit files
systemctl daemon-reload

# Enable and start the timers
systemctl enable $TIMER_FILE
systemctl start $TIMER_FILE
#systemctl enable $TEST_TIMER_FILE
#systemctl start $TEST_TIMER_FILE

echo "Installation complete. The script and configuration file have been installed, and the timers have been set up."

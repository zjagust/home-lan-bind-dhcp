#!/usr/bin/env bash

#######################################################################################################
#
# Home Network - Bind9 and DHCP Setup
# Version: 1.0
#
# This script will install Bind9 system and set it as a forwarding DNS. It will also install a DHCP
# server with automatic DNS zone update.
#
# © 2024 Zack's. All rights reserved.
#
#######################################################################################################

###########################
## SET COLOR & SEPARATOR ##
###########################
declare -gr SPACER='----------------------------------------------------------------------------------------------------'
declare -gr E=$'\e[0;31m'			# (E) Error: highlighted text.
#declare -gr W=$'\e[1;33m'			# (W) Warning: highlighted text.
declare -gr I=$'\e[0;32m'			# (I) Info: highlighted text.
declare -gr B=$'\e[1m'				# B for Bold.
declare -gr R=$'\e[0m'				# R for Reset.

###############################
## CHECK ELEVATED PRIVILEGES ##
###############################
if [[ "$(whoami)" != "root" ]]
	then
		echo
		echo "${E}Script must be run with root privileges! Execution will abort now, please run script again as root user (or use sudo).${R}"
		echo
		exit 1
	fi

#######################
## INITIAL VARIABLES ##
#######################
HOST_GATEWAY=$(ip route get "$(ip route show 0.0.0.0/0 | grep -oP 'via \K\S+')" | grep -oP 'src \K\S+')
IPV4_FORWARDING=$(cat /proc/sys/net/ipv4/ip_forward)
SYSCTL_CONFIG="/etc/sysctl.conf"
ETH1_CHECK=$(find /sys/class/net/ -name "eth1" -printf "%f\n")
IF_CONFIGSDIR="/etc/network/interfaces.d"
BIND9_WORKDIR="/etc/bind"
HOSTNAME=$(hostname)
REVERSE_NET=$(printf %s "$2." | tac -s.)
DHCP_WORKDIR="/etc/dhcp"

####################
## SCRIPT OPTIONS ##
####################
function setOptions () {

  # List Options
	cat <<-END
		${SPACER}
		${B}${I}DNS/DHCP SERVER INSTALL SCRIPT${R}
		${I}This script has multiple options.${R}
		${SPACER}
		The following options are available:
		 ${B}-h:${R} Print this help message
		 ${B}-i:${R} Install DNS and DHCP servies
		   -> (usage: $0 [-i] NETWORK FQDN 
		   ->  NETWORK EXAMPLE: 192.168.100
		   ->  FQDN EXAMPLE: home.lan)
		${SPACER}
	END
}

###################
## SYSTEM CHECKS ##
###################
function systemCheck () {

    # IPV4 FORWARDING
    echo "${SPACER}"
    echo "${B}Checking if IPv4 forwarding is enabled:${R}"
    echo "${SPACER}"
    if [[ "$IPV4_FORWARDING" == "1" ]];
    then
        echo "${I}[PASSED]${R}${B} .... IPv4 forwarding is enabled.${R}"
        echo "${SPACER}"
        sleep 1
    else
        echo "${E}[FAILED]${R}${B} .... IPv4 forwarding is disabled. Will enable now.${R}"
        # Enable IPv4 Forwarding
        sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" $SYSCTL_CONFIG
        sysctl -p > /dev/null
        echo "${I}[INFO]${R}${B} .... IPv4 forwarding is now enabled.${R}"
        echo "${SPACER}"
        sleep 1
    fi

    # ETH1 INTERFACE CHECK
    echo "${SPACER}"
    echo "${B}Checking if eth1 interface is present:${R}"
    echo "${SPACER}"
    if [[ "$ETH1_CHECK" == "eth1" ]];
    then
        echo "${I}[PASSED]${R}${B} .... Interface eth1 is present.${R}"
        echo "${SPACER}"
        sleep 1
    else
        echo "${E}[FAILED]${R}${B} .... There is no eth1 interface on this machine. Aborting now!${R}"
        echo "${SPACER}"
        exit 1
    fi

    # ETH1 STATUS
    echo "${SPACER}"
    echo "${B}Checking if eth1 interface is DOWN:${R}"
    echo "${SPACER}"
    # Define check variable here, since it depends on "$ETH1_CHECK"
    ETH1_STATUS=$(ip link show eth1 | grep -o DOWN)
    if [[ "$ETH1_STATUS" == "DOWN" ]];
    then
        echo "${I}[PASSED]${R}${B} .... Interface eth1 is DOWN.${R}"
        echo "${SPACER}"
        sleep 1
    else
        echo "${E}[FAILED]${R}${B} .... Interface eth1 not DOWN. Aborting now!${R}"
        echo "${SPACER}"
        exit 1
    fi

}

################
## ETH1 SETUP ##
################
function eth1Setup () {

    # Get the config file from the GitHub
    curl -Sso "$IF_CONFIGSDIR"/if-eth1 \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/if-eth1

    # Set the network (RFC1918)
    sed -i "s/NETWORK/$2/g" "$IF_CONFIGSDIR"/if-eth1
    sed -i "s/FQDN/$3/g" "$IF_CONFIGSDIR"/if-eth1

}

#################
## BIND9 SETUP ##
#################
function bind9Setup () {

    # Install required packages and stop the service
    DEBIAN_FRONTEND=noninteractive apt install -y bind9
    systemctl stop named.service

    # Enable only on IPv4
    sed -i "s/OPTIONS=\"-u bind\"/OPTIONS=\"-u bind -4\"/g" /etc/default/named

    # Create a zone signing key
    tsig-keygen -a HMAC-SHA512 "$3" > "$BIND9_WORKDIR"/ns-"$3"_rndc.key

    # Set the main named.conf configuration
    mv "$BIND9_WORKDIR"/named.conf "$BIND9_WORKDIR"/named.conf.dist
    curl -Sso "$BIND9_WORKDIR"/named.conf \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/named.conf

    # Populate named.conf with the correct values
    sed -i "s/NETWORK/$2/g" "$BIND9_WORKDIR"/named.conf
    sed -i "s/FQDN/$3/g" "$BIND9_WORKDIR"/named.conf

    # Set the named.conf.local configuration
    mv "$BIND9_WORKDIR"/named.conf.local "$BIND9_WORKDIR"/named.conf.local.dist
    curl -Sso "$BIND9_WORKDIR"/named.conf.local \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/named.conf.local

    # Populate named.conf.local with the correct values
    sed -i "s/REVERSE_NET/$REVERSE_NET/g" "$BIND9_WORKDIR"/named.conf.local
    sed -i "s/FQDN/$3/g" "$BIND9_WORKDIR"/named.conf.local

    # Set logging
    curl -Sso "$BIND9_WORKDIR"/named.conf.log \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/named.conf.log

    # Create log files
    touch /var/log/{update_debug.log,security_info.log,bind.log}
    chown bind:bind /var/log/{update_debug.log,security_info.log,bind.log}

    # Set the named.conf.options configuration
    mv "$BIND9_WORKDIR"/named.conf.options "$BIND9_WORKDIR"/named.conf.options.dist
    curl -Sso "$BIND9_WORKDIR"/named.conf.options \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/named.conf.options

    # Populate named.conf.options with the correct values
    sed -i "s/NETWORK/$2/g" "$BIND9_WORKDIR"/named.conf.options

    # Set a forward zone
    curl -Sso "$BIND9_WORKDIR"/db."$3" \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/zone.fwd

    # Populate forward zone with the correct values
    sed -i "s/FQDN/$3/g" "$BIND9_WORKDIR"/db."$3"
    sed -i "s/NETWORK/$2/g" "$BIND9_WORKDIR"/db."$3"
    sed -i "s/HOSTNAME/$HOSTNAME/g" "$BIND9_WORKDIR"/db."$3"

    # Set a reverse zone
    curl -Sso "$BIND9_WORKDIR"/db."$REVERSE_NET"in-addr.arpa \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/named-configs/zone.fwd

    # Populate reverse zone with the correct values
    sed -i "s/REVERSE_NET/$REVERSE_NET/g" "$BIND9_WORKDIR"/db."$REVERSE_NET"in-addr.arpa
    sed -i "s/FQDN/$3/g" "$BIND9_WORKDIR"/db."$REVERSE_NET"in-addr.arpa
    sed -i "s/HOSTNAME/$HOSTNAME/g" "$BIND9_WORKDIR"/db."$REVERSE_NET"in-addr.arpa

    # Create symlinks in Bind cache directory
    ln -sf "$BIND9_WORKDIR"/db."$3" /var/cache/bind/db."$3"
    ln -sf "$BIND9_WORKDIR"/db."$REVERSE_NET"in-addr.arpa /var/cache/bind/db."$REVERSE_NET"in-addr.arpa

}

#################
## DHCP SETUP ##
#################
function dhcpSetup () {

    # Install required packages and stop the service
    DEBIAN_FRONTEND=noninteractive apt install -y isc-dhcp-server
    systemctl stop isc-dhcp-server.service

    # Enable only on eth1
    sed -i "s/^INTERFACESv4=\"\"/INTERFACESv4=\"eth1\"/g" /etc/default/isc-dhcp-server

    # Create signing key symlink
    ln -sf "$BIND9_WORKDIR"/ns-"$3"_rndc.key "$DHCP_WORKDIR"/ns-"$3"_rndc.key

    # Set the dhcp main config dhcpd.conf
    mv "$DHCP_WORKDIR"/dhcpd.conf "$DHCP_WORKDIR"/dhcpd.conf.dist
    curl -Sso "$DHCP_WORKDIR"/dhcpd.conf \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/dhcp-configs/dhcpd.conf

    # Populate dhcp config with the correct values
    sed -i "s/FQDN/$3/g" "$DHCP_WORKDIR"/dhcpd.conf
    sed -i "s/HOSTNAME/$HOSTNAME/g" "$DHCP_WORKDIR"/dhcpd.conf
    sed -i "s/NETWORK/$2/g" "$DHCP_WORKDIR"/dhcpd.conf
    sed -i "s/REVERSE_NET/$REVERSE_NET/g" "$DHCP_WORKDIR"/dhcpd.conf

}

##############
## FIREWALL ##
##############
function fwSetup () {

    # Flush everything
    #iptables -t nat -F
    #iptables -t mangle -F
    #iptables -F
    #iptables -X

    # Backup old rules
    #mv /etc/iptables/rules.v4 /etc/iptables/rules.v4.bkp

    # Download new rules
    curl -Sso /etc/iptables/rules.v4 \
    https://raw.githubusercontent.com/zjagust/home-lan-bind-dhcp/main/firewall/rules.v4

    # Populate firewall with the correct values
    sed -i "s/NETWORK/$2/g" /etc/iptables/rules.v4
    sed -i "s/HOST_GATEWAY/$HOST_GATEWAY/g" /etc/iptables/rules.v4

    # Set new rules
    iptables-restore < /etc/iptables/rules.v4

}

#############
## NETWORK ##
#############
function networkRestart () {

    # Disable dns-nameservers on eth0
    sed -i "s/\tdns-nameservers/\t#dns-nameservers/g" /etc/network/interfaces

    # Restart networking
    systemctl restart networking.service

}

#####################
## ENABLE SERVICES ##
#####################
function serviceEnable () {

    # Start Bind9 service
    systemctl start named.service
    sleep 5

    # Start DHCP service
    systemctl start isc-dhcp-server.service

}

#################
## GET OPTIONS ##
#################

# No parameters
if [ $# -eq 0 ]; then
	setOptions
	exit 1
fi

# Execute
while getopts ":hi" option; do
	case $option in
		h) # Display help
			setOptions
			exit
			;;
		i) # Install services
			systemCheck
			eth1Setup "$@"
            bind9Setup "$@"
            dhcpSetup "$@"
            fwSetup "$@"
            networkRestart
            serviceEnable
			exit
			;;
		\?) # Invalid options
			echo "Invalid option, will exit now."
			exit
			;;
	esac
done
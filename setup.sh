#!/bin/bash


# For function returns.
RESULT=


function checkForGit() {
	URL=$1
	FOLDER=$2
	
	if [ ! -d ${BASE}/${FOLDER} ]; then
		echo " - Installing ${FOLDER}"
		git clone ${URL}/${FOLDER}.git ${BASE}/${FOLDER} >> ${LOG} 2>&1
		if [ "$?x" != "0x" ]; then
			echo
			echo "!! Something bad happened while trying to install ${FOLDER}.  Exiting."
			echo
			exit 1
		fi
	fi
}


function checkForPackages() {

	for P in "$@"; do
		dpkg-query -s ${P} 2> /dev/null | grep -q ^"Status: install ok installed"$
		if [ "$?x" == "1x" ]; then
			if [ "${FIRSTPACKAGE}" == "1" ]; then
				echo " - One moment while we install some missing system packages..."
				echo "   - Updating package database"
				apt-get -y update >> ${LOG} 2>&1
				FIRSTPACKAGE=0
			fi
			echo "   - Installing package ${P}"
			apt-get -y install ${P} >> ${LOG} 2>&1
			if [ "$?x" != "0x" ]; then
				echo
				echo "!! Something bad happened while trying to install ${P}.  Exiting."
				echo
				exit 1
			fi
		fi
	done

}


function findPath() {
	local SOURCE=$1
	local DIR=
	while [ -h "${SOURCE}" ]; do
		DIR="$( cd -P "$( dirname "${SOURCE}" )" && pwd )"
		SOURCE="$(readlink "${SOURCE}")"
		# If $SOURCE was a relative symlink, we need to resolve it
		# relative to the path where the symlink file was located.
		[[ ${SOURCE} != /* ]] && SOURCE="${DIR}/${SOURCE}"
	done
	RESULT="$( cd -P "$( dirname "${SOURCE}" )" && pwd )"
}


function htpcDB() {
	DB="$1"
	KEY="$2"
	VAL="$3"
	SQL="INSERT INTO setting (key, val) VALUES ('${KEY}', '${VAL}');"
	sqlite3 ${DB} "${SQL}"
}


function iniSet() {
	FILE="$1"
	KEY="$2"
	VAL="$3"
	sed -i "s#^${KEY} =.*#${KEY} = $(printf '%q' ${VAL})#g" ${FILE}
}


# Ports:
#   8080 - HTPC Manager Web UI
#   8081 - SickRage Web UI
#   8082 - Couch Potato Web UI
#   8083 - Transmission Web UI
#  51413 - Transmission Inbound Port


# Some common values.
RELEASE=1
BASE=/opt/htpc
TITLE="HTPC Automated Installer  (Release ${RELEASE})"
SCRIPT=$0
NAME=`basename ${0%.*}`
findPath "${BASH_SOURCE[0]}" ; SCRIPTDIR="${RESULT}"
LOG=${SCRIPTDIR}/${NAME}.log
FIRSTPACKAGE=1
PORT=1194


# Clear the log.
echo > ${LOG}


echo
echo "Welcome to the ${TITLE}"
echo


if [[ $EUID -ne 0 ]]; then
	echo "!! The installer must be run using sudo."
	echo
	exit 1
fi


# For setup script
checkForPackages git python2.7 python-pip

# For OpenVPN
checkForPackages openvpn

# For Transmission
checkForPackages transmission-daemon

# For SickRage
checkForPackages unrar

# For CouchPotato

# For HTPC Manager
checkForPackages smartmontools sqlite libffi-dev libssl-dev


echo " - Performing initial installation"
mkdir -p ${BASE}/{mnt,pip,scripts,data}
mkdir -p ${BASE}/pip/_cache
echo ${RELEASE} > ${BASE}/release
PIP=${BASE}/pip
pip install pip --cache-dir ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1


# === OpenVPN ===
echo " - Configuring OpenVPN"
COUNT=0
VPN=
for F in *.ovpn; do
	if [ -e "${F}" ]; then
		((COUNT++))
		VPN="$F"
	fi
done
if [ ${COUNT} -eq 0 ]; then
	echo
	echo "!! Unable to locate your *.ovpn file in the current directory."
	echo
	exit 1
fi
if [ ${COUNT} -ne 1 ]; then
	echo
	echo "!! There is more than one *.ovpn file in the current directory."
	echo
	exit 1
fi
# Read our config and make a list of all the files we need to copy to make this ovpn work.
FILEOPTS=(askpass auth-user-pass ca cert config dh key pkcs12 secret)
COPYLIST=()
while IFS='' read -r LINE || [ -n "${LINE}" ]; do
	TOKENS=(${LINE})
	if [ "${TOKENS[0]}" == "remote" ]; then
		PORT="${TOKENS[2]}"
	fi
	for F in ${FILEOPTS[@]}; do
		if [ "${F}" == "${TOKENS[0]}" ]; then
			if [ ! -z "${TOKENS[1]##*/*}" ]; then
				VAR="${TOKENS[1]}"
				VAR="${VAR#"${VAR%%[![:space:]]*}"}"
				VAR="${VAR%"${VAR##*[![:space:]]}"}"
				COPYLIST+=("${VAR}")
			fi
		fi
	done
done < ${VPN}
DATA=${BASE}/data/openvpn
mkdir -p ${DATA}
cp -f "${VPN}" ${DATA}/.
for F in ${COPYLIST[@]}; do
	cp -f "${F}" ${DATA}/.
done
# Startup and shutdown scripts.
cat<<-STARTOVPN > ${BASE}/scripts/start-openvpn.sh
	#!/bin/bash
	cd ${DATA}
	openvpn --config "${VPN}" --daemon --writepid openvpn.pid --log-append openvpn.log
STARTOVPN
chmod +x ${BASE}/scripts/start-openvpn.sh
cat<<-STOPOVPN > ${BASE}/scripts/stop-openvpn.sh
	#!/bin/bash
	kill \$(cat ${DATA}/openvpn.pid)
	rm ${DATA}/openvpn.pid
STOPOVPN
chmod +x ${BASE}/scripts/stop-openvpn.sh


# === Transmission ===
echo " - Configuring Transmission"
mkdir -p ${BASE}/mnt/Torrents/{Complete,Incomplete,Watch}
DATA=${BASE}/data/transmission
mkdir -p ${DATA}
# Startup and shutdown scripts.
cat<<-STARTTRANSMISSION > ${BASE}/scripts/start-transmission.sh
	#!/bin/bash
	transmission-daemon --config-dir ${DATA} --allowed "192.168.*,127.0.*" -c ${BASE}/mnt/Torrents/Watch --encryption-preferred --global-seedratio 0.0 --incomplete-dir ${BASE}/mnt/Torrents/Incomplete --dht --port 8083 --no-auth --utp --download-dir ${BASE}/mnt/Torrents/Complete --logfile ${DATA}/transmission.log --log-debug --no-portmap
	sleep 2
	ps -C transmission-daemon | tail -n 1 | awk '{print \$1}' > ${DATA}/transmission.pid
STARTTRANSMISSION
chmod +x ${BASE}/scripts/start-transmission.sh
cat<<-STOPTRANSMISSION > ${BASE}/scripts/stop-transmission.sh
	#!/bin/bash
	kill \$(cat ${DATA}/transmission.pid)
	rm ${DATA}/transmission.pid
STOPTRANSMISSION
chmod +x ${BASE}/scripts/stop-transmission.sh
# Start and stop the service to create the settings file if it doesn't exist.
CFG=${DATA}/settings.json
if [ ! -e ${CFG} ]; then
	${BASE}/scripts/start-transmission.sh >> ${LOG} 2>&1
	# No pause needed, start script does it for us.
	${BASE}/scripts/stop-transmission.sh >> ${LOG} 2>&1
	sleep 1
	sed -i 's/"lpd-enabled": false/"lpd-enabled": true/g' ${CFG}
	sed -i 's/"speed-limit-up": 100/"speed-limit-up": 200/g' ${CFG}
	sed -i 's/"speed-limit-up-enabled": false/"speed-limit-up-enabled": true/g' ${CFG}
fi


# === SickRage ===
checkForGit https://github.com/SickRage SickRage
DATA=${BASE}/data/SickRage
mkdir -p ${DATA}
mkdir -p ${BASE}/mnt/Shows
# Startup and shutdown scripts.
cat<<-STARTSICKRAGE > ${BASE}/scripts/start-SickRage.sh
	#!/bin/bash
	cd ${BASE}/SickRage
	python SickBeard.py --nolaunch --daemon --pidfile ${DATA}/SickRage.pid --port 8081 --datadir ${DATA} 
STARTSICKRAGE
chmod +x ${BASE}/scripts/start-SickRage.sh
cat<<-STOPSICKRAGE > ${BASE}/scripts/stop-SickRage.sh
	#!/bin/bash
	kill \$(cat ${DATA}/SickRage.pid)
STOPSICKRAGE
chmod +x ${BASE}/scripts/stop-SickRage.sh
# Start and stop the service to create the config file if it doesn't exist.
CFG=${DATA}/config.ini
if [ ! -e ${CFG} ]; then
	${BASE}/scripts/start-SickRage.sh >> ${LOG} 2>&1
	sleep 2
	${BASE}/scripts/stop-SickRage.sh >> ${LOG} 2>&1
	sleep 1
	iniSet ${CFG} rarbg 1
	iniSet ${CFG} torrentz 1
	iniSet ${CFG} elitetorrent 1
	iniSet ${CFG} bitsnoop 1
	iniSet ${CFG} nyaatorrents 1
	iniSet ${CFG} btdigg 1
	iniSet ${CFG} cpasbien 1
	iniSet ${CFG} newpct 1
	iniSet ${CFG} tokyotoshokan 1
	iniSet ${CFG} limetorrents 1
	iniSet ${CFG} torrent_host "http://localhost:8083"
	iniSet ${CFG} torrent_path "/opt/htpc/mnt/Torrents/Complete"
	iniSet ${CFG} torrent_auth_type none
	iniSet ${CFG} torrent_username transmission
	iniSet ${CFG} torrent_password transmission
	iniSet ${CFG} dailysearch_frequency 10
	iniSet ${CFG} api_key 95ef1b0d35d02068c9224e90b20cbf58
	iniSet ${CFG} check_propers_interval 15m
	iniSet ${CFG} update_frequency 24
	iniSet ${CFG} process_method move
	iniSet ${CFG} tv_download_dir "/opt/htpc/mnt/Torrents/Complete"
	iniSet ${CFG} naming_custom_abd 1
	iniSet ${CFG} create_missing_show_dirs 1
	iniSet ${CFG} cur_commit_branch master
	iniSet ${CFG} root_dirs "0|/opt/htpc/mnt/Shows"
	iniSet ${CFG} naming_pattern "Season %0S/%SN - %0Sx%0E - %EN"
	iniSet ${CFG} metadata_kodi "1|1|1|1|1|1|1|1|1|1"
	iniSet ${CFG} naming_custom_sports 1
	iniSet ${CFG} randomize_providers 1
	iniSet ${CFG} process_automatically 1
	iniSet ${CFG} launch_browser 0
	iniSet ${CFG} branch master
	iniSet ${CFG} unpack 1
	iniSet ${CFG} move_associated_files 1
	iniSet ${CFG} naming_multi_ep 16
	iniSet ${CFG} torrent_method transmission
	iniSet ${CFG} proxy_indexers 0
	iniSet ${CFG} keep_processed_dir 0
	iniSet ${CFG} subtitles_history 1
	iniSet ${CFG} subtitles_hearing_impaired 1
	iniSet ${CFG} subtitles_languages eng
	iniSet ${CFG} SUBTITLES_SERVICES_LIST "\"addic7ed,legendastv,opensubtitles,podnapisi,shooter,subscenter,thesubdb,tvsubtitles,itasa\""
	iniSet ${CFG} use_subtitles 1
	iniSet ${CFG} SUBTITLES_SERVICES_ENABLED "0|0|0|1|1|1|1|1|0"
fi


# === Couch Potato ===


# === HTPC Manager ===
checkForGit https://github.com/Hellowlol HTPC-Manager
PYTHONPATH="${PIP}" pip install -r ${BASE}/HTPC-Manager/requirements.txt --cache-dir ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1
DATA=${BASE}/data/HTPC-Manager
mkdir -p ${DATA}
# Startup and shutdown scripts.
cat<<-STARTHTPC > ${BASE}/scripts/start-HTPC-Manager.sh
	#!/bin/bash
	cd ${BASE}/HTPC-Manager
	PYTHONPATH="${PIP}" python Htpc.py --daemon --datadir ${DATA} --pid ${DATA}/HTPC-Manager.pid
STARTHTPC
chmod +x ${BASE}/scripts/start-HTPC-Manager.sh
cat<<-STOPHTPC > ${BASE}/scripts/stop-HTPC-Manager.sh
	#!/bin/bash
	kill \$(cat ${DATA}/HTPC-Manager.pid)
STOPHTPC
chmod +x ${BASE}/scripts/stop-HTPC-Manager.sh
# Start and stop the service to create the settings database if it doesn't exist.
if [ ! -e ${DATA}/database.db ]; then
	${BASE}/scripts/start-HTPC-Manager.sh >> ${LOG} 2>&1
	sleep 2
	${BASE}/scripts/stop-HTPC-Manager.sh >> ${LOG} 2>&1
	sleep 1
	DB=${DATA}/database.db
	htpcDB ${DB} "app_port" "8080"
	htpcDB ${DB} "app_check_for_updates" "on"
	htpcDB ${DB} "git_cleanup" "on"
	htpcDB ${DB} "dash_sysinfo" "on"
	htpcDB ${DB} "dash_couchpotato" "on"
	htpcDB ${DB} "dash_sickrage" "on"
	htpcDB ${DB} "stats_use_bars" "on"
	htpcDB ${DB} "stats_psutil_enabled" "on"
	htpcDB ${DB} "stats_enable" "on"
	htpcDB ${DB} "stats_name" "System"
	htpcDB ${DB} "stats_filesystem" "cgroup tmpfs fusectl fuse.lxcfs fuse.gvfsd-fuse"
	htpcDB ${DB} "transmission_enable" "on"
	htpcDB ${DB} "transmission_name" "Transmission"
	htpcDB ${DB} "transmission_password" "transmission"
	htpcDB ${DB} "transmission_rpcbasepath" "/transmission/"
	htpcDB ${DB} "transmission_port" "8083"
	htpcDB ${DB} "transmission_host" "localhost"
	htpcDB ${DB} "transmission_username" "transmission"
	htpcDB ${DB} "sickrage_basepath" "/"
	htpcDB ${DB} "sickrage_port" "8081"
	htpcDB ${DB} "sickrage_host" "localhost"
	htpcDB ${DB} "sickrage_enable" "on"
	htpcDB ${DB} "sickrage_name" "SickRage"
	htpcDB ${DB} "sickrage_apikey" "95ef1b0d35d02068c9224e90b20cbf58"
fi


# === Main start and stop scripts ===
cat<<-STARTALL > ${BASE}/start.sh
	#!/bin/bash
	cd ${BASE}
	# Clear existing IPv4 firewall rules.
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -F
	iptables -X
	iptables -t raw -F
	iptables -t raw -X
	iptables -t nat -F
	iptables -t nat -X
	iptables -t mangle -F
	iptables -t mangle -X
	# Clear existing IPv6 firewall rules.
	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -F
	ip6tables -X
	ip6tables -t raw -F
	ip6tables -t raw -X
	ip6tables -t nat -F
	ip6tables -t nat -X
	ip6tables -t mangle -F
	ip6tables -t mangle -X
	# Allow loopback device IPv4 (internal communication).
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	# Allow loopback device IPv6 (internal communication).
	ip6tables -A INPUT -i lo -j ACCEPT
	ip6tables -A OUTPUT -o lo -j ACCEPT
	# Allow communications with IPv4 DHCP server.
	iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT
	iptables -A INPUT -s 255.255.255.255 -j ACCEPT
	# Allow all local IPv4 traffic.
	iptables -A INPUT -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT
	iptables -A OUTPUT -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT
	iptables -A INPUT -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT
	iptables -A OUTPUT -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT
	iptables -A INPUT -s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT
	iptables -A OUTPUT -s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT
	# Allow established sessions to receive traffic on IPv4.	
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	# Allow VPN establishment IPv4.
	iptables -A OUTPUT -p udp --dport ${PORT} -j ACCEPT
	iptables -A INPUT -p udp --sport ${PORT} -j ACCEPT
	# Accept all outbound TUN connections and firewalled input on IPv4 (tun = VPN tunnel).
	iptables -A OUTPUT -o tun+ -j ACCEPT
	iptables -A FORWARD -i tun+ -j ACCEPT
	iptables -A INPUT -i tun+ -p udp --dport 51413 -j ACCEPT
	iptables -A INPUT -i tun+ -p tcp --dport 51413 -j ACCEPT
	# Accept all outbound TUN connections and firewalled input on IPv6 (tun = VPN tunnel).
	ip6tables -A OUTPUT -o tun+ -j ACCEPT
	ip6tables -A FORWARD -i tun+ -j ACCEPT
	ip6tables -A INPUT -i tun+ -p udp --dport 51413 -j ACCEPT
	ip6tables -A INPUT -i tun+ -p tcp --dport 51413 -j ACCEPT
	# Set default policies to drop all communication unless specifically allowed on IPv4.
	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP
	# Set default policies to drop all communication unless specifically allowed on IPv6.
	ip6tables -P INPUT DROP
	ip6tables -P OUTPUT DROP
	ip6tables -P FORWARD DROP
	# Start all services.
	for F in \$(ls -1 scripts/start-*.sh); do
		./\${F} > /dev/null 2>&1
	done
STARTALL
chmod +x ${BASE}/start.sh
cat<<-STOPALL > ${BASE}/stop.sh
	#!/bin/bash
	cd ${BASE}
	# Stop all services.
	for F in \$(ls -1 scripts/stop-*.sh); do
		./\${F} > /dev/null 2>&1
	done
	# Clear existing IPv4 firewall rules.
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -F
	iptables -X
	iptables -t raw -F
	iptables -t raw -X
	iptables -t nat -F
	iptables -t nat -X
	iptables -t mangle -F
	iptables -t mangle -X
	# Clear existing IPv6 firewall rules.
	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -F
	ip6tables -X
	ip6tables -t raw -F
	ip6tables -t raw -X
	ip6tables -t nat -F
	ip6tables -t nat -X
	ip6tables -t mangle -F
	ip6tables -t mangle -X
STOPALL
chmod +x ${BASE}/stop.sh


echo
echo Finished!
echo
echo   You can now access your system at http://127.0.0.1:8080
echo

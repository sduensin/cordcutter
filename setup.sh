#!/bin/bash


:<<MIT


The MIT License (MIT)

Copyright (c) 2016 Scott Duensing

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.


MIT


# For function returns.
RESULT=


function checkForGit() {
	URL=$1
	FOLDER=$2
	
	echo " - Installing ${FOLDER}"
	if [ ! -d ${BASE}/${FOLDER} ]; then
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


# Ports:
#   8080 - HTPC Manager Web UI
#   8081 - SickRage Web UI
#   8082 - Couch Potato Web UI
#   8083 - Transmission Web UI
#   8084 - Monit Web UI
#   8888 - PyWebDAV Server
#  51413 - Transmission Inbound Port


# Some common values.
RELEASE=1
BASE=/opt/cordcutter
TITLE="Cord Cutter  (Release ${RELEASE})"
SCRIPT=$0
NAME=`basename ${0%.*}`
findPath "${BASH_SOURCE[0]}" ; SCRIPTDIR="${RESULT}"
LOG=${SCRIPTDIR}/${NAME}.log
FIRSTPACKAGE=1
PORT=1194


# Find our internal IP.
INTERNAL="127.0.0.1"
for IP in $(hostname -I); do
	if [[ ${IP} =~ (^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.) ]]; then
		INTERNAL="${IP}"
	fi
done


# Clear the log.
echo > ${LOG}


echo
echo "Welcome to ${TITLE}"
echo


if [[ $EUID -ne 0 ]]; then
	echo "!! The installer must be run as root."
	echo
	exit 1
fi

PIDLIST=(CouchPotatoServer HTPC-Manager PyWebDAV SickRage OpenVPN Transmission Monit)
for F in ${PIDLIST[@]}; do
	if [ -e ${BASE}/data/${F}/${F}.pid ]; then
		echo "!! Do not run the installer while any servers are running.  (Found ${F}.)"
		echo
		exit 1
	fi
done


# For setup script
checkForPackages git python2.7 python2.7-dev python-pip

# For OpenVPN
checkForPackages openvpn

# For Transmission
checkForPackages transmission-daemon

# For SickRage
checkForPackages unrar

# For CouchPotato
checkForPackages libxml2-dev libxslt1-dev

# For HTPC Manager
checkForPackages smartmontools sqlite libffi-dev libssl-dev

# For MonIt
checkForPackages monit


echo " - Performing initial installation"
mkdir -p ${BASE}/{scripts,data}
mkdir -p ${BASE}/pip/_cache
MNT=${BASE}/data/mnt
mkdir -p ${MNT}
echo ${RELEASE} > ${BASE}/data/release
# Install our own copy of pip using the distro packaged pip.
PIP=${BASE}/pip
if [ ! -d ${PIP}/pip ]; then
	CACHE="--cache-dir"
	pip install --help | grep -q "\--download-cache"
	WHICHPIP=$?
	if [ "x${WHICHPIP}" == "x0" ]; then
		CACHE="--download-cache"
	fi
	pip install pip ${CACHE} ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1
fi


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
DATA=${BASE}/data/OpenVPN
mkdir -p ${DATA}
cp -f "${VPN}" ${DATA}/.
for F in ${COPYLIST[@]}; do
	cp -f "${F}" ${DATA}/.
done
# Startup and shutdown scripts.
cat<<-STARTOVPN > ${BASE}/scripts/start-OpenVPN.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/OpenVPN.pid ]; then rm ${DATA}/OpenVPN.pid; fi; fi
	cd ${DATA}
	openvpn --config "${VPN}" --daemon --writepid OpenVPN.pid --log-append OpenVPN.log
STARTOVPN
chmod +x ${BASE}/scripts/start-OpenVPN.sh
cat<<-STOPOVPN > ${BASE}/scripts/stop-OpenVPN.sh
	#!/bin/bash
	kill \$(cat ${DATA}/OpenVPN.pid)
	rm ${DATA}/OpenVPN.pid
STOPOVPN
chmod +x ${BASE}/scripts/stop-OpenVPN.sh


# === Transmission ===
echo " - Configuring Transmission"
update-rc.d -f transmission-daemon remove >> ${LOG} 2>&1
killall transmission-daemon >> ${LOG} 2>&1
mkdir -p ${MNT}/Torrents/{Complete,Incomplete,Watch}
DATA=${BASE}/data/Transmission
mkdir -p ${DATA}
# Startup and shutdown scripts.
cat<<-STARTTRANSMISSION > ${BASE}/scripts/start-Transmission.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/Transmission.pid ]; then rm ${DATA}/Transmission.pid; fi; fi
	transmission-daemon --config-dir ${DATA} --allowed "192.168.*,127.0.*" -c ${MNT}/Torrents/Watch --encryption-preferred --global-seedratio 0.0 --incomplete-dir ${MNT}/Torrents/Incomplete --dht --port 8083 --no-auth --utp --download-dir ${MNT}/Torrents/Complete --logfile ${DATA}/Transmission.log --log-info --no-portmap
	sleep 2
	ps -C transmission-daemon | tail -n 1 | awk '{print \$1}' > ${DATA}/Transmission.pid
STARTTRANSMISSION
chmod +x ${BASE}/scripts/start-Transmission.sh
cat<<-STOPTRANSMISSION > ${BASE}/scripts/stop-Transmission.sh
	#!/bin/bash
	kill \$(cat ${DATA}/Transmission.pid)
	rm ${DATA}/Transmission.pid
STOPTRANSMISSION
chmod +x ${BASE}/scripts/stop-Transmission.sh
# Prime the settings file if it doesn't exist.
CFG=${DATA}/settings.json
if [ ! -e ${CFG} ]; then
	cat<<-TRANSMISSIONSETTINGS > ${CFG}
		{
		"lpd-enabled": true,
		"speed-limit-up": 200,
		"speed-limit-up-enabled": true
		}
	TRANSMISSIONSETTINGS
fi


# === SickRage ===
checkForGit https://github.com/SickRage SickRage
DATA=${BASE}/data/SickRage
mkdir -p ${DATA}
mkdir -p ${MNT}/Shows
# Startup and shutdown scripts.
cat<<-STARTSICKRAGE > ${BASE}/scripts/start-SickRage.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/SickRage.pid ]; then rm ${DATA}/SickRage.pid; fi; fi
	cd ${BASE}/SickRage
	python SickBeard.py --nolaunch --daemon --pidfile ${DATA}/SickRage.pid --port 8081 --datadir ${DATA} 
STARTSICKRAGE
chmod +x ${BASE}/scripts/start-SickRage.sh
cat<<-STOPSICKRAGE > ${BASE}/scripts/stop-SickRage.sh
	#!/bin/bash
	kill \$(cat ${DATA}/SickRage.pid)
STOPSICKRAGE
chmod +x ${BASE}/scripts/stop-SickRage.sh
# Is our processing script in place?
if [ ! -e ${DATA}/process.sh ]; then
	cat<<-PROCESS > ${DATA}/process.sh
		#!/bin/bash
		FOLDER=\$(dirname "\$2")
		FILE=\$(basename "\${FOLDER}")
		TORRENTID="\$(transmission-remote localhost:8083 -l | grep -F \${FILE} | awk '{print \$1}')" 
		if [[ ! -z \${TORRENTID} ]]; then
			transmission-remote localhost:8083 -t \${TORRENTID} -r 
		fi 
	PROCESS
	chmod +x ${DATA}/process.sh
fi
# Prime the config file if it doesn't exist.
CFG=${DATA}/config.ini
if [ ! -e ${CFG} ]; then
	cat<<-SICKRAGESETTINGS > ${CFG}
		[RARBG]
		rarbg = 1
		[ELITETORRENT]
		elitetorrent = 1
		[BITSNOOP]
		bitsnoop = 1
		[NYAATORRENTS]
		nyaatorrents = 1
		[BTDIGG]
		btdigg = 1
		[NEWPCT]
		newpct = 1
		[THEPIRATEBAY]
		thepiratebay = 1
		[TOKYOTOSHOKAN]
		tokyotoshokan = 1
		[LIMETORRENTS]
		limetorrents = 1
		[TORRENT]
		torrent_host = http://localhost:8083
		torrent_path = ${MNT}/Torrents/Complete
		torrent_auth_type = none
		torrent_username = transmission
		torrent_password = transmission
		[General]
		dailysearch_frequency = 10
		api_key = 95ef1b0d35d02068c9224e90b20cbf58
		check_propers_interval = 15m
		update_frequency = 24
		process_method = move
		tv_download_dir = ${MNT}/Torrents/Complete
		naming_custom_abd = 1
		create_missing_show_dirs = 1
		cur_commit_branch = master
		root_dirs = 0|${MNT}/Shows
		naming_pattern = Season %0S/%SN - %0Sx%0E - %EN
		metadata_kodi = 1|1|1|1|1|1|1|1|1|1
		naming_custom_sports = 1
		randomize_providers = 1
		process_automatically = 1
		launch_browser = 0
		branch = master
		unpack = 1
		move_associated_files = 1
		naming_multi_ep = 16
		torrent_method = transmission
		proxy_indexers = 0
		keep_processed_dir = 0
		extra_scripts = ${DATA}/process.sh
		;handle_reverse_proxy = 1
		;web_root = "/tv"
		[Subtitles]
		subtitles_history = 1
		subtitles_hearing_impaired = 1
		subtitles_languages = eng
		SUBTITLES_SERVICES_LIST = "addic7ed,legendastv,opensubtitles,podnapisi,shooter,subscenter,thesubdb,tvsubtitles,itasa"
		use_subtitles = 1
		SUBTITLES_SERVICES_ENABLED = 0|0|0|1|1|1|1|1|0
	SICKRAGESETTINGS
fi


# === Couch Potato ===
checkForGit https://github.com/CouchPotato CouchPotatoServer
PYTHONPATH="${PIP}" python ${PIP}/pip install lxml --cache-dir ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1
DATA=${BASE}/data/CouchPotatoServer
mkdir -p ${DATA}
mkdir -p ${MNT}/Movies
# Startup and shutdown scripts.
cat<<-STARTCOUCHPOTATO > ${BASE}/scripts/start-CouchPotatoServer.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/CouchPotatoServer.pid ]; then rm ${DATA}/CouchPotatoServer.pid; fi; fi
	cd ${BASE}/CouchPotatoServer
	PYTHONPATH="${PIP}" python CouchPotato.py --daemon --pid_file ${DATA}/CouchPotatoServer.pid --data_dir ${DATA} 
STARTCOUCHPOTATO
chmod +x ${BASE}/scripts/start-CouchPotatoServer.sh
cat<<-STOPCOUCHPOTATO > ${BASE}/scripts/stop-CouchPotatoServer.sh
	#!/bin/bash
	kill \$(cat ${DATA}/CouchPotatoServer.pid)
STOPCOUCHPOTATO
chmod +x ${BASE}/scripts/stop-CouchPotatoServer.sh
# Prime the settings file if it doesn't exist.
CFG=${DATA}/settings.conf
if [ ! -e ${CFG} ]; then
	cat<<-COUCHPOTATOSETTINGS > ${CFG}
		[core]
		launch_browser = False
		port = 8082
		api_key = 5bf1b41b945d444ba9050e88869e6e64
		dark_theme = 1
		show_wizard = 0
		data_dir = ${DATA}
		[renamer]
		from = ${MNT}/Torrents/Complete/
		to = ${MNT}/Movies/
		cleanup = 1
		enabled = 1
		unrar = 1
		default_file_action = move
		file_action = move
		nfo_name = <filename>.<ext>-orig
		[subtitle]
		languages = en
		enabled = 1
		[blackhole]
		enabled = 0
		[transmission]
		username = transmission
		enabled = 1
		host = http://localhost:8083
		password = transmission
		[newznab]
		enabled = 0
		[kickasstorrents]
		seed_time = 0
		seed_ratio = 0
		[magnetdl]
		seed_time = 0
		enabled = 1
		seed_ratio = 0
		[rarbg]
		enabled = 1
		[thepiratebay]
		seed_time = 0
		enabled = 1
		seed_ratio = 0
		[torrentz]
		seed_time = 0
		seed_ratio = 0
		[searcher]
		preferred_method = torrent
		[updater]
		automatic = 0
		[xbmc]
		meta_extra_fanart = 1
		meta_enabled = 1
		meta_logo = 1
		meta_landscape = 1
		meta_banner = 1
		meta_clear_art = 1
		meta_extra_thumbs = 1
		meta_disc_art = 1
		[moviesearcher]
		cron_hour = *
		run_on_launch = 1
	COUCHPOTATOSETTINGS
fi

# === HTPC Manager ===
checkForGit https://github.com/Hellowlol HTPC-Manager
PYTHONPATH="${PIP}" python ${PIP}/pip install -r ${BASE}/HTPC-Manager/requirements.txt --cache-dir ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1
DATA=${BASE}/data/HTPC-Manager
mkdir -p ${DATA}
# Startup and shutdown scripts.
cat<<-STARTHTPC > ${BASE}/scripts/start-HTPC-Manager.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/HTPC-Manager.pid ]; then rm ${DATA}/HTPC-Manager.pid; fi; fi
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
	htpcDB ${DB} "stats_filesystem" "cgroup tmpfs fusectl fuse.lxcfs fuse.gvfsd-fuse rpc_pipefs"
	htpcDB ${DB} "transmission_enable" "on"
	htpcDB ${DB} "transmission_name" "Torrents"
	htpcDB ${DB} "transmission_password" "transmission"
	htpcDB ${DB} "transmission_rpcbasepath" "/transmission/"
	htpcDB ${DB} "transmission_port" "8083"
	htpcDB ${DB} "transmission_host" "localhost"
	htpcDB ${DB} "transmission_username" "transmission"
	htpcDB ${DB} "sickrage_basepath" "/"
	htpcDB ${DB} "sickrage_port" "8081"
	htpcDB ${DB} "sickrage_host" "localhost"
	htpcDB ${DB} "sickrage_enable" "on"
	htpcDB ${DB} "sickrage_name" "Television"
	htpcDB ${DB} "sickrage_apikey" "95ef1b0d35d02068c9224e90b20cbf58"
	htpcDB ${DB} "couchpotato_host" "localhost"
	htpcDB ${DB} "couchpotato_basepath" "/"
	htpcDB ${DB} "couchpotato_apikey" "5bf1b41b945d444ba9050e88869e6e64"
	htpcDB ${DB} "couchpotato_port" "8082"
	htpcDB ${DB} "couchpotato_name" "Movies"
	htpcDB ${DB} "couchpotato_enable" "on"
	htpcDB ${DB} "custom_urls" '[{"name":"SickRage", "url":"http://'${INTERNAL}':8081"},{"name":"CouchPotato", "url":"http://'${INTERNAL}':8082"},{"name":"Transmission", "url":"http://'${INTERNAL}':8083"},{"name":"Monit", "url":"http://'${INTERNAL}':8084"}]'
	htpcDB ${DB} "menu_order" "nav-sickrage,nav-couchpotato,nav-transmission,nav-stats,,,"
fi


# === PyWebDAV ===
echo " - Installing PyWebDAV"
PYTHONPATH="${PIP}" python ${PIP}/pip install PyWebDAV --cache-dir ${PIP}/_cache --target ${PIP} >> ${LOG} 2>&1
DATA=${BASE}/data/PyWebDAV
mkdir -p ${DATA}
mkdir -p ${BASE}/PyWebDAV
cat<<-DAVSERVER > ${BASE}/PyWebDAV/davserver
	#!/usr/bin/python
	import re
	import sys
	from pywebdav.server.server import run
	if __name__ == '__main__':
	   sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
	   sys.exit(run())
DAVSERVER
# Startup and shutdown scripts.
cat<<-STARTPYWEBDAV > ${BASE}/scripts/start-PyWebDAV.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/PyWebDAV.pid ]; then rm ${DATA}/PyWebDAV.pid; fi; fi
	cd ${BASE}/PyWebDAV
	PYTHONPATH="${PIP}" python davserver -D ${MNT} -n -J -H 0.0.0.0 -P 8888 -l warning >> ${DATA}/PyWebDAV.log 2>&1 &
	ps auxw | grep "python davserver" | grep -v grep | awk '{print \$2}' > ${DATA}/PyWebDAV.pid
STARTPYWEBDAV
chmod +x ${BASE}/scripts/start-PyWebDAV.sh
cat<<-STOPPYWEBDAV > ${BASE}/scripts/stop-PyWebDAV.sh
	#!/bin/bash
	kill \$(cat ${DATA}/PyWebDAV.pid)
	rm ${DATA}/PyWebDAV.pid
STOPPYWEBDAV
chmod +x ${BASE}/scripts/stop-PyWebDAV.sh


# === MonIt ===
echo " - Configuring Monit"
update-rc.d -f monit remove >> ${LOG} 2>&1
killall monit >> ${LOG} 2>&1
DATA=${BASE}/data/Monit
mkdir -p ${DATA}
cat<<-MONIT > ${DATA}/Monit.conf
	set daemon 300 with start delay 60
	
	set httpd port 8084
	   allow 192.168.0.0/16
	   allow 172.16.0.0/12
	   allow 10.0.0.0/8
	   allow 127.0.0.1
	   
	set logfile ${DATA}/Monit.log
	set pidfile ${DATA}/Monit.pid
	set statefile ${DATA}/Monit.state
	set idfile ${DATA}/Monit.id

	check process OpenVPN with pidfile ${BASE}/data/OpenVPN/OpenVPN.pid
	   start program = "${BASE}/scripts/start-OpenVPN.sh x"
	   stop  program = "${BASE}/scripts/stop-OpenVPN.sh"
	   if failed host google.com port 80 protocol http for 3 cycles then restart

	check process HTPCManager with pidfile ${BASE}/data/HTPC-Manager/HTPC-Manager.pid
	   start program = "${BASE}/scripts/start-HTPC-Manager.sh x"
	   stop  program = "${BASE}/scripts/stop-HTPC-Manager.sh"

	check process SickRage with pidfile ${BASE}/data/SickRage/SickRage.pid
	   start program = "${BASE}/scripts/start-SickRage.sh x"
	   stop  program = "${BASE}/scripts/stop-SickRage.sh"

	check process CouchPotatoServer with pidfile ${BASE}/data/CouchPotatoServer/CouchPotatoServer.pid
	   start program = "${BASE}/scripts/start-CouchPotatoServer.sh x"
	   stop  program = "${BASE}/scripts/stop-CouchPotatoServer.sh"

	check process Transmission with pidfile ${BASE}/data/Transmission/Transmission.pid
	   start program = "${BASE}/scripts/start-Transmission.sh x"
	   stop  program = "${BASE}/scripts/stop-Transmission.sh"

	check process PyWebDAV with pidfile ${BASE}/data/PyWebDAV/PyWebDAV.pid
	   start program = "${BASE}/scripts/start-PyWebDAV.sh x"
	   stop  program = "${BASE}/scripts/stop-PyWebDAV.sh"
MONIT
chmod 700 ${DATA}/Monit.conf
# Startup and shutdown scripts.
cat<<-STARTMONIT > ${BASE}/scripts/start-Monit.sh
	#!/bin/bash
	if [ "\$1x" != "x" ]; then if [ -e ${DATA}/Monit.pid ]; then rm ${DATA}/Monit.pid; fi; fi
	monit -c ${DATA}/Monit.conf
STARTMONIT
chmod +x ${BASE}/scripts/start-Monit.sh
cat<<-STOPMONIT > ${BASE}/scripts/stop-Monit.sh
	#!/bin/bash
	kill \$(cat ${DATA}/Monit.pid)
STOPMONIT
chmod +x ${BASE}/scripts/stop-Monit.sh


# === Main start and stop scripts ===
cat<<-STARTALL > ${BASE}/start.sh
	#!/bin/bash
	if [[ $EUID -ne 0 ]]; then
	   echo "!! This application must be run as root."
	   exit 1
	fi
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
	if [[ $EUID -ne 0 ]]; then
	   echo "!! This application must be run as root."
	   exit 1
	fi
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


# === Start on Boot ===
grep -qF "${BASE}" /etc/rc.local
INRCLOCAL=$?
if [ "x${INRCLOCAL}" != "x0" ]; then
	sed -i 's#^exit 0#'${BASE}/start.sh'#g' /etc/rc.local
	echo "exit 0" >> /etc/rc.local
fi


cat<<-DONE

Finished!

  After rebooting, you will be able to access your system at the following:

    - HTPC Manager  http://${INTERNAL}:8080
    - SickRage      http://${INTERNAL}:8081
    - CouchPotato   http://${INTERNAL}:8082
    - Transmission  http://${INTERNAL}:8083
    - Monit         http://${INTERNAL}:8084
    - WebDAV Share  http://${INTERNAL}:8888

DONE


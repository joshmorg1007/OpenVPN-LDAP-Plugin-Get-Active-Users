import re
import string
import os
##test
### File Paths
OPENVPNLOG_PATH = '/var/log/openvpn/status.log'
TMP_FILE_PATH = '/OpenVPNLogging/tmp/tmp.txt'

###Regular Expressiosn
VPN_IP = re.compile(".*\d+,\d+")
VIRTUAL_IP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},")
SUCCEED_AUTH = re.compile(".*succeeded for username")
NAME = re.compile ("\w+(?=')")
IP = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=:\d+)")

### Fucntions
def main():
    init_directories()
    concat_syslogs()

    sys_log = open(TMP_FILE_PATH, "r")
    vpn_log = open(OPENVPNLOG_PATH, "r")

    active, virt = pull_active_user_info(vpn_log)

    auth = pull_successful_auth(sys_log)

    match_logs(auth, active, virt)

    sys_log.close()
    vpn_log.close()

def pull_active_user_info(file):
    user_info = {}
    virt_IPs = {}
    for line in file.readlines():
        if VPN_IP.match(line) is not None:
            info = line.split(",")
            user_ip = info[1].split(":")[0]
            user_info[user_ip] = info

        elif VIRTUAL_IP.match(line) is not None:
            info = line.split(',')
            user_ip = info[2].split(":")[0]
            virt_IPs[user_ip] = info[0]

    return user_info, virt_IPs

def pull_successful_auth(file):
    succeded = {}
    for line in file.readlines():
        if SUCCEED_AUTH.match(line) is not None:
            name = NAME.findall(line)
            ip = IP.findall(line)
            succeded[ip[0]] = name[0]
    return succeded

def match_logs(auth, active, virt):
    print("\n")
    print("################################################ CONNECTED USERS ################################################")
    print ("{:<15} {:<18} {:<15} {:<20} {:<16} {:<25}".format('User Name','External IP','Virtual IP', 'Data Recieved (MB)', 'Data Sent (MB)', 'Connected Since: '))
    print("\n")
    for user in active:
        username = auth[user]
        ip = user
        virt_ip = virt[user]
        data_rec = active[user][2]
        data_sent = active[user][3]
        active_time = active[user][4]
        print ("{:<15} {:<18} {:<15} {:<20} {:<16} {:<25}".format(username, ip, virt_ip, float(data_rec)/1000000, float(data_sent)/1000000, active_time))

def concat_syslogs():
    os.system("/bin/cat /var/log/syslog.7.gz /var/log/syslog.6.gz /var/log/syslog.5.gz /var/log/syslog.4.gz /var/log/syslog.3.gz /var/log/syslog.2.gz | /bin/gunzip > " + TMP_FILE_PATH)
    os.system("/bin/cat /var/log/syslog.1 /var/log/syslog >> " + TMP_FILE_PATH)

def init_directories():
    try:
        os.mkdir('/OpenVPNLogging/')
        os.mkdir('/OpenVPNLogging/tmp/')
    except:
        do = None
    try:
        file = open('/OpenVPNLogging/tmp/tmp.txt', 'x')
        file.close()
    except:
        do = None

if __name__ == "__main__":
    main()

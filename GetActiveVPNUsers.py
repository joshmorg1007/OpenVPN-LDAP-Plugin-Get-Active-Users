import re
import string
import os
import json

### File Paths
OPENVPNLOG_PATH = '/var/log/openvpn/status.log'
TMP_FILE_PATH = '/OpenVPNLogging/tmp/tmp.txt'
IP_LOOKUP_TABLE_PATH = '/OpenVPNLogging/IPLookup/IP_Table.json'

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

    if(os.path.exists(IP_LOOKUP_TABLE_PATH) == False):
        build_IP_lookup_table()

    user_data = get_and_match_user_data()

    print_formated_data(user_data)

def build_IP_lookup_table():
    print("Building IP Lookup Table")
    if(os.path.exists(IP_LOOKUP_TABLE_PATH) == False):
        lookup = {}

    else:
        lookup = load_IP_lookup_table()

    ip_table = open(IP_LOOKUP_TABLE_PATH, "w")

    active = pull_active_IPs()
    auth = pull_successful_auth()

    for IP in active:

        lookup[IP] = auth[IP]

    json.dump(lookup, ip_table)

    ip_table.close()

def load_IP_lookup_table():
    with open(IP_LOOKUP_TABLE_PATH, "r") as file:

        try:
            data = json.load(file)
        except:
            data = {}
        return data

def get_and_match_user_data():
    user_list_and_metrics = {}
    user_info, virt_IPs = pull_active_user_info()
    table = load_IP_lookup_table()

    for IP in user_info:
        try:
            if table[IP] is not None:
                name = table[IP]
                virt_ip = virt_IPs[IP]
                data_rec = user_info[IP][2]
                data_sent = user_info[IP][3]
                active_time = user_info[IP][4]

                metrics = [name, IP, virt_ip, data_rec, data_sent, active_time]

                user_list_and_metrics[IP] = metrics
        except:
            build_IP_lookup_table()
            table  = load_IP_lookup_table()

            name = table[IP]
            virt_ip = virt_IPs[IP]
            data_rec = user_info[IP][2]
            data_sent = user_info[IP][3]
            active_time = user_info[IP][4]

            metrics = [name, IP, virt_ip, data_rec, data_sent, active_time]

            user_list_and_metrics[IP] = metrics

    return user_list_and_metrics

def pull_active_user_info():
    with open(OPENVPNLOG_PATH, "r") as file:

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

def pull_active_IPs():
    IPs = []
    with open(OPENVPNLOG_PATH, "r") as file:
        for line in file.readlines():
            if VPN_IP.match(line) is not None:
                info = line.split(",")
                user_ip = info[1].split(":")[0]
                IPs.append(user_ip)
        return IPs

def pull_successful_auth():
    with open(TMP_FILE_PATH, "r") as file:
        succeded = {}
        for line in file.readlines():
            if SUCCEED_AUTH.match(line) is not None:
                name = NAME.findall(line)
                ip = IP.findall(line)
                succeded[ip[0]] = name[0]
        return succeded

def print_formated_data(user_data):
    print("\n")
    print("################################################ CONNECTED USERS ################################################")
    print ("{:<15} {:<18} {:<15} {:<20} {:<16} {:<25}".format('User Name','External IP','Virtual IP', 'Data Recieved From (MB)', 'Data Sent To (MB)', 'Connected Since: '))
    print("\n")
    for IP in user_data:
        name = user_data[IP][0]
        virt_ip = user_data[IP][2]
        data_rec = user_data[IP][3]
        data_sent = user_data[IP][4]
        active_time = user_data[IP][5]
        print ("{:<15} {:<18} {:<15} {:<20} {:<16} {:<25}".format(name, IP, virt_ip, float(data_rec)/1000000, float(data_sent)/1000000, active_time))

def concat_syslogs():
    os.system("/bin/cat /var/log/syslog.7.gz /var/log/syslog.6.gz /var/log/syslog.5.gz /var/log/syslog.4.gz /var/log/syslog.3.gz /var/log/syslog.2.gz | /bin/gunzip > " + TMP_FILE_PATH)
    os.system("/bin/cat /var/log/syslog.1 /var/log/syslog >> " + TMP_FILE_PATH)

def init_directories():
    try:
        os.mkdir('/OpenVPNLogging/')
    except:
        do = None
    try:
        os.mkdir('/OpenVPNLogging/tmp/')
    except:
        do = None
    try:
        os.mkdir('/OpenVPNLogging/IPLookup/')
    except:
        do = None
    try:
        file = open('IP_LOOKUP_TABLE_PATH', 'x')
        file.close()
    except:
        do = None
    try:
        file = open('TMP_FILE_PATH', 'x')
        file.close()
    except:
        do = None

if __name__ == "__main__":
    main()

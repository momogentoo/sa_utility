#!/usr/bin/python

# CISCO ASA 5505 syslog parsing & tcp/udp connections monitor


import re, sys, time

general_format = re.compile(r'%ASA-\d+-(\d+): ')
common_built_connection = re.compile(r'(\w+) connection (\d+) for (\w+):([\w\.-]+)\/(\d+) \(([\w\.-]+/\d+)\) to (\w+):([\w\.-]+)\/(\d+) \(([\w\.-]+\/\d+)\)')
common_teardown_connection = re.compile(r'(\w+) connection (\d+) for (\w+):([\w\.-]+)\/(\d+) to (\w+):([\w\.-]+)\/(\d+)( duration (\d+:\d+:\d+) bytes (\d+)( (\w+) (\w+))?)?')

class ansi_color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    LIGHT_PURPLE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    PADDING = 9

class asa_connection:
    def __init__(self):
        self.prot = None
        self.id = None
        self.msg_id = None
        self.dest_host = None
        self.dest_port = None
        self.src_host = None
        self.src_port = None
        self.duration = None
        self.bytes = None
        self.flags = None
        self.removable = False

    def __str__(self):
        return '%s %s:%s -> %s:%s' % (self.prot, self.dest_host, self.dest_port, self.src_host, self.src_port)

class host_statistics:
    def __init__(self):
        self.host = ''
        self.total_connections = 0
        self.total_tcp_connections = 0
        self.total_udp_connections = 0
        self.max_total_connections = 0
        self.max_total_connections_time = None

# TCP
# %ASA-6-302013: Built outbound TCP connection 38627356 for outside:xxx.xx.xx.xxx/110 (xxx.xx.xx.xxx/110) to inside:aaa.bbb.ccc.ddd/53445 (aaa.bbb.ccc.ddd/38642)
# %ASA-6-302014: Teardown TCP connection 38627356 for outside:xxx.xx.xx.xxx/110 to inside:aaa.bbb.ccc.ddd/53445 duration 0:00:00 bytes 587 TCP FINs
# UDP 
# %ASA-6-302015: Built outbound UDP connection 38627355 for outside:xxx.xx.xx.xxx/53 (xxx.xx.xx.xxx/53) to inside:aaa.bbb.ccc.ddd/6129 (aaa.bbb.ccc.ddd/6129)
# %ASA-6-302016: Teardown UDP connection 38627355 for outside:xxx.xx.xx.xxx/53 to inside:aaa.bbb.ccc.ddd/6129 duration 0:00:00 bytes 148

def stage1_parse(line):
    match = general_format.search(line)

    if match is None:
        return None, None

    msg_id = match.groups()[0]
    details = line[match.end():]

    return msg_id, details


def parse_common_built_connection(msg_id, details, connection_map):
    matches = common_built_connection.search(details)

    c = asa_connection()
    c.msg_id = msg_id

    # Invalid built outbound connection log
    if matches is None:
        print details
        return c 

    captures = matches.groups()

    c.prot = captures[0]
    c.id = captures[1]
    c.dest_host = captures[3]
    c.dest_port = captures[4]
    c.src_host = captures[7]
    c.src_port = captures[8]

    return c

def parse_common_teardown_connection(msg_id, details, connection_map):
    matches = common_teardown_connection.search(details)

    c = asa_connection()
    c.msg_id = msg_id

    if matches is None:
        print details
        return c

    captures = matches.groups()

    c.prot = captures[0]
    c.id = captures[1]
    c.dest_host = captures[3]
    c.dest_port = captures[4]
    c.src_host = captures[6]
    c.src_port = captures[7]

    c.duration = captures[9]
    c.bytes = captures[10]
    c.flags = captures[11] # could be None for UDP

    c.removable = True # could be removed from map

    return c

def clear_screen():
    #print(chr(27) + "[2J")
    sys.stderr.write("\x1b[2J\x1b[H")


def summarize_connection_map(connection_map, previous_statistics, hosts_stats):
    per_host_connections = {}
    total_connections = 0
    # do some summary

    for conn in connection_map.values():
        if not per_host_connections.has_key(conn.src_host):
            host_stat = host_statistics()
            host_stat.host = conn.src_host
            per_host_connections[conn.src_host] = host_stat
        else:
            host_stat = per_host_connections[conn.src_host]

        host_stat.total_connections = host_stat.total_connections + 1

        if conn.prot == 'TCP':
            host_stat.total_tcp_connections = host_stat.total_tcp_connections + 1
        elif conn.prot == 'UDP':
            host_stat.total_udp_connections = host_stat.total_udp_connections + 1

        total_connections = total_connections + 1

    hosts = sorted(per_host_connections, key=lambda k: per_host_connections[k].total_connections, reverse = True)

    update_time = time.ctime()

    # print out last update time
    print 'Last Update: %s' % (update_time)
    print 'Total TCP/UDP Connection: %d' % (total_connections)
    print ''
    print '%-40s%23s%15s%30s%30s' % ('Host', 'Total Connection', 'TCP', 'UDP', 'Max/Time')
    print '-' * 160


    for host in hosts:
        host_stat = per_host_connections[host]
        delta_total = 0
        delta_tcp = 0
        delta_udp = 0

        if not hosts_stats.has_key(host):
            host_stat_hist = host_statistics()
            hosts_stats[host] = host_stat_hist
        else:
            host_stat_hist = hosts_stats[host]

        # Update historical max total connections
        if host_stat.total_connections > host_stat_hist.max_total_connections:
            host_stat_hist.max_total_connections = host_stat.total_connections
            host_stat_hist.max_total_connections_time = update_time

        if previous_statistics.has_key(host):
            prev_host_stat = previous_statistics[host]
            delta_total = host_stat.total_connections - prev_host_stat.total_connections
            delta_tcp = host_stat.total_tcp_connections - prev_host_stat.total_tcp_connections
            delta_udp = host_stat.total_udp_connections - prev_host_stat.total_udp_connections

        print '%-40s%10d%-20s%s%10d%-20s%s%10d%-20s%s%-20s' % (host_stat.host, 
            host_stat.total_connections,
            '%s%d)' % (ansi_color.GREEN + '(+' if delta_total > 0 else ansi_color.RED + '(', delta_total) + ansi_color.END if delta_total != 0 else '',
            ' ' * ansi_color.PADDING if delta_total != 0 else '',
            host_stat.total_tcp_connections,
            '%s%d)' % (ansi_color.GREEN + '(+' if delta_tcp > 0 else ansi_color.RED + '(', delta_tcp) + ansi_color.END if delta_tcp != 0 else '',
            ' ' * ansi_color.PADDING if delta_tcp != 0 else '',
            host_stat.total_udp_connections,
            '%s%d)' % (ansi_color.GREEN + '(+' if delta_udp > 0 else ansi_color.RED + '(', delta_udp) + ansi_color.END if delta_udp != 0 else '',
            ' ' * ansi_color.PADDING if delta_udp != 0 else '',
            '%d/%s' % (host_stat_hist.max_total_connections, host_stat_hist.max_total_connections_time) if host_stat_hist.max_total_connections_time is not None else '' 
            )

    return per_host_connections

# define msg_id vs 
callback_pool = {
    '302013' : parse_common_built_connection, # Built Inbound/Outbound TCP
    '302014' : parse_common_teardown_connection, # Teardown Inbound/Outbound TCP
    '302015' : parse_common_built_connection, # Built Inbound/Outbound UDP
    '302016' : parse_common_teardown_connection # Teardown Inbound/Outbound UDP
    }

# global connection map
connection_map = {}


# settings
summary_interval = 2  # interval in sec between two summary

# Main
if __name__ == '__main__':
    last_summary_time = 0
    previous_statistics = {}
    hosts_stats = {}
    try:
        for line in sys.stdin:
            msg_id, details = stage1_parse(line)
    
            if msg_id is None or details is None:
                continue
        
            # A msg type that cannot be handled yet
            if not callback_pool.has_key(msg_id):
                continue
    
            # get callback function
            callback_func = callback_pool[msg_id]
    
            # invoke and parse msg
            connection = callback_func(msg_id, details, connection_map)
        
            # valid connection info
            if connection is not None and connection.id is not None:
                # connection can be removed - mostly a 'teardown'
                if connection.removable:
                    # delete from map if exists
                    if connection_map.has_key(connection.id):
                        del connection_map[connection.id]
                else: # add into map
                    connection_map[connection.id] = connection
    
            current_time = time.time()
    
            if (current_time - last_summary_time) >= summary_interval:
                # clear screen
                clear_screen()
                    
                # host vs # of connections mapping
                previous_statistics = summarize_connection_map(connection_map, previous_statistics, hosts_stats)
                last_summary_time = current_time
    except KeyboardInterrupt, e:
        print 'Exit'

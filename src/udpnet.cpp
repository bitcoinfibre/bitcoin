// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "udpnet.h"
#include "udprelay.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "compat/endian.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "netbase.h"
#include "primitives/block.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "init.h" // for ShutdownRequested()

#include <sys/socket.h>

#include <event2/event.h>

#include <boost/thread.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <thread>

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static std::vector<int> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])
static bool last_sock_is_local;

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
bool maybe_have_write_nodes;

static std::map<int64_t, std::tuple<CService, uint64_t, size_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static CService LOCAL_WRITE_DEVICE_SERVICE(CNetAddr(), 1);
static CService LOCAL_READ_DEVICE_SERVICE(CNetAddr(), 2);

#define LOCAL_DEVICE_CHECKSUM_MAGIC htole64(0xdeadbeef)

//TODO: Switch to something faster than SHA256 for checksums
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    CSHA256 hasher;
    uint256 h;
    hasher.Write((unsigned char*)&magic, sizeof(magic)).Write((unsigned char*)&msg.header.msg_type, length - 16).Finalize(h.begin());
    msg.header.chk1 = htole64(h.GetUint64(0));
    msg.header.chk2 = htole64(h.GetUint64(1));
}
static bool CheckChecksum(uint64_t magic, const UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    CSHA256 hasher;
    uint256 h;
    hasher.Write((unsigned char*)&magic, sizeof(magic)).Write((unsigned char*)&msg.header.msg_type, length - 16).Finalize(h.begin());
    return msg.header.chk1 == htole64(h.GetUint64(0)) && msg.header.chk2 == htole64(h.GetUint64(1));
}



/**
 * Init/shutdown logic follows
 */

static struct event_base* event_base_read = NULL;
static event *timer_event;
static std::vector<event*> read_events;
static struct timeval timer_interval;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages(size_t group);
static void do_read_local_messages();
static std::atomic_bool local_read_messages_break(false);
static void send_messages_flush_and_break();
static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list, const std::tuple<int64_t, bool, std::string>& local_write_device);
static void ThreadRunWriteEventLoop(size_t group) { do_send_messages(group); }
static void ThreadRunLocalReadEventLoop() { do_read_local_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static boost::thread *udp_read_thread = NULL, *udp_local_read_thread = NULL;
static std::vector<boost::thread> udp_write_threads;

static void OpenLocalDeviceConnection(bool fWrite);
static void StartLocalBackfillThread();
static std::tuple<int64_t, bool, std::string> get_local_device();

static void AddConnectionFromString(const std::string& node, bool fTrust) {
    size_t host_port_end = node.find(',');
    size_t local_pass_end = node.find(',', host_port_end + 1);
    size_t remote_pass_end = node.find(',', local_pass_end + 1);
    size_t group_end = node.find(',', remote_pass_end + 1);
    if (host_port_end == std::string::npos || local_pass_end == std::string::npos || (remote_pass_end != std::string::npos && group_end != std::string::npos)) {
        LogPrintf("UDP: Failed to parse parameter to -add[trusted]udpnode: %s\n", node);
        return;
    }

    std::string host_port = node.substr(0, host_port_end);
    CService addr;
    if (!Lookup(host_port.c_str(), addr, -1, true) || !addr.IsValid()) {
        LogPrintf("UDP: Failed to lookup hostname for -add[trusted]udpnode: %s\n", host_port);
        return;
    }

    std::string local_pass = node.substr(host_port_end + 1, local_pass_end - host_port_end - 1);
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);

    std::string remote_pass;
    if(remote_pass_end == std::string::npos)
        remote_pass = node.substr(local_pass_end + 1);
    else
        remote_pass = node.substr(local_pass_end + 1, remote_pass_end - local_pass_end - 1);
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    size_t group = 0;
    if (remote_pass_end != std::string::npos) {
        std::string group_str(node.substr(remote_pass_end + 1));
        group = atoi64(group_str);
    }

    OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust, UDP_CONNECTION_TYPE_NORMAL, group);
}

static void AddConfAddedConnections() {
    if (gArgs.IsArgSet("-addudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addudpnode")) {
            AddConnectionFromString(node, false);
        }
    }
    if (gArgs.IsArgSet("-addtrustedudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addtrustedudpnode")) {
            AddConnectionFromString(node, true);
        }
    }
}

static void CloseSocketsAndReadEvents() {
    for (event* ev : read_events)
        event_free(ev);
    for (int sock : udp_socks)
        close(sock);
    read_events.clear();
    udp_socks.clear();
}

bool InitializeUDPConnections() {
    assert(udp_write_threads.empty() && !udp_read_thread);

    const std::vector<std::pair<unsigned short, uint64_t> > group_list(GetUDPInboundPorts());
    for (std::pair<unsigned short, uint64_t> port : group_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());

        int opt = 1;
        assert(setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) == 0);
        opt = 0;
        assert(setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt,  sizeof(opt)) == 0);
        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(port.first);

        if (bind(udp_socks.back(), (sockaddr*) &wildcard, sizeof(wildcard))) {
            CloseSocketsAndReadEvents();
            return false;
        }

        LogPrintf("UDP: Bound to port %hd for group %lu with %lu Mbps\n", port.first, udp_socks.size() - 1, port.second);
    }

    event_base_read = event_base_new();
    if (!event_base_read) {
        CloseSocketsAndReadEvents();
        return false;
    }

    for (int socket : udp_socks) {
        event *read_event = event_new(event_base_read, socket, EV_READ | EV_PERSIST, read_socket_func, NULL);
        if (!read_event) {
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        read_events.push_back(read_event);
        event_add(read_event, NULL);
    }

    // Init local write device only after udp socks were all added to read_event
    auto local_write_device = get_local_device();
    if (std::get<0>(local_write_device)) {
        int fd = open(std::get<2>(local_write_device).c_str(), O_WRONLY);
        if (fd < 0) {
            LogPrintf("Failed to open -fecwritedevice, not running any FIBRE connections\n");
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        udp_socks.push_back(fd);
    }

    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, NULL);
    if (!timer_event) {
        CloseSocketsAndReadEvents();
        event_base_free(event_base_read);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500*1000;
    evtimer_add(timer_event, &timer_interval);

    send_messages_init(group_list, local_write_device);
    for (size_t i = 0; i < udp_socks.size(); i++) {
        boost::function<void ()> f(boost::bind(&ThreadRunWriteEventLoop, i));
        udp_write_threads.emplace_back(boost::bind(&TraceThread<boost::function<void ()> >, "udpwrite", f));
    }

    AddConfAddedConnections();

    if (std::get<0>(local_write_device)) {
        OpenLocalDeviceConnection(true);
        if (std::get<1>(local_write_device))
            StartLocalBackfillThread();
    }

    if (gArgs.IsArgSet("-fecreaddevice")) {
        OpenLocalDeviceConnection(false);
        udp_local_read_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpreadlocal", &ThreadRunLocalReadEventLoop));
    }

    BlockRecvInit();

    udp_read_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpread", &ThreadRunReadEventLoop));

    return true;
}

void StopUDPConnections() {
    if (!udp_read_thread)
        return;

    event_base_loopbreak(event_base_read);
    udp_read_thread->join();
    delete udp_read_thread;

    local_read_messages_break = true;
    if (udp_local_read_thread) {
        udp_local_read_thread->join();
        delete udp_local_read_thread;
    }

    BlockRecvShutdown();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessage(msg, sizeof(UDPMessageHeader), it);
    mapUDPNodes.clear();

    send_messages_flush_and_break();

    for (boost::thread& t : udp_write_threads)
        t.join();
    udp_write_threads.clear();

    CloseSocketsAndReadEvents();

    event_free(timer_event);
    event_base_free(event_base_read);
}



/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), it);

    int64_t now = GetTimeMillis();
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second);

    return silent_disconnect(it);
}

void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it) {
    send_and_disconnect(it);
}

static void read_socket_func(evutil_socket_t fd, short event, void* arg) {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    UDPMessage msg;
    struct sockaddr_in6 remoteaddr;
    socklen_t remoteaddrlen = sizeof(remoteaddr);

    ssize_t res = recvfrom(fd, &msg, sizeof(msg), MSG_DONTWAIT, (sockaddr*)&remoteaddr, &remoteaddrlen);
    if (res < 0) {
        int err = errno;
        LogPrintf("UDP: Error reading from socket: %d (%s)!\n", err, strerror(err));
        return;
    }
    assert(remoteaddrlen == sizeof(remoteaddr));

    if (size_t(res) < sizeof(UDPMessageHeader) || size_t(res) >= sizeof(UDPMessage))
        return;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.find(remoteaddr);
    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res))
        return;

    UDPConnectionState& state = it->second;

    state.lastRecvTime = GetTimeMillis();
    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_SYN) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized SYN message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        state.protocolVersion = le64toh(msg.msg.longint);
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > PROTOCOL_VERSION_CUR(UDP_PROTOCOL_VERSION)) {
            LogPrintf("UDP: Got min protocol version we didnt understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogPrintf("UDP: Got invalidly-sized KEEPALIVE message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogPrint(BCLog::UDPNET, "UDP: Successfully connected to %s!\n", it->first.ToString());

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToString());
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockMessage(msg, res, it->first, it->second)) {
            send_and_disconnect(it);
            return;
        }
    } else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
    } else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PONG message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        uint64_t nonce = le64toh(msg.msg.longint);
        std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.find(nonce);
        if (nonceit == state.ping_times.end()) // Possibly duplicated packet
            LogPrintf("UDP: Got PONG message without PING from %s\n", it->first.ToString());
        else {
            double rtt = (GetTimeMicros() - nonceit->second) / 1000.0;
            LogPrintf("UDP: RTT to %s is %lf ms\n", it->first.ToString(), rtt);
            state.ping_times.erase(nonceit);
            state.last_pings[state.last_ping_location] = rtt;
            state.last_ping_location = (state.last_ping_location + 1) % (sizeof(state.last_pings) / sizeof(double));
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
        if (to_millis_double(finish - start) > 1)
            LogPrintf("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
    }
}

static bool read_local_bytes(int fd, unsigned char* buf, size_t num) {
    fd_set read_set;
    struct timeval timeout;
    while (!local_read_messages_break) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        timeout.tv_sec = 0; timeout.tv_usec = 50 * 1000;
        int res = select(fd + 1, &read_set, NULL, NULL, &timeout);
        if (res > 0) {
            ssize_t read_res = read(fd, buf, num);
            if (read_res <= 0) return false;
            buf += (size_t)read_res; num -= (size_t)read_res;
            if (num == 0) return true;
            continue;
        }
        if (res != 0) return false;
    }
    return false;
}

static void do_read_local_messages() {
    std::string localUDPReadDevice(gArgs.GetArg("-fecreaddevice", ""));
    assert(localUDPReadDevice != "");

    do {
        int fd = open(localUDPReadDevice.c_str(), O_RDONLY);
        assert(fd >= 0 && "Failed to open -fecreaddevice, please try again");
        assert(fd <= FD_SETSIZE && "Failed to open -fecreaddevice, please try again");
        while (!local_read_messages_break) {
            // Scan forward until we find magic bytes
            for (ssize_t i = 0; i < (ssize_t)sizeof(LOCAL_MAGIC_BYTES); i++) {
                unsigned char c;
                if (!read_local_bytes(fd, &c, 1))
                    break;
                if (LOCAL_MAGIC_BYTES[i] != c) {
                    i = -1;
                    continue;
                }
            }

            UDPMessage msg;
            // UDPMessage is 1 byte larger than block messages
            if (!read_local_bytes(fd, (unsigned char*)&msg, sizeof(UDPMessage) - 1))
                break;

            const bool fBench = LogAcceptCategory(BCLog::BENCH);
            std::chrono::steady_clock::time_point start;
            if (fBench)
                start = std::chrono::steady_clock::now();

            std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
            std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.find(LOCAL_READ_DEVICE_SERVICE);
            if (it == mapUDPNodes.end())
                continue; // We lost our local node - it'll come back when we reconnect
            if (!CheckChecksum(it->second.connection.local_magic, msg, sizeof(UDPMessage) - 1))
                continue;

            UDPConnectionState& state = it->second;

            state.lastRecvTime = GetTimeMillis();

            if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS) {
                if (!HandleBlockMessage(msg, sizeof(UDPMessage) - 1, it->first, it->second)) {
                    send_and_disconnect(it);
                    continue;
                }
            } else {
                // Huh? Only supposed to get block messages
                continue;
            }

            if (fBench) {
                std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
                if (to_millis_double(finish - start) > 1)
                    LogPrintf("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
            }
        }

        close(fd);
    } while (!local_read_messages_break);
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info);
static void timer_func(evutil_socket_t fd, short event, void* arg) {
    ProcessDownloadTimerEvents();

    UDPMessage msg;
    const int64_t now = GetTimeMillis();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    {
        std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::iterator itend = nodesToRepeatDisconnect.upper_bound(now);
        for (std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::const_iterator it = nodesToRepeatDisconnect.begin(); it != itend; it++) {
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            SendMessage(msg, sizeof(UDPMessageHeader), std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second));
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {
        boost::this_thread::interruption_point();

        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_NORMAL) {
            it++;
            continue;
        }

        UDPConnectionState& state = it->second;

        int64_t origLastSendTime = state.lastSendTime;

        if (state.lastRecvTime < now - 1000 * 60 * 10) {
            LogPrint(BCLog::UDPNET, "UDP: Peer %s timed out\n", it->first.ToString());
            it = send_and_disconnect(it); // Removes it from mapUDPNodes
            continue;
        }

        if (!(state.state & STATE_GOT_SYN_ACK) && origLastSendTime < now - 1000) {
            msg.header.msg_type = MSG_TYPE_SYN;
            msg.msg.longint = htole64(UDP_PROTOCOL_VERSION);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = GetRand(std::numeric_limits<uint64_t>::max());
            msg.header.msg_type = MSG_TYPE_PING;
            msg.msg.longint = htole64(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
            state.ping_times[pingnonce] = GetTimeMicros();
            state.lastPingTime = now;
        }

        for (std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.begin(); nonceit != state.ping_times.end();) {
            if (nonceit->second < (now - 5000) * 1000)
                nonceit = state.ping_times.erase(nonceit);
            else
                nonceit++;
        }

        it++;
    }

    for (const auto& conn : mapPersistentNodes) {
        if (!mapUDPNodes.count(conn.first)) {
            bool fWaitingOnDisconnect = false;
            for (const auto& repeatNode : nodesToRepeatDisconnect) {
                if (std::get<0>(repeatNode.second) == conn.first)
                    fWaitingOnDisconnect = true;
            }
            if (fWaitingOnDisconnect)
                continue;

            OpenUDPConnectionTo(conn.first, conn.second);
        }
    }
}

// ~10MB of outbound messages pending
#define PENDING_MESSAGES_BUFF_SIZE 10000
static std::atomic_bool send_messages_break(false);
struct PerGroupMessageQueue {
    std::mutex send_messages_mutex;
    std::condition_variable send_messages_wake_cv;
    std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
    std::atomic<uint16_t> nextPendingMessage, nextUndefinedMessage;
    uint64_t bw;
    std::vector<UDPMessage> local_send_backfill_messages;
    size_t backfill_index;
    PerGroupMessageQueue() : nextPendingMessage(0), nextUndefinedMessage(0), bw(0), backfill_index(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) { assert(false); }
};
static std::vector<PerGroupMessageQueue> messageQueues;
static const size_t LOCAL_RECEIVE_GROUP = (size_t)-1;
static size_t LOCAL_SEND_GROUP = (size_t)-1;

void SendMessage(const UDPMessage& msg, const unsigned int length, const CService& service, const uint64_t magic, size_t group) {
    assert(length <= sizeof(UDPMessage));

    if (group == LOCAL_RECEIVE_GROUP)
        return;

    assert(group < messageQueues.size());
    PerGroupMessageQueue& queue = messageQueues[group];

    std::unique_lock<std::mutex> lock(queue.send_messages_mutex);
    if (queue.nextPendingMessage == (queue.nextUndefinedMessage + 1) % PENDING_MESSAGES_BUFF_SIZE)
        return;

    std::tuple<CService, UDPMessage, unsigned int, uint64_t>& new_msg = queue.messagesPendingRingBuff[queue.nextUndefinedMessage];
    std::get<0>(new_msg) = service;
    memcpy(&std::get<1>(new_msg), &msg, length);
    std::get<2>(new_msg) = length;
    std::get<3>(new_msg) = magic;

    queue.nextUndefinedMessage = (queue.nextUndefinedMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;

    lock.unlock();
    queue.send_messages_wake_cv.notify_all();
}
void SendMessage(const UDPMessage& msg, const unsigned int length, const std::map<CService, UDPConnectionState>::const_iterator& node) {
    return SendMessage(msg, length, node->first, node->second.connection.remote_magic, node->second.connection.group);
}

static void do_send_messages(size_t group) {
    assert(messageQueues.size() > group);
    PerGroupMessageQueue& queue = messageQueues[group];

    const bool local = last_sock_is_local && group == messageQueues.size() - 1;

    const size_t target_bytes_per_sec = queue.bw * (local ? 1 : 1024 * 1024) / 8;
    const size_t max_buff_bytes = 50 * 1024; // Dont buffer more than 50K at a time

    const size_t WRITE_OBJS_PER_CALL = max_buff_bytes / PACKET_SIZE;
    const int sock = udp_socks[group];

    while (true) {
        if (queue.nextUndefinedMessage == queue.nextPendingMessage) {
            std::unique_lock<std::mutex> lock(queue.send_messages_mutex);
            while (queue.nextUndefinedMessage == queue.nextPendingMessage && queue.local_send_backfill_messages.empty() && !send_messages_break)
                queue.send_messages_wake_cv.wait(lock);
        }
        if (send_messages_break)
            return;

        std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

        size_t i = 0;
        for (; i < WRITE_OBJS_PER_CALL && queue.nextUndefinedMessage != queue.nextPendingMessage; i++) {
            std::tuple<CService, UDPMessage, unsigned int, uint64_t>& msg = queue.messagesPendingRingBuff[queue.nextPendingMessage];

            FillChecksum(std::get<3>(msg), std::get<1>(msg), std::get<2>(msg));

            if (local) {
                if ((std::get<1>(msg).header.msg_type & UDP_MSG_TYPE_TYPE_MASK) != MSG_TYPE_BLOCK_HEADER &&
                        (std::get<1>(msg).header.msg_type & UDP_MSG_TYPE_TYPE_MASK) != MSG_TYPE_BLOCK_CONTENTS) {
                    LogPrintf("UDP: Something tried to send non-block to local write!\n");
                    continue;
                }

                assert(std::get<2>(msg) == sizeof(UDPMessage) - 1); // UDPMessage is 1 byte larger than block messages

                if (write(sock, &LOCAL_MAGIC_BYTES, sizeof(LOCAL_MAGIC_BYTES)) != sizeof(LOCAL_MAGIC_BYTES) ||
                        write(sock, &std::get<1>(msg), std::get<2>(msg)) != std::get<2>(msg)) {
                    //TODO: Handle?
                }
            } else {
                sockaddr_in6 remoteaddr;
                memset(&remoteaddr, 0, sizeof(remoteaddr));
                remoteaddr.sin6_family = AF_INET6;
                assert(std::get<0>(msg).GetIn6Addr(&remoteaddr.sin6_addr));
                remoteaddr.sin6_port = htons(std::get<0>(msg).GetPort());

                if (sendto(sock, &std::get<1>(msg), std::get<2>(msg), 0, (sockaddr*)&remoteaddr, sizeof(remoteaddr)) != std::get<2>(msg)) {
                    //TODO: Handle?
                }
            }

            queue.nextPendingMessage = (queue.nextPendingMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;
        }
        if (local && i == 0) {
            std::unique_lock<std::mutex> lock(queue.send_messages_mutex);
            if (queue.backfill_index >= queue.local_send_backfill_messages.size()) {
                queue.local_send_backfill_messages.clear();
                queue.backfill_index = 0;
            } else {
                UDPMessage& msg = queue.local_send_backfill_messages[queue.backfill_index++];
                if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) != MSG_TYPE_BLOCK_HEADER &&
                        (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) != MSG_TYPE_BLOCK_CONTENTS) {
                    LogPrintf("UDP: Backfill tried to send non-block to local write!\n");
                    continue;
                }

                FillChecksum(LOCAL_DEVICE_CHECKSUM_MAGIC, msg, sizeof(UDPMessage) - 1);
                if (write(sock, &LOCAL_MAGIC_BYTES, sizeof(LOCAL_MAGIC_BYTES)) != sizeof(LOCAL_MAGIC_BYTES) ||
                        write(sock, &msg, sizeof(UDPMessage) - 1) != sizeof(UDPMessage) - 1) {
                    //TODO: Handle?
                }
                i++;
            }
        }

        uint64_t sleep_time = 1000*1000 * PACKET_SIZE * i / target_bytes_per_sec;
        uint64_t run_time = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::chrono::microseconds::period> >(std::chrono::steady_clock::now() - start).count();
        if (run_time < sleep_time)
            std::this_thread::sleep_for(std::chrono::microseconds(sleep_time - run_time));
    }
}

static void StartLocalBackfillThread() {
    assert(LOCAL_SEND_GROUP < messageQueues.size());
    boost::thread(boost::bind(&TraceThread<boost::function<void ()> >, "udpbackfill", [] {
        while (IsInitialBlockDownload() && !send_messages_break)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));

        const CBlockIndex *lastBlock;
        {
            LOCK(cs_main);
            lastBlock = chainActive.Tip()->pprev;
            assert(lastBlock);
        }

        PerGroupMessageQueue& queue = messageQueues[LOCAL_SEND_GROUP];
        while (!send_messages_break) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            bool should_generate = false;
            {
                std::unique_lock<std::mutex> lock(queue.send_messages_mutex);
                should_generate = queue.local_send_backfill_messages.empty();
            }
            if (should_generate) {
                int height;
                {
                    LOCK(cs_main);
                    height = lastBlock->nHeight + 1;
                    lastBlock = chainActive[height];
                    if (!lastBlock || lastBlock->nHeight < chainActive.Height() - 24 * 6) {
                        height = chainActive.Height() - 24 * 6;
                        lastBlock = chainActive[height];
                    }
                }

                LogPrint(BCLog::UDPNET, "UDP: Building backfill block at height %d with hash %s\n", height, lastBlock->phashBlock->ToString());

                CBlock block;
                assert(ReadBlockFromDisk(block, lastBlock, Params().GetConsensus()));
                std::vector<UDPMessage> msgs;
                UDPFillMessagesFromBlock(block, msgs);

                std::unique_lock<std::mutex> lock(queue.send_messages_mutex);
                queue.local_send_backfill_messages = std::move(msgs);
                lock.unlock();
                queue.send_messages_wake_cv.notify_all();
            }
        }
    })).detach();
}

static std::tuple<int64_t, bool, std::string> get_local_device() {
    std::string localUDPWriteDevice(gArgs.GetArg("-fecwritedevice", ""));

    if (localUDPWriteDevice == "")
        return std::make_tuple((int64_t)0, false, std::string());

    size_t bw_end = localUDPWriteDevice.find(',');
    size_t backfill_end = localUDPWriteDevice.find(',', bw_end + 1);

    if (bw_end == std::string::npos || backfill_end == std::string::npos) {
        LogPrintf("Failed to parse -fecwritedevice=bw,backfill,file option, not writing\n");
        return std::make_tuple((int64_t)0, false, std::string());
    }

    std::string backfill_str(localUDPWriteDevice.substr(bw_end + 1, backfill_end - bw_end - 1));
    if (backfill_str != "true" && backfill_str != "false") {
        LogPrintf("-fecwritedevice=bw,backfill,file backfill option must be true or false, not writing\n");
        return std::make_tuple((int64_t)0, false, std::string());
    }

    int64_t bw = atoi64(localUDPWriteDevice.substr(0, bw_end));
    bool backfill = backfill_str == "true";
    localUDPWriteDevice = localUDPWriteDevice.substr(backfill_end + 1);

    return std::make_tuple(bw, backfill, localUDPWriteDevice);
}

static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list, const std::tuple<int64_t, bool, std::string>& local_write_device) {
    messageQueues.resize(group_list.size() + (std::get<0>(local_write_device) ? 1 : 0));
    for (size_t i = 0; i < group_list.size(); i++)
        messageQueues[i].bw = group_list[i].second;
    if (std::get<0>(local_write_device)) {
        LOCAL_SEND_GROUP = group_list.size();
        messageQueues[LOCAL_SEND_GROUP].bw = std::get<0>(local_write_device);
        last_sock_is_local = true;
    } else {
        last_sock_is_local = false;
    }
}

static void send_messages_flush_and_break() {
    send_messages_break = true;
    for (PerGroupMessageQueue& q : messageQueues)
        q.send_messages_wake_cv.notify_all();
}



/**
 * Public API follows
 */

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts()
{
    if (!gArgs.IsArgSet("-udpport")) return std::vector<std::pair<unsigned short, uint64_t> >();

    std::map<size_t, std::pair<unsigned short, uint64_t> > res;
    for (const std::string& s : gArgs.GetArgs("-udpport")) {
        size_t port_end = s.find(',');
        size_t group_end = s.find(',', port_end + 1);
        size_t bw_end = s.find(',', group_end + 1);

        if (port_end == std::string::npos || (group_end != std::string::npos && bw_end != std::string::npos)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t port = atoi64(s.substr(0, port_end));
        if (port != (unsigned short)port || port == 0) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t group = atoi64(s.substr(port_end + 1, group_end - port_end - 1));
        if (group < 0 || res.count(group)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t bw = 1024;
        if (group_end != std::string::npos) {
            bw = atoi64(s.substr(group_end + 1));
            if (bw < 0) {
                LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
                return std::vector<std::pair<unsigned short, uint64_t> >();
            }
        }

        res[group] = std::make_pair((unsigned short)port, uint64_t(bw));
    }

    std::vector<std::pair<unsigned short, uint64_t> > v;
    for (size_t i = 0; i < res.size(); i++) {
        if (!res.count(i)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }
        v.push_back(res[i]);
    }

    return v;
}

void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list) {
    connections_list.clear();
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    connections_list.reserve(mapUDPNodes.size());
    for (const auto& node : mapUDPNodes) {
        connections_list.push_back({node.first, node.second.connection.group, node.second.connection.fTrusted, (node.second.state & STATE_GOT_SYN_ACK) ? node.second.lastRecvTime : 0, {}});
        for (size_t i = 0; i < sizeof(node.second.last_pings) / sizeof(double); i++)
            if (node.second.last_pings[i] != -1)
                connections_list.back().last_pings.push_back(node.second.last_pings[i]);
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    assert(info.group < messageQueues.size() || addr == LOCAL_READ_DEVICE_SERVICE);

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    if (info.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
        maybe_have_write_nodes = true;

    bool fIsLocal = (addr == LOCAL_WRITE_DEVICE_SERVICE || addr == LOCAL_READ_DEVICE_SERVICE);

    LogPrint(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", addr.ToString());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = fIsLocal ? STATE_INIT_COMPLETE : STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = GetTimeMillis();

    if (fIsLocal) {
        for (size_t i = 0; i < sizeof(state.last_pings) / sizeof(double); i++) {
            state.last_pings[i] = 0;
        }
    }
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type};
    OpenUDPConnectionTo(addr, info);
    mapPersistentNodes[addr] = info;
}

void CloseUDPConnectionTo(const CService& addr) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapPersistentNodes.find(addr);
    if (it != mapPersistentNodes.end())
        mapPersistentNodes.erase(it);

    auto it2 = mapUDPNodes.find(addr);
    if (it2 == mapUDPNodes.end())
        return;
    DisconnectNode(it2);
}

static void OpenLocalDeviceConnection(bool fWrite) {
    const CService& service = fWrite ? LOCAL_WRITE_DEVICE_SERVICE : LOCAL_READ_DEVICE_SERVICE;
    OpenPersistentUDPConnectionTo(service, LOCAL_DEVICE_CHECKSUM_MAGIC, LOCAL_DEVICE_CHECKSUM_MAGIC, false,
            fWrite ? UDP_CONNECTION_TYPE_OUTBOUND_ONLY : UDP_CONNECTION_TYPE_INBOUND_ONLY,
            fWrite ? LOCAL_SEND_GROUP : LOCAL_RECEIVE_GROUP);
}

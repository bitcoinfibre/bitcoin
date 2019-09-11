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
#include "crypto/poly1305.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "netbase.h"
#include "primitives/block.h"
#include "util/strencodings.h"
#include "util/time.h"
#include "init.h" // for ShutdownRequested()

#include <sys/socket.h>

#include <event2/event.h>

#include <boost/thread.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <thread>

#ifndef WIN32
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#endif

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static std::vector<int> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
std::atomic<uint64_t> min_per_node_mbps(1024);

static std::map<int64_t, std::tuple<CService, uint64_t, size_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

//TODO: The checksum stuff is not endian-safe (esp the poly impl):
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));

    uint8_t key[POLY1305_KEYLEN]; // (32 bytes)
    memcpy(key,      &magic, sizeof(magic));
    memcpy(key + 8,  &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[POLY1305_TAGLEN]; // (16 bytes)
    poly1305_auth(hash, (unsigned char*)&msg.header.msg_type, length - 16, key);
    memcpy(&msg.header.chk1, hash, sizeof(msg.header.chk1));
    memcpy(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));

    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type) [i+j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }
}
static bool CheckChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type) [i+j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }

    uint8_t key[POLY1305_KEYLEN]; // (32 bytes)
    memcpy(key,      &magic, sizeof(magic));
    memcpy(key + 8,  &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[POLY1305_TAGLEN]; // (16 bytes)
    poly1305_auth(hash, (unsigned char*)&msg.header.msg_type, length - 16, key);
    return !memcmp(&msg.header.chk1, hash, sizeof(msg.header.chk1)) && !memcmp(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));
}



/**
 * Init/shutdown logic follows
 */

static struct event_base* event_base_read = NULL;
static event *timer_event;
static std::vector<event*> read_events;
static struct timeval timer_interval;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages();
static void send_messages_flush_and_break();
static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list);
static void ThreadRunWriteEventLoop() { do_send_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static boost::thread *udp_read_thread = NULL;
static std::vector<boost::thread> udp_write_threads;

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

    OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust, group);
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
    assert(GetUDPInboundPorts().size());

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

    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, NULL);
    if (!timer_event) {
        CloseSocketsAndReadEvents();
        event_base_free(event_base_read);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500*1000;
    evtimer_add(timer_event, &timer_interval);

    send_messages_init(group_list);
    udp_write_threads.emplace_back(boost::bind(&TraceThread<boost::function<void ()> >, "udpwrite", &ThreadRunWriteEventLoop));

    AddConfAddedConnections();

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

    BlockRecvShutdown();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessage(msg, sizeof(UDPMessageHeader), true, it);
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
    SendMessage(msg, sizeof(UDPMessageHeader), false, it);

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
    std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

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
    std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.find(CService(remoteaddr));
    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res))
        return;

    UDPConnectionState& state = it->second;

    const uint8_t msg_type_masked = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK);

    state.lastRecvTime = GetTimeMillis();
    if (msg_type_masked == MSG_TYPE_SYN) {
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
    } else if (msg_type_masked == MSG_TYPE_KEEPALIVE) {
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
    } else if (msg_type_masked == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToString());
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg_type_masked == MSG_TYPE_BLOCK_HEADER || msg_type_masked == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockTxMessage(msg, res, it->first, it->second, start)) {
            send_and_disconnect(it);
            return;
        }
    } else if (msg_type_masked == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
    } else if (msg_type_masked == MSG_TYPE_PONG) {
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
            SendMessage(msg, sizeof(UDPMessageHeader), false, std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second));
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {
        boost::this_thread::interruption_point();

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
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), false, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = GetRand(std::numeric_limits<uint64_t>::max());
            msg.header.msg_type = MSG_TYPE_PING;
            msg.msg.longint = htole64(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
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
#define PENDING_MESSAGES_BUFF_SIZE 8192
static std::atomic_bool send_messages_break(false);
std::mutex send_messages_mutex;
std::condition_variable send_messages_wake_cv;
struct PendingMessagesBuff {
    std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
    std::atomic<uint16_t> nextPendingMessage, nextUndefinedMessage;
    PendingMessagesBuff() : nextPendingMessage(0), nextUndefinedMessage(0) {}
};
struct MessageStateCache {
    ssize_t buff_id;
    uint16_t nextPendingMessage;
    uint16_t nextUndefinedMessage;
};
struct PerGroupMessageQueue {
    std::array<PendingMessagesBuff, 2> buffs;
    inline MessageStateCache NextBuff(std::memory_order order) {
        for (size_t i = 0; i < buffs.size(); i++) {
            uint16_t next_undefined_message = buffs[i].nextUndefinedMessage.load(order);
            uint16_t next_pending_message = buffs[i].nextPendingMessage.load(order);
            if (next_undefined_message != next_pending_message)
                return {(ssize_t)i, next_pending_message, next_undefined_message};
        }
        return {-1, 0, 0};
    }
    uint64_t bw;
    PerGroupMessageQueue() : bw(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) =delete;
};
static std::vector<PerGroupMessageQueue> messageQueues;

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group) {
    assert(length <= sizeof(UDPMessage));
    assert(group < messageQueues.size());
    PerGroupMessageQueue& queue = messageQueues[group];
    PendingMessagesBuff& buff = high_prio ? queue.buffs[0] : queue.buffs[1];

    std::unique_lock<std::mutex> lock(send_messages_mutex);
    const uint16_t next_undefined_message_cache = buff.nextUndefinedMessage.load(std::memory_order_acquire);
    const uint16_t next_pending_message_cache = buff.nextPendingMessage.load(std::memory_order_acquire);
    if (next_pending_message_cache == (next_undefined_message_cache + 1) % PENDING_MESSAGES_BUFF_SIZE)
        return;

    std::tuple<CService, UDPMessage, unsigned int, uint64_t>& new_msg = buff.messagesPendingRingBuff[next_undefined_message_cache];
    std::get<0>(new_msg) = service;
    memcpy(&std::get<1>(new_msg), &msg, length);
    std::get<2>(new_msg) = length;
    std::get<3>(new_msg) = magic;

    bool need_notify = next_undefined_message_cache == next_pending_message_cache;
    buff.nextUndefinedMessage.store((next_undefined_message_cache + 1) % PENDING_MESSAGES_BUFF_SIZE, std::memory_order_release);

    lock.unlock();
    if (need_notify)
        send_messages_wake_cv.notify_all();
}
void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::map<CService, UDPConnectionState>::const_iterator& node) {
    SendMessage(msg, length, high_prio, node->first, node->second.connection.remote_magic, node->second.connection.group);
}

struct PerQueueSendState {
    MessageStateCache buff_state;
    std::chrono::steady_clock::time_point next_send;
    size_t write_objs_per_call, bytes_per_obj, target_bytes_per_sec;
    bool buff_emptied;
};

static inline bool fill_cache(PerQueueSendState* states, std::chrono::steady_clock::time_point& now) {
    bool have_work = false;
    for (size_t i = 0; i < messageQueues.size(); i++) {
        if (states[i].next_send > now)
            continue;

        states[i].buff_state = messageQueues[i].NextBuff(std::memory_order_acquire);
        if (states[i].buff_state.buff_id != -1) {
            have_work = true;
            break;
        }
    }
    return have_work;
}

static void do_send_messages() {
#ifndef WIN32
    {
        struct sched_param sched{sched_get_priority_max(SCHED_RR)};
        int res = pthread_setschedparam(pthread_self(), SCHED_RR, &sched);
        LogPrintf("UDP: %s write thread priority to SCHED_RR%s\n", !res ? "Set" : "Was unable to set", !res ? "" : (res == EPERM ? " (permission denied)" : " (other error)"));
        if (res) {
            res = nice(-20);
            errno = 0;
            LogPrintf("UDP: %s write thread nice value to %d%s\n", !errno ? "Set" : "Was unable to set", res, !errno ? "" : (errno == EPERM ? " (permission denied)" : " (other error)"));
        }
    }
#endif

    static const size_t WRITES_PER_SEC = 1000;

    PerQueueSendState* states = (PerQueueSendState*)alloca(sizeof(PerQueueSendState) * messageQueues.size());
    for (size_t i = 0; i < messageQueues.size(); i++) {
        states[i].buff_state           = {-1, 0, 0};
        states[i].next_send            = std::chrono::steady_clock::now();
        states[i].target_bytes_per_sec = messageQueues[i].bw * 1024 * 1024 / 8;
        states[i].bytes_per_obj        = PACKET_SIZE;
        states[i].write_objs_per_call  = std::max<size_t>(1, states[i].target_bytes_per_sec / WRITES_PER_SEC / states[i].bytes_per_obj / messageQueues.size());
        states[i].buff_emptied         = true;
    }

    while (true) {
        std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());
        if (send_messages_break)
            return;
        std::chrono::steady_clock::time_point sleep_until(start + std::chrono::minutes(60));

        for (size_t group = 0; group < messageQueues.size(); group++) {
            PerQueueSendState& send_state = states[group];
            if (send_state.next_send > start) {
                sleep_until = std::min(sleep_until, send_state.next_send);
                continue;
            }

            size_t extra_writes = 0;
            if (!send_state.buff_emptied) {
                static_assert(std::is_same<std::chrono::steady_clock::time_point::period, std::nano>::value, "Better to math you with");
                extra_writes = std::chrono::nanoseconds(start - send_state.next_send).count() * WRITES_PER_SEC * send_state.write_objs_per_call / std::nano::den;
            }

            if (send_state.buff_state.buff_id == -1 || // Skip if we got filled in in the locked check...
                    send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage || // ...or we're out of known messages
                    send_state.buff_state.buff_id == 0) // ...or we want to check for availability in a higher-priority buffer
                send_state.buff_state = messageQueues[group].NextBuff(std::memory_order_acquire);
            if (send_state.buff_state.buff_id == -1) {
                send_state.buff_emptied = true;
                continue;
            }

            PendingMessagesBuff* buff = &messageQueues[group].buffs[send_state.buff_state.buff_id];
            size_t i = 0;
            for (; i < send_state.write_objs_per_call + extra_writes && send_state.buff_state.buff_id != -1; i++) {
                std::tuple<CService, UDPMessage, unsigned int, uint64_t>& msg = buff->messagesPendingRingBuff[send_state.buff_state.nextPendingMessage];

                FillChecksum(std::get<3>(msg), std::get<1>(msg), std::get<2>(msg));
                if (std::get<0>(msg).IsIPv6()) {
                    sockaddr_in6 remoteaddr;
                    memset(&remoteaddr, 0, sizeof(remoteaddr));
                    remoteaddr.sin6_family = AF_INET6;
                    assert(std::get<0>(msg).GetIn6Addr(&remoteaddr.sin6_addr));
                    remoteaddr.sin6_port = htons(std::get<0>(msg).GetPort());

                    if (sendto(udp_socks[group], &std::get<1>(msg), std::get<2>(msg), 0, (sockaddr*)&remoteaddr, sizeof(remoteaddr)) != std::get<2>(msg)) {
                        //TODO: Handle?
                    }
                } else {
                    sockaddr_in remoteaddr;
                    memset(&remoteaddr, 0, sizeof(remoteaddr));
                    remoteaddr.sin_family = AF_INET;
                    assert(std::get<0>(msg).GetInAddr(&remoteaddr.sin_addr));
                    remoteaddr.sin_port = htons(std::get<0>(msg).GetPort());

                    if (sendto(udp_socks[group], &std::get<1>(msg), std::get<2>(msg), 0, (sockaddr*)&remoteaddr, sizeof(remoteaddr)) != std::get<2>(msg)) {
                        //TODO: Handle?
                    }
                }

                send_state.buff_state.nextPendingMessage = (send_state.buff_state.nextPendingMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;
                if (send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage) {
                    buff->nextPendingMessage.store(send_state.buff_state.nextPendingMessage, std::memory_order_release);
                    send_state.buff_state = messageQueues[group].NextBuff(std::memory_order_acquire);
                    if (send_state.buff_state.buff_id != -1)
                        buff = &messageQueues[group].buffs[send_state.buff_state.buff_id];
                }
            }
            if (send_state.buff_state.buff_id != -1)
                buff->nextPendingMessage.store(send_state.buff_state.nextPendingMessage, std::memory_order_release);
            size_t non_extra_messages_sent = std::max<ssize_t>(std::min(i, send_state.write_objs_per_call), ssize_t(i) - extra_writes);
            send_state.next_send = start + std::chrono::nanoseconds(1000ULL*1000*1000 * send_state.bytes_per_obj * non_extra_messages_sent / send_state.target_bytes_per_sec);
            send_state.buff_emptied = false;
            sleep_until = std::min(sleep_until, send_state.next_send);
        }

        std::chrono::steady_clock::time_point end(std::chrono::steady_clock::now());
        if (sleep_until > end) { // No need to be aggressive here, fill_cache is useful to speed up per-queue loop anyway
            if (fill_cache(states, end))
                continue;
            std::unique_lock<std::mutex> lock(send_messages_mutex);
            if (!fill_cache(states, end))
                send_messages_wake_cv.wait_until(lock, sleep_until);
        }
    }
}

static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list) {
    messageQueues = std::vector<PerGroupMessageQueue>(group_list.size());
    for (size_t i = 0; i < group_list.size(); i++)
        messageQueues[i].bw = group_list[i].second;
}

static void send_messages_flush_and_break() {
    send_messages_break = true;
    send_messages_wake_cv.notify_all();
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
    assert(info.group < GetUDPInboundPorts().size());

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    LogPrint(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", addr.ToString());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = GetTimeMillis();

    size_t group_count = 0;
    for (const auto& it : mapUDPNodes)
        if (it.second.connection.group == info.group)
            group_count++;
    min_per_node_mbps = std::min(min_per_node_mbps.load(), messageQueues[info.group].bw / group_count);
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, size_t group) {
    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, size_t group) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted};
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

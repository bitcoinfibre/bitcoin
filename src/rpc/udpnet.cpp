// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "rpc/server.h"
#include "rpc/util.h"

#include "hash.h"
#include "util/strencodings.h"
#include "udpapi.h"
#include "netbase.h"

#include <univalue.h>

using namespace std;

UniValue getudppeerinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getudppeerinfo",
                "\nReturns data about each connected UDP peer as a json array of objects.\n",
                {},
                RPCResult{
                    "[\n"
                    "  {\n"
                    "    \"addr\":\"host:port\",        (string)  The ip address and port of the peer\n"
                    "    \"group\": nnn                 (numeric) The group this peer belongs to\n"
                    "    \"lastrecv\": ttt,             (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
                    "    \"ultimatetrust\": true/false  (boolean) Whether this peer, and all of its peers, are trusted\n"
                    "    \"min_recent_rtt\": nnn        (numeric) The minimum RTT among recent pings (in ms)\n"
                    "    \"max_recent_rtt\": nnn        (numeric) The maximum RTT among recent pings (in ms)\n"
                    "    \"avg_recent_rtt\": nnn        (numeric) The average RTT among recent pings (in ms)\n"
                    "  }\n"
                    "  ,...\n"
                    "]\n"
                },
                RPCExamples{
                    HelpExampleCli("getudppeerinfo", "")
                  + HelpExampleRpc("getudppeerinfo", "")
                },
            }.Check(request);

    vector<UDPConnectionStats> vstats;
    GetUDPConnectionList(vstats);

    UniValue ret(UniValue::VARR);

    for (const UDPConnectionStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("addr", stats.remote_addr.ToString());
        obj.pushKV("group", stats.group);
        obj.pushKV("lastrecv", stats.lastRecvTime);
        obj.pushKV("ultimatetrust", stats.fUltimatelyTrusted);

        double min = 1000000, max = 0, total = 0;

        for (double rtt : stats.last_pings) {
            min = std::min(rtt, min);
            max = std::max(rtt, max);
            total += rtt;
        }

        obj.pushKV("min_recent_rtt", min);
        obj.pushKV("max_recent_rtt", max);
        obj.pushKV("avg_recent_rtt", stats.last_pings.size() == 0 ? 0 : total / stats.last_pings.size());

        ret.push_back(obj);
    }

    return ret;
}

UniValue addudpnode(const JSONRPCRequest& request)
{
    string strCommand;
    if (request.params.size() >= 5)
        strCommand = request.params[4].get_str();
    if (request.fHelp || request.params.size() > 7 || request.params.size() < 5 ||
        (strCommand != "onetry" && strCommand != "add")) {
        throw runtime_error(
            RPCHelpMan{"addudpnode",
                "\nAttempts add a node to the UDP addnode list.\n"
                "Or try a connection to a UDP node once.\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
                    {"local_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "Our magic secret value for this connection (should be a secure, random string)"},
                    {"remote_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "The node's magic secret value (should be a secure, random string)"},
                    {"ultimately_trusted", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to trust this peer, and all of its trusted UDP peers, recursively"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add a persistent connection or 'onetry' to try a connection to the node once"},
                    {"group", RPCArg::Type::NUM, /* default */ "0", "The group this peer shall belong to, defaults to 0"},
                    {"type", RPCArg::Type::STR, /* default */ "bidirectional", "May be one of 'bidirectional', 'inbound_only' or 'I_certify_remote_is_listening_and_not_a_DoS_target_outbound_only'"},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
                  + HelpExampleRpc("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
                },
            }.ToString());
    }

    string strNode = request.params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    string local_pass = request.params[1].get_str();
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);
    string remote_pass = request.params[2].get_str();
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    bool fTrust = request.params[3].get_bool();

    size_t group = 0;
    if (request.params.size() >= 6)
        group = request.params[5].get_int64();
    if (group > GetUDPInboundPorts().size())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Group out of range or UDP port not bound");

    UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL;
    if (request.params.size() >= 7) {
        if (request.params[6].get_str() == "inbound_only")
            connection_type = UDP_CONNECTION_TYPE_INBOUND_ONLY;
        else if (request.params[6].get_str() == "I_certify_remote_is_listening_and_not_a_DoS_target_oubound_only")
            connection_type = UDP_CONNECTION_TYPE_OUTBOUND_ONLY;
        else if (request.params[6].get_str() != "bidirectional")
            throw JSONRPCError(RPC_INVALID_PARAMS, "Bad argument for connection type");
    }

    if (strCommand == "onetry")
        OpenUDPConnectionTo(addr, local_magic, remote_magic, fTrust, connection_type, group);
    else if (strCommand == "add")
        OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust, connection_type, group);

    return NullUniValue;
}

UniValue disconnectudpnode(const JSONRPCRequest& request)
{
            RPCHelpMan{"disconnectudpnode",
                "\nDisconnects a connected UDP node.\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("disconnectudpnode", "\"192.168.0.6:8333\"")
                  + HelpExampleRpc("disconnectudpnode", "\"192.168.0.6:8333\"")
                },
            }.Check(request);

    string strNode = request.params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    CloseUDPConnectionTo(addr);

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "udpnetwork",         "getudppeerinfo",         &getudppeerinfo,         {} },
    { "udpnetwork",         "addudpnode",             &addudpnode,             {"node", "local_magic", "remote_magic", "ultimately_trusted", "command", "group"} },
    { "udpnetwork",         "disconnectudpnode",      &disconnectudpnode,      {"node"} },
};

void RegisterUDPNetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

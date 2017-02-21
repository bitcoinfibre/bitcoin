// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "rpc/server.h"

#include "hash.h"
#include "utilstrencodings.h"
#include "udpapi.h"
#include "netbase.h"

#include <univalue.h>

using namespace std;

UniValue getudppeerinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getudppeerinfo\n"
            "\nReturns data about each connected UDP peer as a json array of objects.\n"
            "\nResult:\n"
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
            "\nExamples:\n"
            + HelpExampleCli("getudppeerinfo", "")
            + HelpExampleRpc("getudppeerinfo", "")
        );

    vector<UDPConnectionStats> vstats;
    GetUDPConnectionList(vstats);

    UniValue ret(UniValue::VARR);

    for (const UDPConnectionStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("addr", stats.remote_addr.ToString()));
        obj.push_back(Pair("group", stats.group));
        obj.push_back(Pair("lastrecv", stats.lastRecvTime));
        obj.push_back(Pair("ultimatetrust", stats.fUltimatelyTrusted));

        double min = 1000000, max = 0, total = 0;

        for (double rtt : stats.last_pings) {
            min = std::min(rtt, min);
            max = std::max(rtt, max);
            total += rtt;
        }

        obj.push_back(Pair("min_recent_rtt", min));
        obj.push_back(Pair("max_recent_rtt", max));
        obj.push_back(Pair("avg_recent_rtt", stats.last_pings.size() == 0 ? 0 : total / stats.last_pings.size()));

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
        (strCommand != "onetry" && strCommand != "add"))
        throw runtime_error(
            "addudpnode \"node\" \"local_magic\" \"remote_magic\" ultimately_trusted \"add|onetry\" group\n"
            "\nAttempts add a node to the UDP addnode list.\n"
            "Or try a connection to a UDP node once.\n"
            "\nArguments:\n"
            "1. \"node\"                (string, required)  The node IP:port\n"
            "2. \"local_magic\"         (string, required)  Our magic secret value for this connection (should be a secure, random string)\n"
            "3. \"remote_magic\"        (string, required)  The node's magic secret value (should be a secure, random string)\n"
            "4. \"ultimately_trusted\"  (boolean, required) Whether to trust this peer, and all of its trusted UDP peers, recursively\n"
            "5. \"command\"             (string, required)  'add' to add a persistent connection or 'onetry' to try a connection to the node once\n"
            "6. \"group\"               (numeric, optional) The group this peer shall belong to, defaults to 0\n"
            "7. \"type\"                (string, optional)  May be one of 'bidirectional', 'inbound_only' or 'I_certify_remote_is_listening_and_not_a_DoS_target_outbound_only'.\n"
            "\nExamples:\n"
            + HelpExampleCli("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
            + HelpExampleRpc("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
        );

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
    string strCommand;
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "disconnectudpnode \"node\"\n"
            "\nDisconnects a connected UDP node.\n"
            "\nArguments:\n"
            "1. \"node\"                (string, required)  The node IP:port\n"
            "\nExamples:\n"
            + HelpExampleCli("disconnectudpnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("disconnectudpnode", "\"192.168.0.6:8333\"")
        );

    string strNode = request.params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    CloseUDPConnectionTo(addr);

    return NullUniValue;
}





static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "udpnetwork",         "getudppeerinfo",         &getudppeerinfo,         true,  {} },
    { "udpnetwork",         "addudpnode",             &addudpnode,             true,  {"node", "local_magic", "remote_magic", "ultimately_trusted", "command", "group"} },
    { "udpnetwork",         "disconnectudpnode",      &disconnectudpnode,      true,  {"node"} },
};

void RegisterUDPNetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
void
SimpleRouter::processARPPkt(const arp_hdr *arpHdr, const Interface *inface) {
    //Actually we don't need to check this, because the mac has been checked before that
    if (arpHdr->arp_tip != inface->ip) {
        return;
    } 
    auto op_code = ntohs(arpHdr->arp_op);
    if (op_code == arp_op_request) {
        std::cerr << "Now sending a arp reply..." << std::endl;

        Buffer replyPkt(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        //ethernet_hdr
        ethernet_hdr replyEthHdr{};
        std::memcpy(replyEthHdr.ether_shost, inface->addr.data(), ETHER_ADDR_LEN);
        std::memcpy(replyEthHdr.ether_dhost, arpHdr->arp_sha, ETHER_ADDR_LEN);
        replyEthHdr.ether_type = htons(ethertype_arp);
        // arp_hdr
        arp_hdr reply_arp_hdr{
                .arp_hrd = htons(arp_hrd_ethernet),
                .arp_pro = htons(ethertype_ip),
                .arp_hln = ETHER_ADDR_LEN,
                .arp_pln = 4,
                .arp_op = htons(arp_op_reply),
        };
        std::memcpy(reply_arp_hdr.arp_sha, inface->addr.data(), ETHER_ADDR_LEN);
        reply_arp_hdr.arp_sip = inface->ip;
        std::memcpy(reply_arp_hdr.arp_tha, arpHdr->arp_sha, ETHER_ADDR_LEN);
        reply_arp_hdr.arp_tip = arpHdr->arp_sip;

        std::memcpy(replyPkt.data(), &replyEthHdr, sizeof(ethernet_hdr));
        std::memcpy(replyPkt.data() + sizeof(ethernet_hdr), &reply_arp_hdr, sizeof(arp_hdr));

        sendPacket(replyPkt, inface->name);
//            print_hdrs(replyPkt);

        // In fact, when receiving this arp request, the mapping of mac and ip should also be added to the cache
//            Buffer mac(ETHER_ADDR_LEN);
//            std::memcpy(mac.data(), arpHdr->arp_sha, ETHER_ADDR_LEN);
//            auto req = m_arp.insertArpEntry(mac, arpHdr->arp_sip);
    } else if (op_code == arp_op_reply) {
        std::cerr << "Now handling a arp reply..." << std::endl;

        // Store the mapping of mac and ip
        Buffer mac(ETHER_ADDR_LEN);
        std::memcpy(mac.data(), arpHdr->arp_sha, ETHER_ADDR_LEN);
        auto req = m_arp.insertArpEntry(mac, arpHdr->arp_sip);

        // Check if there are waiting packages
        if (req == nullptr) {
            return;
        }

        // Send all pending packets on the req->packets linked list
        for (auto &packet : req->packets) {
            ethernet_hdr tmp{};
            std::memcpy(&tmp, packet.packet.data(), sizeof(ethernet_hdr));
            // Reset ethernet_hdr
            // the dest is the source, the source is the target
            memcpy(tmp.ether_dhost, arpHdr->arp_sha, ETHER_ADDR_LEN);
            memcpy(tmp.ether_shost, arpHdr->arp_tha, ETHER_ADDR_LEN);

            std::memcpy(packet.packet.data(), &tmp, sizeof(ethernet_hdr));
            sendPacket(packet.packet, packet.iface);
        }
        // Remove all queued requests
        m_arp.removeRequest(req);
    }
}

uint32_t
SimpleRouter::find_ex_ip(uint32_t in_ip) {
    for (const auto &iface : m_ifaces) {
        auto route = m_routingTable.lookup(iface.ip);
        // This is a default route
        // Use the unused interface as external ip
        if (route.dest == 0) {
            return iface.ip;
        }
    }

    for (const auto &iface : m_ifaces) {
        auto route = m_routingTable.lookup(iface.ip);
        // Choose an interface at will
        if (route.dest != in_ip && route.gw != in_ip) {
            return iface.ip;
        }
    }
    return 0;
}


void
SimpleRouter::processIPPkt(const Buffer &packet, const std::string &inface, int nat_flag) {
    //check length
    if (packet.size() - sizeof(ethernet_hdr) < sizeof(ip_hdr)) {
        std::cerr << "Error length and ignore it" << std::endl;
        return;
    }

    //check cksum
    ip_hdr ip_header{};
    std::memcpy(&ip_header, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
    if (cksum(&ip_header, sizeof(ip_hdr)) != 0xffff) {
        std::cerr << "Error checksum and ignore it" << std::endl;
        return;
    }

    // NAT
    // Convert internal ip to external ip. Convert external ip to internal ip
    uint32_t dest_ip = ip_header.ip_dst;
    bool nat_modify = false;
    if (nat_flag == 1) {
        auto *in_iface = findIfaceByName(inface);
        auto ip_h = (ip_hdr *) (packet.data() + sizeof(ethernet_hdr));
        auto icmp_header = (icmp_hdr *) (packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        auto id = icmp_header->icmp_id;
        uint32_t in_ip=0, ex_ip=0;
        // to find the nat entry
        auto nat_entry = m_natTable.lookup(id);
        if (nat_entry != nullptr) {
            in_ip = nat_entry->internal_ip;
            ex_ip = nat_entry->external_ip;
            nat_entry->timeUsed = steady_clock::now();
        }
        // Out of NAT
        if (icmp_header->icmp_type == 8) {
            printIfaces(std::cerr);
            if (nat_entry == nullptr) {
                in_ip = in_iface->ip;
                // Find a suitable external interface and ip
                ex_ip = find_ex_ip(in_ip);
                if (ex_ip == 0) {
                    std::cerr << "!!!!!There is no suitable interface for external ip!!!!" << std::endl;
                    return;
                } else {
                    std::cerr << "find ex_ip: " << ipToString(ex_ip) << std::endl;
                }
            }
            // receives from the client (10.0.1.100) through the internal interface (10.0.1.1),
            // change the source IP address in the IP header to the external interface address (172.32.10.1)
//                if(ex_ip != ip_h->ip_dst){
            if(findIfaceByIp(ip_h->ip_dst) == nullptr){
                // insert the external ip and the internal ip or update the time
                m_natTable.insertNatEntry(id, in_ip, ex_ip);
                ip_h->ip_src = ex_ip;
                nat_modify = true;
            }

        } else if (nat_entry != nullptr) {
            // icmp reply and with the nat id(key)
            // In this case, the destination IP address should be
            // changed from 172.32.10.1 to 10.0.1.1, so that the client can receive the PING responses.
            ip_h->ip_dst = in_ip;
            nat_modify = true;
            // changed from 172.32.10.1 to 10.0.1.1, so that the client can receive the PING responses.
            auto route = m_routingTable.lookup(in_ip);
            ip_h->ip_dst = route.gw;
        }
        std::cerr << "in_ip: " << ipToString(in_ip) << std::endl;
        std::cerr << "ex_ip: " << ipToString(ex_ip) << std::endl;
        dest_ip = ip_h->ip_dst;
        std::cerr << std::endl;
        std::cerr << "After NAT: " << std::endl;
//            print_hdrs(packet);
    }


    // Your router should classify datagrams into (1) destined to the router (to one of
    // the IP addresses of the router), and (2) datagrams to be forwarded:
    const Interface *dst_iface = findIfaceByIp(dest_ip);
    // to one of the IP addresses of the router
    if (dst_iface && !nat_modify) {
        //  For (1), if the packet carries ICMP payload, it should be properly
        //  dispatched. Otherwise, discarded.
        std::cerr << "get the ICMP for this router" << std::endl;
        auto *icmpH = (icmp_hdr *) (packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        // 8: echo message
        // 0: echo reply message (Because the router will not actively ping, it cannot be 0)
        if (icmpH->icmp_type != 8) {
            std::cerr << "icmp_type is :" << icmpH->icmp_type << std::endl;
//                print_hdrs(packet);
            return;
        }
        sendICMPReply(packet, inface);
    } else {
        std::cerr << "Now forwarding" << std::endl;
        // For (2), your router should use the longest prefix match algorithm to find a
        // next-hop IP address in the routing table and attempt to forward it there

        // Your router should discard the packet if TTL equals 0 after decrementing it.
        if (ip_header.ip_ttl - 1 <= 0) {
            return;
        }
        Buffer forward_pkt(packet.size());
        std::memcpy(forward_pkt.data(), packet.data(), packet.size());

        forwardIPPkt(forward_pkt);
    }
}

void
SimpleRouter::sendICMPReply(const Buffer &requestPacket, const std::string &inface) {
    std::cerr << "Sending icmp Echo Reply" << std::endl;

    auto iface = findIfaceByName(inface);
    //the header information of request packet
    Buffer replyPkt(requestPacket.size());
    memcpy(replyPkt.data(), requestPacket.data(), requestPacket.size());

    // Set the ethernet hdr
    auto *req_eth_hdr = (ethernet_hdr *) (requestPacket.data());
    ethernet_hdr reply_eth_hdr{};
    memcpy(reply_eth_hdr.ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
    reply_eth_hdr.ether_type = req_eth_hdr->ether_type;
    memcpy(replyPkt.data(), &reply_eth_hdr, sizeof(ethernet_hdr));

    // Set the ip header
    auto *req_ip_hdr = (ip_hdr *) ((uint8_t *) requestPacket.data() + sizeof(ethernet_hdr));
    req_ip_hdr->ip_len = htons(requestPacket.size() - (sizeof(ethernet_hdr)));
    req_ip_hdr->ip_ttl = 64;
    req_ip_hdr->ip_p = ip_protocol_icmp;
    uint32_t tmp = req_ip_hdr->ip_dst;
    req_ip_hdr->ip_dst = req_ip_hdr->ip_src;
    req_ip_hdr->ip_src = tmp;
    req_ip_hdr->ip_sum = 0;
    req_ip_hdr->ip_sum = cksum((const void *) req_ip_hdr, sizeof(ip_hdr));
    memcpy(replyPkt.data() + sizeof(ethernet_hdr), req_ip_hdr, sizeof(ip_hdr));

    // Set the icmp header
    auto *req_icmp_hdr = (icmp_hdr *) ((uint8_t *) requestPacket.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
    icmp_hdr reply_icmp_hdr{
            .icmp_type = 0,   // 0: reply
            .icmp_code = 0,
            .icmp_sum = 0,
            .icmp_id = req_icmp_hdr->icmp_id,
            .icmp_seq = req_icmp_hdr->icmp_seq
    };
    reply_icmp_hdr.icmp_sum = cksum((const void *) &reply_icmp_hdr,
                                    requestPacket.size() - (sizeof(ethernet_hdr)) - (sizeof(ip_hdr)));
    memcpy(replyPkt.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), &reply_icmp_hdr, sizeof(icmp_hdr));

    // Setting the head is complete
    // Steps to send
    auto nextHop = m_routingTable.lookup(req_ip_hdr->ip_dst);
    if (m_arp.lookup(nextHop.gw) == nullptr) {
        // no arp
        std::cerr << "No mapping between ip: " << req_ip_hdr->ip_dst <<
                  " and its MAC.\nBegin to request" << std::endl;
        m_arp.queueRequest(req_ip_hdr->ip_dst, replyPkt, iface->name);
        m_arp.periodicCheckArpRequestsAndCacheEntries();
        return;
    }
    sendPacket(replyPkt, iface->name);
    std::cerr << "Reply ICMP OK" << std::endl;
}

int
SimpleRouter::forwardIPPkt(Buffer &packet) {
    // Modify ip header
    auto *ip_headr = (struct ip_hdr *) (packet.data() + sizeof(ethernet_hdr));
    ip_headr->ip_ttl -= 1;
    ip_headr->ip_sum = 0;
    ip_headr->ip_sum = cksum((const void *) ip_headr, sizeof(ip_hdr));
    RoutingTableEntry route_entry = m_routingTable.lookup(ip_headr->ip_dst);

    // Find the outgoing interface
    auto *out_iface = findIfaceByName(route_entry.ifName);
    if (out_iface == nullptr) {
        std::cerr << "No outgoing interface." << std::endl;
        return -1;
    }

    //Modify the ethernet header
    auto eth_headr = (struct ethernet_hdr *) (packet.data());
    std::memcpy(eth_headr->ether_shost, out_iface->addr.data(), ETHER_ADDR_LEN);
    eth_headr->ether_type = htons(ethertype_ip);

    auto next_iface = m_arp.lookup(route_entry.gw);
    if (next_iface == nullptr) // Did not find IP-MAC mapping in arp cache
    {
        auto req = m_arp.queueRequest(ip_headr->ip_dst, packet, out_iface->name);
        req->nTimesSent = 0;
        // Send out arp request
        // Now it’s okay not to send arp, because the timer will send arp every second
        // But the value of the first RTT will be large (maybe > 1000ms).
        // should lock, but it's private
        m_arp.periodicCheckArpRequestsAndCacheEntries();
        return -1;
    }

    std::memcpy(eth_headr->ether_dhost, next_iface->mac.data(), ETHER_ADDR_LEN);

    std::cerr << "Forwarded packet: " << std::endl;
//        print_hdrs(packet);
    sendPacket(packet, out_iface->name);
    std::cerr << "Forwarded the packet to " << out_iface->name << std::endl;
    return 0;
}

// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface, int nat_flag) {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN
    std::cerr << "-----------packet information begin----------------" << std::endl;
//        print_hdrs(packet);

    // not NAT
    // get the ethernet headers.
    auto *ethHdr = (ethernet_hdr *) (packet.data());

    Buffer destMacAddr(ETHER_ADDR_LEN);
    std::memcpy(destMacAddr.data(), ethHdr->ether_dhost, ETHER_ADDR_LEN);
    std::string destMacAddrStr = macToString(destMacAddr);

    // Check if the dest mac is correct
    if (destMacAddrStr != "ff:ff:ff:ff:ff:ff" && destMacAddrStr != macToString(iface->addr)) {
        return;
    }
    //  the router must ignore Ethernet frames other than ARP and IPv4.
    auto eth_type = ntohs(ethHdr->ether_type);
    if (eth_type == ethertype_arp) // process arp packet
    {
        std::cerr << "Received an ARP packet" << std::endl;
        // Packet length error
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) {
            return;
        }
        auto arpHdr = (arp_hdr *) (packet.data() + sizeof(ethernet_hdr));
        processARPPkt(arpHdr, iface);
    } else if (eth_type == ethertype_ip) { // process IP packet
        std::cerr << "Received an IP packet" << std::endl;
        processIPPkt(packet, inIface, nat_flag);
    }
    std::cerr << "-----------packet information end----------------" << std::endl << std::endl;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
  , m_natTable(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {

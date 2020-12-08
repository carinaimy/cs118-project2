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


// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface, int nat_flag)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

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

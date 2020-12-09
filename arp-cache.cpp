/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// IMPLEMENT THIS METHOD
    void
    ArpCache::periodicCheckArpRequestsAndCacheEntries() {
        // FILL THIS IN
        //  for each request in queued requests
        for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); it++) {
            // handleRequest(request)
            time_point current = steady_clock::now();
            auto req = *it;
            //  or the request has been sent out at least 5 times.
            if (req->nTimesSent >= MAX_SENT_TIME) {
                m_arpRequests.remove(req);
                it--;
                continue;
            }

            if(current - req->timeSent < seconds(ARP_INTERVAL_SEC)){
                continue;
            }

            // The router should send an ARP request about once a second
            // until an ARP reply comes back
            req->nTimesSent += 1;

            // Search interface to send req
            // Map ip to mac
            auto route = m_router.getRoutingTable().lookup(req->ip);
            auto outIface = m_router.findIfaceByName(route.ifName);
            if (outIface == nullptr) {
                std::cerr << "out interface error." << std::endl;
                continue;
            }

            // the ethernet header of the arp request
            ethernet_hdr ethernetHdr{};
            // broadcast
            std::memset(ethernetHdr.ether_dhost, 255, ETHER_ADDR_LEN);
            std::memcpy(ethernetHdr.ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
            //only dispatch Ethernet frames (their payload) carrying ARP and IPv4 packets.
            ethernetHdr.ether_type = htons(ethertype_arp);

            // the arp header of the arp request
            arp_hdr arpHdr{};
            arpHdr.arp_hrd = htons(arp_hrd_ethernet);
            arpHdr.arp_pro = htons(ethertype_ip);
            //number of octets in the specified hardware address. Ethernet has
            //6-octet addresses, so 0x06.
            arpHdr.arp_hln = 0x06;
            //number of octets in the requested network address. IPv4 has
            //4-octet addresses, so 0x04.
            arpHdr.arp_pln = 0x04;
            // ARP request
            arpHdr.arp_op = htons(arp_op_request);
            std::memcpy(arpHdr.arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
            arpHdr.arp_sip = outIface->ip;
            std::memset(arpHdr.arp_tha, 0, ETHER_ADDR_LEN);
            arpHdr.arp_tip = req->ip;

            // push the data of headers to buffer
            Buffer buffer(sizeof(ethernetHdr) + sizeof(arpHdr));
            std::memcpy(buffer.data(), &ethernetHdr, sizeof(ethernetHdr));
            std::memcpy(buffer.data() + sizeof(ethernetHdr), &arpHdr, sizeof(arpHdr));

            // broadcast arp request
            std::cerr << "Send arp request to " << outIface->name << "..." << std::endl;
            m_router.sendPacket(buffer, outIface->name);
            // update the time sent
            req->timeSent = steady_clock::now();
        }

        //for each cache entry in entries:
        for(auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); it++){
            if(!(*it)->isValid){
                it = m_cacheEntries.erase(it);
                it--;
            }
        }

    }
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

    ArpCache::ArpCache(SimpleRouter &router)
            : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this)) {
    }

    ArpCache::~ArpCache() {
        m_shouldStop = true;
        m_tickerThread.join();
    }

    std::shared_ptr<ArpEntry>
    ArpCache::lookup(uint32_t ip) {
        std::lock_guard<std::mutex> lock(m_mutex);

        for (const auto &entry : m_cacheEntries) {
            if (entry->isValid && entry->ip == ip) {
                return entry;
            }
        }

        return nullptr;
    }

    std::shared_ptr<ArpRequest>
    ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request) {
                                        return (request->ip == ip);
                                    });

        if (request == m_arpRequests.end()) {
            request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
        }

        (*request)->packets.push_back({packet, iface});
        return *request;
    }

    void
    ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_arpRequests.remove(entry);
    }

    std::shared_ptr<ArpRequest>
    ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto entry = std::make_shared<ArpEntry>();
        entry->mac = mac;
        entry->ip = ip;
        entry->timeAdded = steady_clock::now();
        entry->isValid = true;
        m_cacheEntries.push_back(entry);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request) {
                                        return (request->ip == ip);
                                    });
        if (request != m_arpRequests.end()) {
            return *request;
        } else {
            return nullptr;
        }
    }

    void
    ArpCache::clear() {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_cacheEntries.clear();
        m_arpRequests.clear();
    }

    void
    ArpCache::ticker() {
        while (!m_shouldStop) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            {
                std::lock_guard<std::mutex> lock(m_mutex);

                auto now = steady_clock::now();

                for (auto &entry : m_cacheEntries) {
                    if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
                        entry->isValid = false;
                    }
                }

                periodicCheckArpRequestsAndCacheEntries();
            }
        }
    }

    std::ostream &
    operator<<(std::ostream &os, const ArpCache &cache) {
        std::lock_guard<std::mutex> lock(cache.m_mutex);

        os << "\nMAC            IP         AGE                       VALID\n"
           << "-----------------------------------------------------------\n";

        auto now = steady_clock::now();
        for (const auto &entry : cache.m_cacheEntries) {

            os << macToString(entry->mac) << "   "
               << ipToString(entry->ip) << "   "
               << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
               << entry->isValid
               << "\n";
        }
        os << std::endl;
        return os;
    }

} // namespace simple_router

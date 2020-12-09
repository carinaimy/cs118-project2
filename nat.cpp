#include "nat.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THESE METHODS
    void
    NatTable::checkNatTable() {
        // used by ticker, every 1 second.
        //After 30 seconds of the last use, the NAT entry should be removed from the NAT table
//        time_point current = steady_clock::now();
        for (auto it = m_natTable.begin(); it != m_natTable.end(); it++) {
            if (!it->second->isValid) {
                m_natTable.erase(it->first);
                it--;
            }
        }
//        for(const auto& pair : m_natTable){
//            if( !pair.second->isValid){
//                m_natTable.erase(pair.first);
//            }
//        }

    }

    std::shared_ptr<NatEntry>
    NatTable::lookup(uint16_t id) {
        auto it = m_natTable.find(id);
        // could not find it
        if (it == m_natTable.end()) {
            return nullptr;
        }

        return it->second;
    }


    void
    NatTable::insertNatEntry(uint16_t id, uint32_t in_ip, uint32_t ex_ip) {
        auto entry = lookup(id);
        // There is no such entry in the current nat table
        if (entry != nullptr) {
            if (entry->internal_ip != in_ip || entry->external_ip != ex_ip) {
                std::cerr << "!!!!!!!!!!!!!!!!!!!!NAT IP is different!!!!!!!!!!!!!!!!!" << std::endl;
            }
            entry->timeUsed = steady_clock::now();
            return;
        }
        // Create a new
        auto new_entry = std::make_shared<NatEntry>();
        new_entry->external_ip = ex_ip;
        new_entry->internal_ip = in_ip;
        new_entry->timeUsed = steady_clock::now();
        new_entry->isValid = true;
        // Insert into nat
        m_natTable.insert({id, new_entry});
    }



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

NatTable::NatTable(SimpleRouter &router)
        : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&NatTable::ticker, this)) {
}

NatTable::~NatTable() {
    m_shouldStop = true;
    m_tickerThread.join();
}


void
NatTable::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_natTable.clear();
}

void
NatTable::ticker() {
    while (!m_shouldStop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto now = steady_clock::now();

            std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator entryIt;
            for (entryIt = m_natTable.begin(); entryIt != m_natTable.end(); entryIt++) {
                if (entryIt->second->isValid && (now - entryIt->second->timeUsed > SR_ARPCACHE_TO)) {
                    entryIt->second->isValid = false;
                }
            }

            checkNatTable();
        }
    }
}

std::ostream &
operator<<(std::ostream &os, const NatTable &table) {
    std::lock_guard<std::mutex> lock(table.m_mutex);

    os << "\nID            Internal IP         External IP             AGE               VALID\n"
       << "-----------------------------------------------------------------------------------\n";

    auto now = steady_clock::now();

    for (auto const &entryIt : table.m_natTable) {
        os << entryIt.first << "            "
           << ipToString(entryIt.second->internal_ip) << "         "
           << ipToString(entryIt.second->external_ip) << "         "
           << std::chrono::duration_cast<seconds>((now - entryIt.second->timeUsed)).count() << " seconds         "
           << entryIt.second->isValid
           << "\n";
    }
    os << std::endl;
    return os;
}

} // namespace simple_router

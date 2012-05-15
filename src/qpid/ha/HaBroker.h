#ifndef QPID_HA_BROKER_H
#define QPID_HA_BROKER_H

/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "Enum.h"
#include "LogPrefix.h"
#include "Settings.h"
#include "qpid/Url.h"
#include "qpid/sys/Mutex.h"
#include "qmf/org/apache/qpid/ha/HaBroker.h"
#include "qpid/management/Manageable.h"
#include "qpid/types/Variant.h"
#include <memory>
#include <set>
#include <boost/shared_ptr.hpp>

namespace qpid {
namespace broker {
class Broker;
}
namespace framing {
class FieldTable;
}

namespace ha {
class Backup;
class ConnectionExcluder;
class Primary;

/**
 * HA state and actions associated with a broker.
 *
 * THREAD SAFE: may be called in arbitrary broker IO or timer threads.
 */
class HaBroker : public management::Manageable
{
  public:
    HaBroker(broker::Broker&, const Settings&);
    ~HaBroker();

    // Implement Manageable.
    qpid::management::ManagementObject* GetManagementObject() const { return mgmtObject; }
    management::Manageable::status_t ManagementMethod (
        uint32_t methodId, management::Args& args, std::string& text);

    broker::Broker& getBroker() { return broker; }
    const Settings& getSettings() const { return settings; }

    /** Shut down the broker. Caller should log a critical error message. */
    void shutdown();

    BrokerStatus getStatus() const;
    void setStatus(BrokerStatus);
    void activate();

    Backup* getBackup() { return backup.get(); }

    // Translate replicate levels.
    ReplicateLevel replicateLevel(const std::string& str);
    ReplicateLevel replicateLevel(const framing::FieldTable& f);
    ReplicateLevel replicateLevel(const types::Variant::Map& m);

    // Keep track of the set of actively replicated queues on a backup
    // so that it can be transferred to the Primary on promotion.
    typedef std::set<std::string> QueueNames;
    void activatedBackup(const std::string& queue);
    void deactivatedBackup(const std::string& queue);
    QueueNames getActiveBackups() const;

    boost::shared_ptr<ConnectionExcluder> getExcluder() { return excluder; }

  private:
    void setClientUrl(const Url&, const sys::Mutex::ScopedLock&);
    void setBrokerUrl(const Url&, const sys::Mutex::ScopedLock&);
    void setExpectedBackups(size_t, const sys::Mutex::ScopedLock&);
    void updateClientUrl(const sys::Mutex::ScopedLock&);

    bool isPrimary(const sys::Mutex::ScopedLock&) { return !backup.get(); }

    void setStatus(BrokerStatus, sys::Mutex::ScopedLock&);
    void promoting(sys::Mutex::ScopedLock&);
    void activate(sys::Mutex::ScopedLock&);
    void statusChanged(sys::Mutex::ScopedLock&);

    std::vector<Url> getKnownBrokers() const;

    LogPrefix logPrefix;
    broker::Broker& broker;
    const Settings settings;

    mutable sys::Mutex lock;
    std::auto_ptr<Backup> backup;
    std::auto_ptr<Primary> primary;
    qmf::org::apache::qpid::ha::HaBroker* mgmtObject;
    Url clientUrl, brokerUrl;
    std::vector<Url> knownBrokers;
    size_t expectedBackups;
    BrokerStatus status;
    QueueNames activeBackups;
    boost::shared_ptr<ConnectionExcluder> excluder;
};
}} // namespace qpid::ha

#endif  /*!QPID_HA_BROKER_H*/

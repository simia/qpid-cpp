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
#include "LogPrefix.h"
#include "HaBroker.h"
#include <iostream>

namespace qpid {
namespace ha {

LogPrefix::LogPrefix(HaBroker& hb, const std::string& queue) : haBroker(&hb), status(0) {
    if (queue.size()) tail = " queue " + queue;
}

LogPrefix::LogPrefix(BrokerStatus& s) : haBroker(0), status(&s) {}

std::ostream& operator<<(std::ostream& o, const LogPrefix& l) {
    return o << "HA("
             << printable(l.status ? *l.status : l.haBroker->getStatus())
             << ")" << l.tail << ": ";
}

}} // namespace qpid::ha

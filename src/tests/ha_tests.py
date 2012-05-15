#!/usr/bin/env python

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import os, signal, sys, time, imp, re, subprocess, glob, random, logging, shutil, math
from qpid.messaging import Message, NotFound, ConnectionError, ReceiverError, Connection
from qpid.datatypes import uuid4
from brokertest import *
from threading import Thread, Lock, Condition
from logging import getLogger, WARN, ERROR, DEBUG
from qpidtoollibs import BrokerAgent

log = getLogger(__name__)

class QmfHaBroker(object):
    def __init__(self, address):
        self.connection = Connection.establish(
            address, client_properties={"qpid.ha-admin":1})
        self.qmf = BrokerAgent(self.connection)
        self.ha_broker = self.qmf.getHaBroker()
        if not self.ha_broker:
            raise Exception("HA module is not loaded on broker at %s"%address)

class HaBroker(Broker):
    def __init__(self, test, args=[], broker_url=None, ha_cluster=True,
                 ha_replicate="all", **kwargs):
        assert BrokerTest.ha_lib, "Cannot locate HA plug-in"
        args = copy(args)
        args += ["--load-module", BrokerTest.ha_lib,
                 "--log-enable=info+",
                 "--log-enable=debug+:ha::",
                 # FIXME aconway 2012-02-13: workaround slow link failover.
                 "--link-maintenace-interval=0.1",
                 "--ha-cluster=%s"%ha_cluster]
        if ha_replicate is not None:
            args += [ "--ha-replicate=%s"%ha_replicate ]
        if broker_url: args.extend([ "--ha-brokers", broker_url ])
        Broker.__init__(self, test, args, **kwargs)
        self.qpid_ha_path=os.path.join(os.getenv("PYTHON_COMMANDS"), "qpid-ha")
        assert os.path.exists(self.qpid_ha_path)
        self.qpid_config_path=os.path.join(os.getenv("PYTHON_COMMANDS"), "qpid-config")
        assert os.path.exists(self.qpid_config_path)
        getLogger().setLevel(ERROR) # Hide expected WARNING log messages from failover.
        self.qpid_ha_script=import_script(self.qpid_ha_path)

    def qpid_ha(self, args): self.qpid_ha_script.main(["", "-b", self.host_port()]+args)

    def promote(self): self.qpid_ha(["promote"])
    def set_client_url(self, url): self.qpid_ha(["set", "--public-brokers", url])
    def set_broker_url(self, url): self.qpid_ha(["set", "--brokers", url])
    def replicate(self, from_broker, queue): self.qpid_ha(["replicate", from_broker, queue])
    def ha_status(self): QmfHaBroker(self.host_port()).ha_broker.status

    # FIXME aconway 2012-05-01: do direct python call to qpid-config code.
    def qpid_config(self, args):
        assert subprocess.call(
            [self.qpid_config_path, "--broker", self.host_port()]+args) == 0

    def config_replicate(self, from_broker, queue):
        self.qpid_config(["add", "queue", "--start-replica", from_broker, queue])

    def config_declare(self, queue, replication):
        self.qpid_config(["add", "queue", queue, "--replicate", replication])

    def connect_admin(self, **kwargs):
        return Broker.connect(self, client_properties={"qpid.ha-admin":1}, **kwargs)

    def wait_backup(self, address):
        """Wait for address to become valid on a backup broker."""
        bs = self.connect_admin().session()
        try: wait_address(bs, address)
        finally: bs.connection.close()

    def assert_browse_backup(self, queue, expected, **kwargs):
        """Combines wait_backup and assert_browse_retry."""
        bs = self.connect_admin().session()
        try:
            wait_address(bs, queue)
            assert_browse_retry(bs, queue, expected, **kwargs)
        finally: bs.connection.close()

    def assert_connect_fail(self):
        try:
            self.connect()
            self.test.fail("Expected ConnectionError")
        except ConnectionError: pass

    def connect_retry(self):
        def try_connect():
            try: return self.connect()
            except ConnectionError: return None
        c = retry(try_connect)
        if c: return c
        else: self.test.fail("Failed to connect")

class HaCluster(object):
    _cluster_count = 0

    def __init__(self, test, n, **kwargs):
        """Start a cluster of n brokers"""
        self.test = test
        self.kwargs = kwargs
        self._brokers = []
        self.id = HaCluster._cluster_count
        HaCluster._cluster_count += 1
        for i in xrange(n): self.start(False)
        self.update_urls()
        self[0].promote()

    def start(self, update_urls=True):
        """Start a new broker in the cluster"""
        b = HaBroker(
            self.test,
            name="broker%s-%s"%(self.id, len(self._brokers)),
            **self.kwargs)
        self._brokers.append(b)
        if update_urls: self.update_urls()
        return b

    def update_urls(self):
        self.url = ",".join([b.host_port() for b in self])
        for b in self: b.set_broker_url(self.url)

    def connect(self, i):
        """Connect with reconnect_urls"""
        return self[i].connect(reconnect=True, reconnect_urls=self.url.split(","))

    def kill(self, i):
        """Kill broker i, promote broker i+1"""
        self[i].kill()
        self[i].expect = EXPECT_EXIT_FAIL
        self[(i+1) % len(self)].promote()

    def restart(self, i):
        b = self._brokers[i]
        self._brokers[i] = HaBroker(
            self.test, name=b.name, port=b.port(), broker_url=self.url, **self.kwargs)

    def bounce(self, i):
        """Stop and restart a broker in a cluster."""
        self.kill(i)
        self.restart(i)

    # Behave like a list of brokers.
    def __len__(self): return len(self._brokers)
    def __getitem__(self,index): return self._brokers[index]
    def __iter__(self): return self._brokers.__iter__()

def wait_address(session, address):
    """Wait for an address to become valid."""
    def check():
        try:
            session.sender(address)
            return True
        except NotFound: return False
    assert retry(check), "Timed out waiting for address %s"%(address)

def assert_missing(session, address):
    """Assert that the address is _not_ valid"""
    try:
        session.receiver(address)
        self.fail("Expected NotFound: %s"%(address))
    except NotFound: pass

class ReplicationTests(BrokerTest):
    """Correctness tests for  HA replication."""

    def test_replication(self):
        """Test basic replication of configuration and messages before and
        after backup has connected"""

        def queue(name, replicate):
            return "%s;{create:always,node:{x-declare:{arguments:{'qpid.replicate':%s}}}}"%(name, replicate)

        def exchange(name, replicate, bindq):
            return"%s;{create:always,node:{type:topic,x-declare:{arguments:{'qpid.replicate':%s}, type:'fanout'},x-bindings:[{exchange:'%s',queue:'%s'}]}}"%(name, replicate, name, bindq)
        def setup(p, prefix, primary):
            """Create config, send messages on the primary p"""
            s = p.sender(queue(prefix+"q1", "all"))
            for m in ["a", "b", "1"]: s.send(Message(m))
            # Test replication of dequeue
            self.assertEqual(p.receiver(prefix+"q1").fetch(timeout=0).content, "a")
            p.acknowledge()
            p.sender(queue(prefix+"q2", "configuration")).send(Message("2"))
            p.sender(queue(prefix+"q3", "none")).send(Message("3"))
            p.sender(exchange(prefix+"e1", "all", prefix+"q1")).send(Message("4"))
            p.sender(exchange(prefix+"e2", "all", prefix+"q2")).send(Message("5"))
            # Test  unbind
            p.sender(queue(prefix+"q4", "all")).send(Message("6"))
            s3 = p.sender(exchange(prefix+"e4", "all", prefix+"q4"))
            s3.send(Message("7"))
            # Use old connection to unbind
            us = primary.connect_old().session(str(uuid4()))
            us.exchange_unbind(exchange=prefix+"e4", binding_key="", queue=prefix+"q4")
            p.sender(prefix+"e4").send(Message("drop1")) # Should be dropped
            # Need a marker so we can wait till sync is done.
            p.sender(queue(prefix+"x", "configuration"))

        def verify(b, prefix, p):
            """Verify setup was replicated to backup b"""
            # Wait for configuration to replicate.
            wait_address(b, prefix+"x");
            self.assert_browse_retry(b, prefix+"q1", ["b", "1", "4"])

            self.assertEqual(p.receiver(prefix+"q1").fetch(timeout=0).content, "b")
            p.acknowledge()
            self.assert_browse_retry(b, prefix+"q1", ["1", "4"])

            self.assert_browse_retry(b, prefix+"q2", []) # configuration only
            assert_missing(b, prefix+"q3")
            b.sender(prefix+"e1").send(Message(prefix+"e1")) # Verify binds with replicate=all
            self.assert_browse_retry(b, prefix+"q1", ["1", "4", prefix+"e1"])
            b.sender(prefix+"e2").send(Message(prefix+"e2")) # Verify binds with replicate=configuration
            self.assert_browse_retry(b, prefix+"q2", [prefix+"e2"])

            b.sender(prefix+"e4").send(Message("drop2")) # Verify unbind.
            self.assert_browse_retry(b, prefix+"q4", ["6","7"])

        primary = HaBroker(self, name="primary")
        primary.promote()
        p = primary.connect().session()

        # Create config, send messages before starting the backup, to test catch-up replication.
        setup(p, "1", primary)
        backup  = HaBroker(self, name="backup", broker_url=primary.host_port())
        # Create config, send messages after starting the backup, to test steady-state replication.
        setup(p, "2", primary)

        # Verify the data on the backup
        b = backup.connect_admin().session()
        verify(b, "1", p)
        verify(b, "2", p)
        # Test a series of messages, enqueue all then dequeue all.
        s = p.sender(queue("foo","all"))
        wait_address(b, "foo")
        msgs = [str(i) for i in range(10)]
        for m in msgs: s.send(Message(m))
        self.assert_browse_retry(p, "foo", msgs)
        self.assert_browse_retry(b, "foo", msgs)
        r = p.receiver("foo")
        for m in msgs: self.assertEqual(m, r.fetch(timeout=0).content)
        p.acknowledge()
        self.assert_browse_retry(p, "foo", [])
        self.assert_browse_retry(b, "foo", [])

        # Another series, this time verify each dequeue individually.
        for m in msgs: s.send(Message(m))
        self.assert_browse_retry(p, "foo", msgs)
        self.assert_browse_retry(b, "foo", msgs)
        for i in range(len(msgs)):
            self.assertEqual(msgs[i], r.fetch(timeout=0).content)
            p.acknowledge()
            self.assert_browse_retry(p, "foo", msgs[i+1:])
            self.assert_browse_retry(b, "foo", msgs[i+1:])

    def test_sync(self):
        primary = HaBroker(self, name="primary")
        primary.promote()
        p = primary.connect().session()
        s = p.sender("q;{create:always}")
        for m in [str(i) for i in range(0,10)]: s.send(m)
        s.sync()
        backup1 = HaBroker(self, name="backup1", broker_url=primary.host_port())
        for m in [str(i) for i in range(10,20)]: s.send(m)
        s.sync()
        backup2 = HaBroker(self, name="backup2", broker_url=primary.host_port())
        for m in [str(i) for i in range(20,30)]: s.send(m)
        s.sync()

        msgs = [str(i) for i in range(30)]
        b1 = backup1.connect_admin().session()
        wait_address(b1, "q");
        self.assert_browse_retry(b1, "q", msgs)
        b2 = backup2.connect_admin().session()
        wait_address(b2, "q");
        self.assert_browse_retry(b2, "q", msgs)

    def test_send_receive(self):
        """Verify sequence numbers of messages sent by qpid-send"""
        brokers = HaCluster(self, 3)
        sender = self.popen(
            ["qpid-send",
             "--broker", brokers[0].host_port(),
             "--address", "q;{create:always}",
             "--messages=1000",
             "--content-string=x"
             ])
        receiver = self.popen(
            ["qpid-receive",
             "--broker", brokers[0].host_port(),
             "--address", "q;{create:always}",
             "--messages=990",
             "--timeout=10"
             ])
        self.assertEqual(sender.wait(), 0)
        self.assertEqual(receiver.wait(), 0)
        expect = [long(i) for i in range(991, 1001)]
        sn = lambda m: m.properties["sn"]
        brokers[1].assert_browse_backup("q", expect, transform=sn)
        brokers[2].assert_browse_backup("q", expect, transform=sn)

    def test_failover_python(self):
        """Verify that backups rejects connections and that fail-over works in python client"""
        primary = HaBroker(self, name="primary", expect=EXPECT_EXIT_FAIL)
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        # Check that backup rejects normal connections
        try:
            backup.connect().session()
            self.fail("Expected connection to backup to fail")
        except ConnectionError: pass
        # Check that admin connections are allowed to backup.
        backup.connect_admin().close()

        # Test discovery: should connect to primary after reject by backup
        c = backup.connect(reconnect_urls=[primary.host_port(), backup.host_port()], reconnect=True)
        s = c.session()
        sender = s.sender("q;{create:always}")
        backup.wait_backup("q")
        sender.send("foo")
        primary.kill()
        assert retry(lambda: not is_running(primary.pid))
        backup.promote()
        self.assert_browse_retry(s, "q", ["foo"])
        c.close()

    def test_failover_cpp(self):
        """Verify that failover works in the C++ client."""
        primary = HaBroker(self, name="primary", expect=EXPECT_EXIT_FAIL)
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        url="%s,%s"%(primary.host_port(), backup.host_port())
        primary.connect().session().sender("q;{create:always}")
        backup.wait_backup("q")

        sender = NumberedSender(primary, url=url, queue="q", failover_updates = False)
        receiver = NumberedReceiver(primary, url=url, queue="q", failover_updates = False)
        receiver.start()
        sender.start()
        backup.wait_backup("q")
        assert retry(lambda: receiver.received > 10) # Wait for some messages to get thru

        primary.kill()
        assert retry(lambda: not is_running(primary.pid)) # Wait for primary to die
        backup.promote()
        n = receiver.received       # Make sure we are still running
        assert retry(lambda: receiver.received > n + 10)
        sender.stop()
        receiver.stop()

    def test_backup_failover(self):
        """Verify that a backup broker fails over and recovers queue state"""
        brokers = HaCluster(self, 3)
        brokers[0].connect().session().sender("q;{create:always}").send("a")
        for b in brokers[1:]: b.assert_browse_backup("q", ["a"], msg=b)
        brokers[0].expect = EXPECT_EXIT_FAIL
        brokers.kill(0)
        brokers[1].connect().session().sender("q").send("b")
        brokers[2].assert_browse_backup("q", ["a","b"])
        s = brokers[1].connect().session()
        self.assertEqual("a", s.receiver("q").fetch().content)
        s.acknowledge()
        brokers[2].assert_browse_backup("q", ["b"])

    def test_qpid_config_replication(self):
        """Set up replication via qpid-config"""
        brokers = HaCluster(self,2)
        brokers[0].config_declare("q","all")
        brokers[0].connect().session().sender("q").send("foo")
        brokers[1].assert_browse_backup("q", ["foo"])

    def test_standalone_queue_replica(self):
        """Test replication of individual queues outside of cluster mode"""
        getLogger().setLevel(ERROR) # Hide expected WARNING log messages from failover.
        primary = HaBroker(self, name="primary", ha_cluster=False)
        pc = primary.connect()
        ps = pc.session().sender("q;{create:always}")
        pr = pc.session().receiver("q;{create:always}")
        backup = HaBroker(self, name="backup", ha_cluster=False)
        br = backup.connect().session().receiver("q;{create:always}")

        # Set up replication with qpid-ha
        backup.replicate(primary.host_port(), "q")
        ps.send("a")
        backup.assert_browse_backup("q", ["a"])
        ps.send("b")
        backup.assert_browse_backup("q", ["a", "b"])
        self.assertEqual("a", pr.fetch().content)
        pr.session.acknowledge()
        backup.assert_browse_backup("q", ["b"])

        # Set up replication with qpid-config
        ps2 = pc.session().sender("q2;{create:always}")
        backup.config_replicate(primary.host_port(), "q2");
        ps2.send("x")
        backup.assert_browse_backup("q2", ["x"])


    def test_queue_replica_failover(self):
        """Test individual queue replication from a cluster to a standalone backup broker, verify it fails over."""
        cluster = HaCluster(self, 2)
        primary = cluster[0]
        pc = cluster.connect(0)
        ps = pc.session().sender("q;{create:always}")
        pr = pc.session().receiver("q;{create:always}")
        backup = HaBroker(self, name="backup", ha_cluster=False)
        br = backup.connect().session().receiver("q;{create:always}")
        backup.replicate(cluster.url, "q")
        ps.send("a")
        backup.assert_browse_backup("q", ["a"])
        cluster.bounce(0)
        backup.assert_browse_backup("q", ["a"])
        ps.send("b")
        backup.assert_browse_backup("q", ["a", "b"])
        cluster.bounce(1)
        self.assertEqual("a", pr.fetch().content)
        pr.session.acknowledge()
        backup.assert_browse_backup("q", ["b"])

    def test_lvq(self):
        """Verify that we replicate to an LVQ correctly"""
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        s = primary.connect().session().sender("lvq; {create:always, node:{x-declare:{arguments:{'qpid.last_value_queue_key':lvq-key}}}}")
        def send(key,value): s.send(Message(content=value,properties={"lvq-key":key}))
        for kv in [("a","a-1"),("b","b-1"),("a","a-2"),("a","a-3"),("c","c-1"),("c","c-2")]:
            send(*kv)
        backup.assert_browse_backup("lvq", ["b-1", "a-3", "c-2"])
        send("b","b-2")
        backup.assert_browse_backup("lvq", ["a-3", "c-2", "b-2"])
        send("c","c-3")
        backup.assert_browse_backup("lvq", ["a-3", "b-2", "c-3"])
        send("d","d-1")
        backup.assert_browse_backup("lvq", ["a-3", "b-2", "c-3", "d-1"])

    def test_ring(self):
        """Test replication with the ring queue policy"""
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        s = primary.connect().session().sender("q; {create:always, node:{x-declare:{arguments:{'qpid.policy_type':ring, 'qpid.max_count':5}}}}")
        for i in range(10): s.send(Message(str(i)))
        backup.assert_browse_backup("q", [str(i) for i in range(5,10)])

    def test_reject(self):
        """Test replication with the reject queue policy"""
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        s = primary.connect().session().sender("q; {create:always, node:{x-declare:{arguments:{'qpid.policy_type':reject, 'qpid.max_count':5}}}}")
        try:
            for i in range(10): s.send(Message(str(i)), sync=False)
        except qpid.messaging.exceptions.TargetCapacityExceeded: pass
        backup.assert_browse_backup("q", [str(i) for i in range(0,5)])

    def test_priority(self):
        """Verify priority queues replicate correctly"""
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        session = primary.connect().session()
        s = session.sender("priority-queue; {create:always, node:{x-declare:{arguments:{'qpid.priorities':10}}}}")
        priorities = [8,9,5,1,2,2,3,4,9,7,8,9,9,2]
        for p in priorities: s.send(Message(priority=p))
        # Can't use browse_backup as browser sees messages in delivery order not priority.
        backup.wait_backup("priority-queue")
        r = backup.connect_admin().session().receiver("priority-queue")
        received = [r.fetch().priority for i in priorities]
        self.assertEqual(sorted(priorities, reverse=True), received)

    def test_priority_fairshare(self):
        """Verify priority queues replicate correctly"""
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        session = primary.connect().session()
        levels = 8
        priorities = [4,5,3,7,8,8,2,8,2,8,8,16,6,6,6,6,6,6,8,3,5,8,3,5,5,3,3,8,8,3,7,3,7,7,7,8,8,8,2,3]
        limits={7:0,6:4,5:3,4:2,3:2,2:2,1:2}
        limit_policy = ",".join(["'qpid.fairshare':5"] + ["'qpid.fairshare-%s':%s"%(i[0],i[1]) for i in limits.iteritems()])
        s = session.sender("priority-queue; {create:always, node:{x-declare:{arguments:{'qpid.priorities':%s, %s}}}}"%(levels,limit_policy))
        messages = [Message(content=str(uuid4()), priority = p) for p in priorities]
        for m in messages: s.send(m)
        backup.wait_backup(s.target)
        r = backup.connect_admin().session().receiver("priority-queue")
        received = [r.fetch().content for i in priorities]
        sort = sorted(messages, key=lambda m: priority_level(m.priority, levels), reverse=True)
        fair = [m.content for m in fairshare(sort, lambda l: limits.get(l,0), levels)]
        self.assertEqual(received, fair)

    def test_priority_ring(self):
        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup = HaBroker(self, name="backup", broker_url=primary.host_port())
        s = primary.connect().session().sender("q; {create:always, node:{x-declare:{arguments:{'qpid.policy_type':ring, 'qpid.max_count':5, 'qpid.priorities':10}}}}")
        priorities = [8,9,5,1,2,2,3,4,9,7,8,9,9,2]
        for p in priorities: s.send(Message(priority=p))

        # FIXME aconway 2012-02-22: there is a bug in priority ring
        # queues that allows a low priority message to displace a high
        # one. The following commented-out assert_browse is for the
        # correct result, the uncommented one is for the actualy buggy
        # result.  See https://issues.apache.org/jira/browse/QPID-3866
        #
        # backup.assert_browse_backup("q", sorted(priorities,reverse=True)[0:5], transform=lambda m: m.priority)
        backup.assert_browse_backup("q", [9,9,9,9,2], transform=lambda m: m.priority)

    def test_backup_acquired(self):
        """Verify that acquired messages are backed up, for all queue types."""
        class Test:
            def __init__(self, queue, arguments, expect):
                self.queue = queue
                self.address = "%s;{create:always,node:{x-declare:{arguments:{%s}}}}"%(
                    self.queue, ",".join(arguments + ["'qpid.replicate':all"]))
                self.expect = [str(i) for i in expect]

            def send(self, connection):
                """Send messages, then acquire one but don't acknowledge"""
                s = connection.session()
                for m in range(10): s.sender(self.address).send(str(m))
                s.receiver(self.address).fetch()

            def wait(self, brokertest, backup):
                backup.wait_backup(self.queue)

            def verify(self, brokertest, backup):
                backup.assert_browse_backup(self.queue, self.expect, msg=self.queue)

        tests = [
            Test("plain",[],range(10)),
            Test("ring", ["'qpid.policy_type':ring", "'qpid.max_count':5"], range(5,10)),
            Test("priority",["'qpid.priorities':10"], range(10)),
            Test("fairshare", ["'qpid.priorities':10,'qpid.fairshare':5"], range(10)),
            Test("lvq", ["'qpid.last_value_queue_key':lvq-key"], [9])
            ]

        primary  = HaBroker(self, name="primary")
        primary.promote()
        backup1 = HaBroker(self, name="backup1", broker_url=primary.host_port())
        c = primary.connect()
        for t in tests: t.send(c) # Send messages, leave one unacknowledged.

        backup2 = HaBroker(self, name="backup2", broker_url=primary.host_port())
        # Wait for backups to catch up.
        for t in tests:
            t.wait(self, backup1)
            t.wait(self, backup2)
        # Verify acquired message was replicated
        for t in tests: t.verify(self, backup1)
        for t in tests: t.verify(self, backup2)

    def test_replicate_default(self):
        """Make sure we don't replicate if ha-replicate is unspecified or none"""
        cluster1 = HaCluster(self, 2, ha_replicate=None)
        c1 = cluster1[0].connect().session().sender("q;{create:always}")
        cluster2 = HaCluster(self, 2, ha_replicate="none")
        cluster2[0].connect().session().sender("q;{create:always}")
        time.sleep(.1)               # Give replication a chance.
        try:
            cluster1[1].connect_admin().session().receiver("q")
            self.fail("Excpected no-such-queue exception")
        except NotFound: pass
        try:
            cluster2[1].connect_admin().session().receiver("q")
            self.fail("Excpected no-such-queue exception")
        except NotFound: pass

    def test_invalid_default(self):
        """Verify that a queue with an invalid qpid.replicate gets default treatment"""
        cluster = HaCluster(self, 2, ha_replicate="all")
        c = cluster[0].connect().session().sender("q;{create:always, node:{x-declare:{arguments:{'qpid.replicate':XXinvalidXX}}}}")
        cluster[1].wait_backup("q")

    def test_exclusive_queue(self):
        """Ensure that we can back-up exclusive queues, i.e. the replicating
        subscriptions are exempt from the exclusivity"""
        cluster = HaCluster(self, 2)
        def test(addr):
            c = cluster[0].connect()
            q = addr.split(";")[0]
            r = c.session().receiver(addr)
            try: c.session().receiver(addr); self.fail("Expected exclusive exception")
            except ReceiverError: pass
            s = c.session().sender(q).send(q)
            cluster[1].assert_browse_backup(q, [q])
        test("excl_sub;{create:always, link:{x-subscribe:{exclusive:True}}}");
        test("excl_queue;{create:always, node:{x-declare:{exclusive:True}}}")

    def test_promoting(self):
        """Verify that the primary broker does not go active until expected
        backups have connected or timeout expires."""
        cluster = HaCluster(self, 3, args=["--ha-expected-backups=2"])
        c = cluster[0].connect()
        for i in xrange(10):
            s = c.session().sender("q%s;{create:always}"%i)
            for j in xrange(100): s.send(str(j))
        cluster.kill(0)         # Fail over to 1
        cluster[1].assert_connect_fail() # Waiting for backups, won't accept clients.
        cluster.restart(0)
        c = cluster[1].connect_retry()
        cluster[1].assert_browse_backup("q0", [str(i) for i in xrange(100)]);

        # Verify in logs that all queue catch-up happened before the transition to active.
        log = open(cluster[1].log).read()
        i = log.find("Status change: promoting -> active")
        self.failIf(i < 0)
        self.assertEqual(log.find("caught up", i), -1)

def fairshare(msgs, limit, levels):
    """
    Generator to return prioritised messages in expected order for a given fairshare limit
    """
    count = 0
    last_priority = None
    postponed = []
    while msgs or postponed:
        if not msgs:
            msgs = postponed
            count = 0
            last_priority = None
            postponed = []
        msg = msgs.pop(0)
        if last_priority and priority_level(msg.priority, levels) == last_priority:
            count += 1
        else:
            last_priority = priority_level(msg.priority, levels)
            count = 1
        l = limit(last_priority)
        if (l and count > l):
            postponed.append(msg)
        else:
            yield msg
    return

def priority_level(value, levels):
    """
    Method to determine which of a distinct number of priority levels
    a given value falls into.
    """
    offset = 5-math.ceil(levels/2.0)
    return min(max(value - offset, 0), levels-1)

class LongTests(BrokerTest):
    """Tests that can run for a long time if -DDURATION=<minutes> is set"""

    def duration(self):
        d = self.config.defines.get("DURATION")
        if d: return float(d)*60
        else: return 3                  # Default is to be quick


    def disable_test_failover_send_receive(self):
        """Test failover with continuous send-receive"""
        # FIXME aconway 2012-02-03: fails due to dropped messages,
        # known issue: sending messages to new primary before
        # backups are ready. Enable when fixed.

        # Start a cluster, all members will be killed during the test.
        brokers = [ HaBroker(self, name=name, expect=EXPECT_EXIT_FAIL,
                             args=["--ha-expected-backups=2"])
                    for name in ["ha0","ha1","ha2"] ]
        url = ",".join([b.host_port() for b in brokers])
        for b in brokers: b.set_broker_url(url)
        brokers[0].promote()

        # Start sender and receiver threads
        sender = NumberedSender(brokers[0], max_depth=1000, failover_updates=False)
        receiver = NumberedReceiver(brokers[0], sender=sender, failover_updates=False)
        receiver.start()
        sender.start()
        try:
            # Wait for sender & receiver to get up and running
            assert retry(lambda: receiver.received > 100)
            # Kill and restart brokers in a cycle:
            endtime = time.time() + self.duration()
            i = 0
            while time.time() < endtime or i < 3: # At least 3 iterations
                sender.sender.assert_running()
                receiver.receiver.assert_running()
                port = brokers[i].port()
                brokers[i].kill()
                brokers.append(
                    HaBroker(self, name="ha%d"%(i+3), broker_url=url, port=port,
                             expect=EXPECT_EXIT_FAIL))
                i += 1
                brokers[i].promote()
                n = receiver.received       # Verify we're still running
                def enough():
                    receiver.check()        # Verify no exceptions
                    return receiver.received > n + 100
                assert retry(enough, timeout=5)
        finally:
            sender.stop()
            receiver.stop()
            for b in brokers[i:]: b.kill()

if __name__ == "__main__":
    shutil.rmtree("brokertest.tmp", True)
    qpid_ha = os.getenv("QPID_HA_EXEC")
    if  qpid_ha and os.path.exists(qpid_ha):
        os.execvp("qpid-python-test",
                  ["qpid-python-test", "-m", "ha_tests"] + sys.argv[1:])
    else:
        print "Skipping ha_tests, qpid_ha not available"


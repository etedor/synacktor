#!/usr/bin/env python

import os
import os.path
import shlex
import socket
import subprocess as sp
import sys
import syslog

import eossdk

try:
    sys.path.append("/usr/local/bin")
    from synscan import scan
except ImportError:
    pass

sys.dont_write_bytecode = True

__version__ = "2020.04.09.1"


def is_file(path):
    return os.path.isfile(path)


def is_ip(ip):
    for af in socket.AF_INET, socket.AF_INET6:
        try:
            socket.inet_pton(af, ip)
            return True
        except socket.error:
            continue
    return False


def is_populated(path):
    return os.path.getsize(path) > 0


def vrf_exists(vrf, vrf_mgr):
    if vrf == "default":
        return True
    return vrf_mgr.exists(vrf)


class SynAcktorAgent(
    eossdk.AgentHandler, eossdk.TimeoutHandler, eossdk.VrfHandler
):
    def __init__(self, agent_mgr, eapi_mgr, timeout_mgr, vrf_mgr):
        self.tracer = eossdk.Tracer("SynAcktorPythonAgent")
        eossdk.AgentHandler.__init__(self, agent_mgr)
        eossdk.TimeoutHandler.__init__(self, timeout_mgr)
        eossdk.VrfHandler.__init__(self, vrf_mgr)
        self.agent_mgr = agent_mgr
        self.eapi_mgr = eapi_mgr
        self.vrf_mgr = vrf_mgr

        self._options = None
        self._conf_fail = None  # required
        self._conf_recover = None  # required
        self._dport = None  # required
        self._ip = None  # required
        self._nexthop = None  # required
        self._hold_count = None
        self._hold_down = None
        self._hold_up = None
        self._interval = None
        self._vrf = None

        self.counter = 0
        self.disabled = None
        self.healthy = None
        self.results = []

    @property
    def options(self):
        # cf. https://stackoverflow.com/a/5876258
        if self._options:
            return self._options

        from six import iteritems

        self._options = [
            k.replace("_", "-")
            for k, v in iteritems(self.__class__.__dict__)
            if isinstance(v, property) and k != "options"
        ]
        self._options.sort()
        return self._options

    @property
    def conf_fail(self):
        if self._conf_fail:
            return self._conf_fail

        option = "conf-fail"
        conds = [("found", is_file), ("populated", is_populated)]
        return self._set_option_attr(option, conds)

    @property
    def conf_recover(self):
        if self._conf_recover:
            return self._conf_recover

        option = "conf-recover"
        conds = [("found", is_file), ("populated", is_populated)]
        return self._set_option_attr(option, conds)

    @property
    def dport(self):
        if self._dport:
            return self._dport

        option = "dport"
        conds = [
            ("integer", str.isdigit),
            ("in range [1-65535]", lambda x: 1 <= int(x) <= 65535),
        ]
        return self._set_option_attr(option, conds, tform=int)

    @property
    def hold_count(self):
        if self._hold_count:
            return self._hold_count
        self._hold_count = max(self.hold_down, self.hold_up)
        return self._hold_count

    @property
    def hold_down(self):
        if self._hold_down:
            return self._hold_down

        option = "hold-down"
        conds = [
            ("integer", str.isdigit),
            ("in range [1-60]", lambda x: 1 <= int(x) <= 60),
        ]
        return self._set_option_attr(option, conds, default=3, tform=int)

    @property
    def hold_up(self):
        if self._hold_up:
            return self._hold_up

        option = "hold-up"
        conds = [
            ("integer", str.isdigit),
            ("in range [1-60]", lambda x: 1 <= int(x) <= 60),
        ]
        return self._set_option_attr(option, conds, default=3, tform=int)

    @property
    def interval(self):
        if self._interval:
            return self._interval

        option = "interval"
        conds = [
            ("integer", str.isdigit),
            ("in range [3-60]", lambda x: 3 <= int(x) <= 60),
        ]
        return self._set_option_attr(option, conds, default=5, tform=int)

    @property
    def ip(self):
        if self._ip:
            return self._ip

        option = "ip"
        conds = [("valid", is_ip)]
        return self._set_option_attr(option, conds)

    @property
    def nexthop(self):
        if self._nexthop:
            return self._nexthop

        option = "nexthop"
        conds = [("valid", is_ip)]
        return self._set_option_attr(option, conds)

    @property
    def vrf(self):
        if self._vrf:
            return self._vrf

        option = "vrf"
        conds = [("present", lambda x: vrf_exists(x, self.vrf_mgr))]
        return self._set_option_attr(option, conds, default="default")

    def _set_option_attr(self, option, conds, default=None, tform=str):
        value = self.agent_mgr.agent_option(option)
        if not value and default:
            value = default

        conds.insert(0, ("configured", lambda x: x != ""))
        for test, cond in conds:
            try:
                if not cond(value):
                    reason = "{0} not {1}".format(option, test)
                    self.err_disable(reason)
                    break
            except Exception as e:
                exc_name = e.__class__.__name__
                reason = "{0} {1} exception".format(option, exc_name)
                self.err_disable(reason)
                break
        else:
            setattr(self, "_" + option.replace("-", "_"), tform(value))
            self.agent_mgr.status_set(option, value)
            return tform(value)

    def configure(self, conf_path):
        def clean():
            with open(conf_path, "r") as f:
                conf = f.read()
            conf_lines = conf.splitlines()
            if conf_lines[0] == "enable":
                del conf_lines[0]
            return [line.strip() for line in conf_lines]

        try:
            result = self.eapi_mgr.run_config_cmds(clean())
            if result.success():
                message = "Success applying configuration commands from {0}"
                message = message.format(conf_path)
                self.log(message)
                return
        except Exception:
            pass

        self.err_disable("configuration failure")
        message = "Failure applying configuration commands from {0}"
        message = message.format(conf_path)
        self.log(message)

    def err_disable(self, reason):
        self.log("Error-disabled: {0}".format(reason))
        self.disabled = True
        enabled = str(not bool(self.disabled)).lower()
        self.agent_mgr.status_set("Enabled", enabled)
        self.agent_mgr.status_set("Healthy", "unknown")
        self.agent_mgr.status_set("Reason", reason)
        self.agent_mgr.status_del("Last action")
        self.agent_mgr.status_del("Last fail")
        self.agent_mgr.status_del("Last recover")
        for option in self.options:
            self.agent_mgr.status_del(option)

    def log(self, message):
        message = str(message)
        self.tracer.trace0(message)
        syslog.syslog(message)

    def on_agent_enabled(self, enabled):
        if not enabled:
            self.log("Shutting down")
            self.agent_mgr.status_set("Enabled", "false")
            self.agent_mgr.status_set("Healthy", "unknown")
            self.agent_mgr.status_set("Reason", "administratively down")
            self.agent_mgr.status_del("Last action")
            self.agent_mgr.status_del("Last fail")
            self.agent_mgr.status_del("Last recover")
            for option in self.options:
                self.agent_mgr.status_del(option)
            self.agent_mgr.agent_shutdown_complete_is(True)

    # def on_agent_option(self, option, value):
    #     # we require the daemon to be shutdown/no shutdown to apply changes
    #     pass

    def on_initialized(self):
        self.log("Initialized")
        self.agent_mgr.status_set("Enabled", "true")
        self.agent_mgr.status_set("Healthy", "unknown")
        self.agent_mgr.status_set("Last action", "none")
        self.agent_mgr.status_set("Last fail", "never")
        self.agent_mgr.status_set("Last recover", "never")
        self.agent_mgr.status_del("Reason")
        self.timeout_time_is(eossdk.now())

    def on_timeout(self):
        def action(conf, healthy, verb):
            self.log("{0}:{1} has {2}ed".format(self.ip, self.dport, verb))
            self.agent_mgr.status_set("Last action", verb)
            self.agent_mgr.status_set(
                "Last {0}".format(verb), self.show_clock()
            )
            self.configure(conf)
            self.healthy = healthy

        # first run,
        if self.disabled is None:
            # check configuration options
            for option in self.options:
                getattr(self, option.replace("-", "_"))
                if self.disabled is True:
                    break
            else:
                self.disabled = False
                enabled = str(not bool(self.disabled)).lower()
                self.agent_mgr.status_set("Enabled", enabled)

            if "synscan" not in sys.modules:
                self.err_disable("synscan import error")

        # halt if err-disabled
        if self.disabled:
            return

        # execute the scan
        start_time = eossdk.now()
        try:
            result = scan(self.ip, self.dport, self.nexthop, self.vrf)
        except RuntimeError:
            self.err_disable("synscan runtime error")
            return
        if self.healthy is None:
            self.healthy = result
        self.results.append(result)

        # update health status
        if self.counter < 9999999:
            self.counter += 1
            plus = ""
        else:
            plus = "+"
        if len(self.results) >= 2 and result != self.results[-2]:
            self.counter = 1
        health = "{0}, last {1}{2}".format(
            str(result).lower(), self.counter, plus
        )
        self.agent_mgr.status_set("Healthy", health)

        # prevent results list from growing indefinitely
        if len(self.results) > self.hold_count:
            del self.results[0]

        # check if we should stay in the hold-down state
        if len(self.results) >= self.hold_down:
            hd = -self.hold_down
            if all(self.results[hd:]) and not self.healthy:
                action(conf=self.conf_recover, healthy=True, verb="recover")

        # check if we should stay in the hold-up state
        if len(self.results) >= self.hold_up:
            hu = -self.hold_up
            if not any(self.results[hu:]) and self.healthy:
                action(conf=self.conf_fail, healthy=False, verb="fail")

        # determine next run time
        elapsed_time = eossdk.now() - start_time
        if self.interval:
            if elapsed_time > self.interval:
                self.timeout_time_is(eossdk.now())
            else:
                next_run = self.interval - elapsed_time
                self.timeout_time_is(eossdk.now() + next_run)

    def _subprocess(self, args):
        args = shlex.split(args)
        p = sp.Popen(args, stdout=sp.PIPE, stderr=sp.PIPE)
        stdout, stderr = p.communicate()
        rc = p.returncode
        return stdout, stderr, rc

    def show_clock(self):
        args = 'FastCli -c "show clock"'
        stdout, _, rc = self._subprocess(args)
        if rc:
            self.err_disable("show clock error")
        time = stdout.splitlines()[0]
        return time


def main():
    syslog.openlog(
        ident="SynAcktor-ALERT-AGENT",
        logoption=syslog.LOG_PID,
        facility=syslog.LOG_LOCAL4,
    )

    sdk = eossdk.Sdk()
    _ = SynAcktorAgent(
        agent_mgr=sdk.get_agent_mgr(),
        eapi_mgr=sdk.get_eapi_mgr(),
        timeout_mgr=sdk.get_timeout_mgr(),
        vrf_mgr=sdk.get_vrf_mgr(),
    )
    sdk.main_loop(sys.argv)


if __name__ == "__main__":
    main()

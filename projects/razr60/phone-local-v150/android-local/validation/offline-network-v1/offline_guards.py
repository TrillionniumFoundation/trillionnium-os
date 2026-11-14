"""Small independent parsers for a bounded, USB-only offline test transaction."""
from __future__ import annotations

import hashlib
import json
import re


class UnknownState(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def unique(items):
        out = {}
        for key, value in items:
            if key in out:
                raise UnknownState("duplicate JSON field")
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(UnknownState("nonfinite JSON")))


def switch_value(data, *, absent=False):
    value = data.decode("utf-8").strip()
    if value in ("0", "1"):
        return int(value)
    if absent and value == "null":
        return None
    raise UnknownState("switch is neither stable 0/1" + (" nor absent" if absent else ""))


def subscription_id(data):
    value = data.decode("utf-8").strip()
    if not re.fullmatch(r"0|[1-9][0-9]{0,8}", value):
        raise UnknownState("no explicit valid default data subscription")
    return int(value)


def wifi_status(data):
    # Android's disabled text also covers non-ENABLED transitional states. This
    # field alone never establishes stable off; wifi_on and repeated checks do.
    text = data.decode("utf-8")
    lines = re.findall(r"(?m)^Wifi is (enabled|disabled)\r?$", text)
    labels = re.findall(r"(?m)^Wifi is ", text)
    if len(lines) != 1 or len(labels) != 1:
        raise UnknownState("unique Android Wifi status line not observed")
    return lines[0] == "enabled"


def default_network(data):
    values = re.findall(r"(?m)^[ \t]*Active default network:[ \t]*(none|[0-9]+)[ \t]*\r?$", data.decode("utf-8"))
    # Count every similarly named line too; do not ignore a malformed/conflicting
    # second declaration or interpret a historical log fragment as the header.
    labels = re.findall(r"(?m)^[ \t]*Active default network:", data.decode("utf-8"))
    if len(values) != 1 or len(labels) != 1:
        raise UnknownState("unique complete default-network header not observed")
    return None if values[0] == "none" else int(values[0])


def usb_device(data, serial):
    rows = []
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2:
            raise UnknownState("malformed device record")
        if fields[0] != serial:
            continue
        row = {"serial": fields[0], "state": fields[1]}
        for field in fields[2:]:
            key, separator, value = field.partition(":")
            if separator and key in ("usb", "transport_id", "product", "model", "device"):
                if key in row:
                    raise UnknownState("duplicate device property")
                row[key] = value
        rows.append(row)
    if len(rows) != 1 or rows[0]["state"] != "device":
        raise UnknownState("selected serial is not uniquely online")
    row = rows[0]
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", row.get("usb", "")):
        raise UnknownState("selected device has no affirmative USB transport")
    if not re.fullmatch(r"[1-9][0-9]{0,15}", row.get("transport_id", "")):
        raise UnknownState("selected USB transport ID missing")
    return row


def selected_data_key(key, sub_id):
    # Explicit operator-selected candidate. No storage-mode inference and no
    # fallback from a missing subscription key to a global default.
    if key not in ("mobile_data", "mobile_data" + str(sub_id)):
        raise UnknownState("data key does not match the explicitly selected subscription")
    return key


def stable_controls(first, second):
    keys = ("wifi_on", "wifi_status_enabled", "mobile_data_global", "mobile_data_selected",
            "data_setting_key", "default_data_subscription", "multisim_config")
    return all(first.get(key) == second.get(key) for key in keys)


def offline(snapshot):
    return (snapshot["wifi_on"] == 0 and snapshot["wifi_status_enabled"] is False
            and snapshot["mobile_data_selected"] == 0 and snapshot["default_network_known"] is True
            and snapshot["default_network"] is None)


def restored(original, current):
    # Restore both the explicit candidate and the independent global setting.
    return (current["default_data_subscription"] == original["default_data_subscription"]
            and current["wifi_on"] == original["wifi_on"]
            and current["wifi_status_enabled"] == bool(original["wifi_on"])
            and current["mobile_data_selected"] == original["mobile_data_selected"]
            and current["data_setting_key"] == original["data_setting_key"]
            and current["multisim_config"] == original["multisim_config"]
            and current["mobile_data_global"] == original["mobile_data_global"])


def process_identity(stat_text):
    end = stat_text.rfind(")")
    if end < 0:
        raise UnknownState("malformed process identity")
    pid = int(stat_text[:stat_text.index("(")].strip())
    rest = stat_text[end + 2:].split()
    if len(rest) < 20:
        raise UnknownState("short process identity")
    return {"pid": pid, "pgrp": int(rest[2]), "session": int(rest[3]), "start_ticks": int(rest[19])}

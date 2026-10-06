"""Locate Wireshark's folders and edit its coloring rules, filter buttons and label files."""
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import colors

PLUGIN_NAME = "pcap_labels.lua"
DATA_DIR_NAME = "pcap_labels_data"   # lives next to the plugin; the plugin reads *.tsv from it
FIELD = "pcaplabel.name"
RULE_PREFIX = "Label: "              # coloring rules and filter buttons are named "Label: <name>"

_TSHARK_CANDIDATES = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
)
_GLOBAL_DIR_CANDIDATES = (
    r"C:\Program Files\Wireshark",
    "/usr/share/wireshark",
    "/usr/local/share/wireshark",
    "/Applications/Wireshark.app/Contents/Resources/share/wireshark",
)


class WiresharkError(Exception):
    """A problem with the Wireshark setup that the user can fix."""


@dataclass
class Paths:
    config_dir: Path          # personal configuration (colorfilters, dfilter_buttons)
    lua_plugins_dir: Path     # personal Lua plugins
    global_dir: Path = None   # Wireshark's own files (default colorfilters)

    @property
    def plugin_file(self):
        return self.lua_plugins_dir / PLUGIN_NAME

    @property
    def data_dir(self):
        return self.lua_plugins_dir / DATA_DIR_NAME

    @property
    def colorfilters(self):
        return self.config_dir / "colorfilters"

    @property
    def buttons(self):
        return self.config_dir / "dfilter_buttons"

    def label_file(self, label):
        return self.data_dir / f"{label}.tsv"


def find_tshark():
    found = shutil.which("tshark")
    if found:
        return found
    return next((p for p in _TSHARK_CANDIDATES if os.path.exists(p)), None)


def _folders_from_tshark():
    tshark = find_tshark()
    if not tshark:
        return {}
    try:
        out = subprocess.run([tshark, "-G", "folders"], capture_output=True, text=True,
                             timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    folders = {}
    for line in out.splitlines():
        name, sep, value = line.partition(":\t")
        if sep:
            folders.setdefault(name.strip(), value.strip())
    return folders


def locate(config_dir=None):
    """Find Wireshark's folders. `config_dir` overrides the personal configuration folder."""
    folders = {} if config_dir else _folders_from_tshark()
    if config_dir:
        config = Path(config_dir)
        plugins = config / "plugins"
    elif "Personal configuration" in folders:
        config = Path(folders["Personal configuration"])
        plugins = Path(folders.get("Personal Lua Plugins", config / "plugins"))
    elif sys.platform == "win32":
        config = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Wireshark"
        plugins = config / "plugins"
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "wireshark"
        plugins = Path.home() / ".local" / "lib" / "wireshark" / "plugins"

    global_dir = folders.get("Global configuration") or _folders_from_tshark().get("Global configuration")
    if not global_dir:
        global_dir = next((p for p in _GLOBAL_DIR_CANDIDATES if os.path.exists(p)), None)
    return Paths(config, plugins, Path(global_dir) if global_dir else None)


# ---------------------------------------------------------------- plugin

def install_plugin(paths):
    paths.lua_plugins_dir.mkdir(parents=True, exist_ok=True)
    paths.data_dir.mkdir(exist_ok=True)
    shutil.copy(Path(__file__).with_name(PLUGIN_NAME), paths.plugin_file)


def is_installed(paths):
    return paths.plugin_file.exists()


# ---------------------------------------------------------------- label files

def write_label_file(paths, label, color_hex, dates, source, tz_name, marks):
    paths.data_dir.mkdir(parents=True, exist_ok=True)
    with open(paths.label_file(label), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# name: {label}\n")
        f.write(f"# color: {color_hex}\n")
        f.write(f"# date: {', '.join(d.isoformat() for d in sorted(dates))}\n")
        f.write(f"# timezone: {tz_name}\n")
        f.write(f"# source: {source}\n")
        f.write("# columns: epoch_us<TAB>protocol<TAB>src_ip<TAB>dst_ip\n")
        f.writelines("\t".join(map(str, m)) + "\n" for m in sorted(marks))


def read_label_files(paths):
    """Return a list of dicts (name, color, date, source, marks) for every installed label."""
    labels = []
    if not paths.data_dir.is_dir():
        return labels
    for file in sorted(paths.data_dir.glob("*.tsv")):
        info = {"name": file.stem, "color": "", "date": "", "source": "", "timezone": "", "marks": 0}
        with open(file, encoding="utf-8") as f:
            for line in f:
                if line.startswith("#"):
                    key, sep, value = line[1:].partition(":")
                    if sep and key.strip() in info:
                        info[key.strip()] = value.strip()
                elif line.strip():
                    info["marks"] += 1
        labels.append(info)
    return labels


# ---------------------------------------------------------------- coloring rules

def _parse_rule(line):
    """'@name@filter@[bg][fg]' -> (name, filter, colors_text), or None for comments/blank lines.

    A leading '!' means the rule is disabled.
    """
    body = line.rstrip("\r\n").lstrip("!")
    if not body.startswith("@"):
        return None
    parts = body.split("@")
    if len(parts) < 4:
        return None
    return parts[1], "@".join(parts[2:-1]), parts[-1]


def _rule_background(line):
    parsed = _parse_rule(line)
    rgb = colors.from_wireshark(parsed[2]) if parsed else []
    return rgb[0] if rgb else None


def _rule_name(line):
    parsed = _parse_rule(line)
    return parsed[0] if parsed else None


def load_color_rules(paths):
    """Lines of the personal colorfilters file, or Wireshark's defaults if there is none yet.

    A personal file replaces the global one entirely, so starting from the defaults
    is what keeps Wireshark's built-in rules.
    """
    if paths.colorfilters.exists():
        source = paths.colorfilters
    elif paths.global_dir and (paths.global_dir / "colorfilters").exists():
        source = paths.global_dir / "colorfilters"
    else:
        raise WiresharkError(
            "Could not find Wireshark's default coloring rules, and writing a new file would "
            "hide them. Open Wireshark, go to View > Coloring Rules, click OK, then run this again.")
    with open(source, encoding="utf-8") as f:
        return f.readlines()


def save_color_rules(paths, lines):
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    if paths.colorfilters.exists():
        shutil.copy(paths.colorfilters, str(paths.colorfilters) + ".bak")
    with open(paths.colorfilters, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(l if l.endswith("\n") else l + "\n" for l in lines)


def label_filter(label):
    return f'{FIELD} == "{label}"'


def make_rule(label, rgb):
    return "@%s%s@%s@%s%s\n" % (RULE_PREFIX, label, label_filter(label),
                                colors.to_wireshark(rgb),
                                colors.to_wireshark(colors.text_color_for(rgb)))


def rules_using_color(lines, rgb, ignore_label=None):
    """Names of rules whose background is `rgb`, except the rule of `ignore_label`."""
    own = RULE_PREFIX + ignore_label if ignore_label else None
    return [_rule_name(l) for l in lines if _rule_background(l) == rgb and _rule_name(l) != own]


def set_label_rule(lines, label, rgb, remove_rules=(), last=False):
    """Return new lines with the rule for `label` set to `rgb`.

    Wireshark colors a packet by the first rule that matches, so position is priority.
    A new label goes first: it wins over other labels and over Wireshark's built-in rules.
    With `last`, it goes after the other labels but still before the built-in rules, so
    it only colors packets no other label claims. An existing rule for the same label
    keeps its position unless `last` is given. Rules named in `remove_rules` are dropped
    (used when the user chose to overwrite a rule with the same color).
    """
    own = RULE_PREFIX + label
    rule = make_rule(label, rgb)
    out, placed = [], False
    for line in lines:
        name = _rule_name(line)
        if name == own:
            if not placed and not last:
                out.append(rule)
                placed = True
        elif name is not None and name in remove_rules:
            continue
        else:
            out.append(line)
    if not placed:
        rule_positions = [i for i, l in enumerate(out) if _parse_rule(l)]
        label_positions = [i for i in rule_positions if _rule_name(out[i]).startswith(RULE_PREFIX)]
        if last and label_positions:
            position = label_positions[-1] + 1
        else:
            position = rule_positions[0] if rule_positions else len(out)
        out.insert(position, rule)
    return out


def remove_rules_named(lines, predicate):
    return [l for l in lines if _rule_name(l) is None or not predicate(_rule_name(l))]


# ---------------------------------------------------------------- filter buttons

def _uat_quote(text):
    """Wireshark's table files escape quotes and backslashes as \\xNN."""
    return "".join("\\x%02x" % ord(c) if c in '"\\' or not c.isprintable() else c for c in text)


def _button_label(line):
    parts = line.split('","')
    return parts[1] if len(parts) >= 3 else None


def load_buttons(paths):
    if not paths.buttons.exists():
        return []
    with open(paths.buttons, encoding="utf-8") as f:
        return f.readlines()


def save_buttons(paths, lines):
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    with open(paths.buttons, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(l if l.endswith("\n") else l + "\n" for l in lines)


def set_label_button(lines, label):
    name = RULE_PREFIX + label
    button = '"TRUE","%s","%s","%s"\n' % (
        name, _uat_quote(label_filter(label)), f"Packets labeled {label} (pcap-labels)")
    out = [l for l in lines if _button_label(l) != name]
    out.append(button)
    return out


def remove_buttons_named(lines, predicate):
    return [l for l in lines if _button_label(l) is None or not predicate(_button_label(l))]

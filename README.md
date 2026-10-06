# pcap-labels

Show labeled packets in Wireshark. You give it a CSV of packets your team has labeled; it colors those packets in the Wireshark packet list and adds a filter button for them.

- **Several labels at once**, each with its own name and color.
- **Day-specific**: a label only matches packets from the capture day of its CSV.
- **Works on split captures**: packets are identified by time, not frame number, so the same label works on the full pcap and on any part cut from it.

## Requirements

- Python 3.9 or newer
- Wireshark with Lua support (the standard installers include it; tested on 4.6)
- Windows, Linux or macOS

## Install

From the project folder:

```bash
pip install .
```

Then install the Wireshark plugin (once per computer) and restart Wireshark:

```bash
pcap-labels install
```

### If `pcap-labels` is not found

This means the folder where pip puts commands is not on your PATH. It is common with Python from the Microsoft Store. Any of these fixes it:

- **Use the module form.** It always works, with no setup: write `python -m pcap_labels` instead of `pcap-labels` in every command.
- **Add the scripts folder to your PATH.** `pip install .` prints a warning with the folder (`... Scripts' which is not on PATH`). On Windows, add it for your user in PowerShell, replacing the path with the one from the warning, then open a new terminal:

  ```powershell
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";C:\path\from\the\warning\Scripts", "User")
  ```

With Python from python.org, ticking "Add python.exe to PATH" in the installer usually avoids the problem.

## Quick start

1. Add a label from a CSV:

   ```bash
   pcap-labels add malicious.csv --name malicious --color pink --date 2023-06-19
   ```

2. **Restart Wireshark** and open a capture from that day. Wireshark reads coloring rules and filter buttons only when it starts, so a new label, a new color or a removed label shows up after a restart. The command tells you which is needed: when you only update the rows of an existing label, **Ctrl+R** is enough.

3. Labeled packets are shown in the label's color. To show only them, click the **Label: malicious** button in the filter toolbar, or type a filter:

   ```
   pcaplabel.name == "malicious"
   ```

   `pcaplabel` on its own matches packets with any label.

## Commands

| Command | What it does |
|---|---|
| `pcap-labels install` | Installs the Wireshark plugin |
| `pcap-labels add <csv> --name <label> --color <color>` | Adds a label, or updates it if the name already exists |
| `pcap-labels list` | Shows installed labels with color, day and number of marks |
| `pcap-labels remove <label> [<label> ...]` | Removes labels with their coloring rules and buttons |
| `pcap-labels uninstall` | Removes the plugin and all labels from Wireshark |

### Options for `add`

| Option | Short | Meaning |
|---|---|---|
| `--name` | `-n` | Label name. Letters, digits, `_`, `-` and `.` |
| `--color` | `-c` | `#RRGGBB`, or one of: pink, red, orange, yellow, green, cyan, blue, purple, gray |
| `--date YYYY-MM-DD` | `-d` | Capture day. Needed only when the CSV timestamps have no date (see below) |
| `--timezone` | `-z` | Time zone of the CSV timestamps. Default `Asia/Jerusalem`; also accepts fixed offsets such as `UTC+3` |
| `--last` | `-l` | Put the label after the other labels instead of first (see "Packets with several labels") |
| `--by-class` | `-b` | One label per value of the `class` column, named `<name>-<value>` |
| `--class-column` | `-C` | Column used by `--by-class`. Default `class` |
| `--on-conflict overwrite\|add` | `-o` | Answers the color-conflict question in advance (see below) |

Other short forms: `-y` for `uninstall --yes`, `-w` for `--wireshark-dir`, `-V` for `--version`.

The quick-start command in short form:

```bash
pcap-labels add malicious.csv -n malicious -c pink -d 2023-06-19
```

### The capture day

A label matches a packet only when date and time both agree, so a label from 19 June never colors packets from another day.

- If the timestamps contain a date (`Jun 19, 2023 12:15:58.387265000`), it is used.
- Otherwise pass `--date`.
- Without `--date`, the tool looks for a date in the CSV's file or folder name (`2023-06-19`, `20230619`, or `06_19` when the year appears in the timestamps) and asks you to confirm it.

### Colors already in use

- Adding a label whose name already exists replaces it, including its color.
- If the color is already used by a different coloring rule (one of Wireshark's own or another label), the tool asks whether to **overwrite** that rule, **add** the label anyway, or **change** the color. With `--on-conflict` it does not ask.

Label rules are placed above Wireshark's default rules, which are kept. The previous rules file is saved as `colorfilters.bak` before every change.

### Packets with several labels

A packet can carry several labels, and every label's filter finds it, but Wireshark shows only one color per packet: the color of the first matching rule in *View → Coloring Rules*.

- By default a new label is placed **first**, so the label added most recently wins.
- With `--last` (`-l`) the label is placed after the other labels, so it only colors packets that no other label matches. It still comes before Wireshark's built-in rules.
- Updating an existing label keeps its position, unless you pass `--last`.

To find packets that have two labels: `pcaplabel.name == "malicious" && pcaplabel.name == "review"`.

### Several labels from one CSV

```bash
pcap-labels add traffic.csv --name traffic --by-class --color green,red --date 2023-06-19
```

With `class` values `0` and `1` this creates `traffic-0` (green) and `traffic-1` (red). Colors are assigned in sorted order of the class values.

## CSV format

Columns are found by name (case-insensitive); extra columns are ignored.

```
timestamp,src_ip,tcp src_port,dst_ip,ip dst,tcp dst port,udp dst port,protocol,class
"Jun 19, 2023 12:15:58.769286000 Jerusalem Daylight Time",192.0.2.10,,5353,224.0.0.251,,5353,MDNS,1
```

| Column | Use |
|---|---|
| `timestamp` (or `time`, `frame.time`) | Required. Packet time to the microsecond, as Wireshark prints it |
| `src_ip`, `ip dst` (or `ip src`, `dst_ip`, `ip.src`, `ip.dst`) | Recommended. Tell apart packets that share the same microsecond. Values that are not IP addresses are ignored |
| `protocol` | Used only for rows without IP addresses, such as ARP |
| `class` | Used only with `--by-class` |

Frame numbers are not used, because they restart at 1 in every split file.

## Troubleshooting

**No packets are colored.**
1. Restart Wireshark. This is needed after `pcap-labels install` and after adding a label or changing its color; Ctrl+R does not reload coloring rules or buttons.
2. Type `pcaplabel` in the filter bar. If the bar turns red, the plugin is not loaded: check *Help → About Wireshark → Plugins* for `pcap_labels.lua`.
3. If the filter is valid but shows nothing, the label's day or time zone does not match the capture. Run `pcap-labels list` and compare the day with the file you opened; check `--timezone`.
4. If the filter shows packets but without color, turn on *View → Colorize Packet List* and check that the rule is enabled in *View → Coloring Rules*.

**Other profiles.** Coloring rules and buttons are written to Wireshark's default profile.

**Custom Wireshark location.** Folders are found with `tshark -G folders`. If that fails, pass `--wireshark-dir <personal configuration folder>` before the command name.

## How it works

`pcap-labels add` converts each CSV row to a mark: packet time in microseconds since 1970 (UTC), plus source and destination IP, or the protocol when there are no IPs. Marks are saved per label in `pcap_labels_data/<label>.tsv`, next to the plugin in Wireshark's personal Lua plugins folder.

The plugin (`pcap_labels.lua`) loads those files and adds a `pcaplabel.name` field to every matching packet. Coloring rules and filter buttons are ordinary Wireshark rules on that field.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests run against a temporary configuration folder and do not need Wireshark.

"""Command line interface: pcap-labels install | add | list | remove | uninstall."""
import argparse
import re
import shutil
import sys
from datetime import date
from pathlib import Path

from . import __version__, colors, csv_reader, wireshark

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# Wireshark reads coloring rules and filter buttons only when it starts;
# Ctrl+R (reload) only makes the plugin re-read the label files.
RESTART_HINT = "Restart Wireshark to see the change (coloring rules and buttons are read at startup)."
RELOAD_HINT = "In Wireshark press Ctrl+R to reload the capture."


class UserError(Exception):
    """Something the user can fix; shown without a traceback."""


def _interactive():
    return sys.stdin is not None and sys.stdin.isatty()


def _read(prompt):
    try:
        return input(prompt)
    except EOFError:
        print()
        raise UserError("No answer was given. Run again and answer the question, "
                        "or pass the matching option (see --help).")


def _ask(prompt, choices):
    while True:
        answer = _read(prompt).strip().lower()
        if answer in choices:
            return answer
        print(f"  Please answer one of: {', '.join(choices)}")


def _check_label(name):
    if not _LABEL_RE.match(name):
        raise UserError(f"Invalid label name '{name}'. Use letters, digits, '_', '-' and '.' only.")
    return name


# ---------------------------------------------------------------- install / uninstall

def cmd_install(args, paths):
    wireshark.install_plugin(paths)
    print(f"Installed the Wireshark plugin: {paths.plugin_file}")
    print("Restart Wireshark, then add labels with:  pcap-labels add <file.csv> --name <label> --color <color>")


def cmd_uninstall(args, paths):
    if not args.yes:
        if not _interactive():
            raise UserError("Pass --yes to uninstall without a confirmation prompt.")
        if _ask("Remove the plugin, all labels, their coloring rules and buttons? [y/n] ",
                ("y", "n")) == "n":
            return
    ours = lambda name: name.startswith(wireshark.RULE_PREFIX)
    if paths.colorfilters.exists():
        wireshark.save_color_rules(paths, wireshark.remove_rules_named(
            wireshark.load_color_rules(paths), ours))
    if paths.buttons.exists():
        wireshark.save_buttons(paths, wireshark.remove_buttons_named(
            wireshark.load_buttons(paths), ours))
    if paths.plugin_file.exists():
        paths.plugin_file.unlink()
    shutil.rmtree(paths.data_dir, ignore_errors=True)
    print("pcap-labels was removed from Wireshark. Restart Wireshark to finish.")


# ---------------------------------------------------------------- add

def _resolve_date(args, rows, columns):
    """The date to use for timestamps that carry none (None if the CSV has full dates)."""
    if args.date:
        return args.date
    if csv_reader.has_dates(rows, columns):
        return None
    guess = csv_reader.guess_date_from_path(args.csv, csv_reader.first_timestamp(rows, columns))
    if guess and _interactive():
        print(f"The timestamps in this CSV have no date. From the file location it looks like {guess}.")
        if _ask(f"Were these packets captured on {guess}? [y/n] ", ("y", "n")) == "y":
            return guess
    raise UserError("The timestamps in this CSV have no date. Pass the capture day with --date YYYY-MM-DD.")


def _split_by_class(args, rows, columns):
    """Return [(label_name, rows)] - one entry, or one per class value with --by-class."""
    if not args.by_class:
        return [(_check_label(args.name), rows)]
    class_col = columns.get(args.class_column.lower())
    if not class_col:
        raise UserError(f"--by-class needs a '{args.class_column}' column, which this CSV does not have.")
    groups = {}
    for row in rows:
        groups.setdefault((row.get(class_col) or "").strip() or "none", []).append(row)
    return [(_check_label(f"{args.name}-{value}"), groups[value]) for value in sorted(groups)]


def _resolve_color(label, rgb, rule_lines, on_conflict):
    """Handle a color already used by another coloring rule.

    Returns (rgb, rules_to_remove). The label's own existing rule is never a conflict:
    it is simply replaced.
    """
    while True:
        clashing = wireshark.rules_using_color(rule_lines, rgb, ignore_label=label)
        if not clashing:
            return rgb, ()
        names = ", ".join(f"'{n}'" for n in clashing)
        if on_conflict == "overwrite":
            return rgb, tuple(clashing)
        if on_conflict == "add":
            return rgb, ()
        if not _interactive():
            raise UserError(
                f"Color {colors.to_hex(rgb)} is already used by the coloring rule {names}. "
                "Choose another --color, or pass --on-conflict overwrite|add.")
        print(f"Color {colors.to_hex(rgb)} is already used by the coloring rule {names}.")
        choice = _ask("  [o]verwrite that rule, [a]dd this label anyway, or [c]hange color? ",
                      ("o", "a", "c"))
        if choice == "o":
            return rgb, tuple(clashing)
        if choice == "a":
            return rgb, ()
        while True:
            try:
                rgb = colors.parse_color(_read("  New color (name or #RRGGBB): "))
                break
            except ValueError as e:
                print(f"  {e}")


def cmd_add(args, paths):
    csv_path = Path(args.csv)
    if not csv_path.is_file():
        raise UserError(f"File not found: {csv_path}")
    rows, columns = csv_reader.read_rows(csv_path)
    if not rows:
        raise UserError(f"{csv_path.name} has no data rows.")

    groups = _split_by_class(args, rows, columns)
    color_names = [c for c in args.color.split(",") if c.strip()]
    if len(color_names) != len(groups):
        raise UserError(
            f"Got {len(color_names)} color(s) for {len(groups)} label(s) "
            f"({', '.join(name for name, _ in groups)}). Pass one color per label, comma-separated.")
    try:
        rgbs = [colors.parse_color(c) for c in color_names]
    except ValueError as e:
        raise UserError(str(e))

    default_date = _resolve_date(args, rows, columns)
    tz = csv_reader.parse_timezone(args.timezone)

    rule_lines = wireshark.load_color_rules(paths)
    button_lines = wireshark.load_buttons(paths)
    rules_on_disk = paths.colorfilters.exists() and list(rule_lines)
    buttons_on_disk = list(button_lines)
    newly_installed = not wireshark.is_installed(paths)
    for (label, label_rows), rgb in zip(groups, rgbs):
        marks, dates, skipped = csv_reader.rows_to_marks(label_rows, columns, tz, default_date)
        if not marks:
            raise UserError(f"No usable rows for label '{label}' (no readable timestamps).")
        rgb, to_remove = _resolve_color(label, rgb, rule_lines, args.on_conflict)
        wireshark.write_label_file(paths, label, colors.to_hex(rgb), dates,
                                   csv_path.resolve(), args.timezone, marks)
        rule_lines = wireshark.set_label_rule(rule_lines, label, rgb, to_remove, last=args.last)
        button_lines = wireshark.set_label_button(button_lines, label)

        days = ", ".join(d.isoformat() for d in sorted(dates))
        print(f"Label '{label}': {len(label_rows)} rows -> {len(marks)} packet marks, "
              f"color {colors.to_hex(rgb)}, day {days}")
        if skipped:
            print(f"  Skipped {skipped} rows without a readable time.")
        for name in to_remove:
            print(f"  Replaced the coloring rule '{name}'.")
    if newly_installed:
        wireshark.install_plugin(paths)
        print(f"Installed the Wireshark plugin: {paths.plugin_file}")
    appearance_changed = rule_lines != rules_on_disk or button_lines != buttons_on_disk
    if appearance_changed:
        wireshark.save_color_rules(paths, rule_lines)
        wireshark.save_buttons(paths, button_lines)
    print(RESTART_HINT if appearance_changed or newly_installed else RELOAD_HINT)
    print(f'Filter for one label:  {wireshark.label_filter(groups[0][0])}     Any label:  pcaplabel')


# ---------------------------------------------------------------- list / remove

def cmd_list(args, paths):
    labels = wireshark.read_label_files(paths)
    if not labels:
        print("No labels yet. Add one with:  pcap-labels add <file.csv> --name <label> --color <color>")
        return
    header = ("LABEL", "COLOR", "DAY", "MARKS", "SOURCE")
    table = [header] + [(l["name"], l["color"], l["date"], str(l["marks"]), l["source"]) for l in labels]
    widths = [max(len(row[i]) for row in table) for i in range(len(header) - 1)]
    for row in table:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)) + "  " + row[-1])


def cmd_remove(args, paths):
    existing = {l["name"] for l in wireshark.read_label_files(paths)}
    missing = [n for n in args.names if n not in existing]
    if missing:
        raise UserError(f"No such label: {', '.join(missing)}. See:  pcap-labels list")
    names = {wireshark.RULE_PREFIX + n for n in args.names}
    for name in args.names:
        paths.label_file(name).unlink()
    if paths.colorfilters.exists():
        wireshark.save_color_rules(paths, wireshark.remove_rules_named(
            wireshark.load_color_rules(paths), names.__contains__))
    wireshark.save_buttons(paths, wireshark.remove_buttons_named(
        wireshark.load_buttons(paths), names.__contains__))
    print(f"Removed: {', '.join(args.names)}")
    print(RESTART_HINT)


# ---------------------------------------------------------------- entry point

def build_parser():
    parser = argparse.ArgumentParser(
        prog="pcap-labels",
        description="Show labeled packets from CSV files in Wireshark, one color per label.")
    parser.add_argument("-V", "--version", action="version", version=f"pcap-labels {__version__}")
    parser.add_argument("-w", "--wireshark-dir", metavar="DIR",
                        help="Wireshark personal configuration folder (found automatically by default)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("install", help="install the Wireshark plugin (once per computer)")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("add", help="add or update a label from a CSV file")
    p.add_argument("csv", help="CSV file with the labeled packets")
    p.add_argument("-n", "--name", required=True, help="label name, e.g. malicious")
    p.add_argument("-c", "--color", required=True,
                   help=f"#RRGGBB or one of: {', '.join(colors.NAMED_COLORS)}. "
                        "With --by-class: one color per class, comma-separated")
    p.add_argument("-d", "--date", type=date.fromisoformat, metavar="YYYY-MM-DD",
                   help="capture day, needed when the CSV timestamps have no date")
    p.add_argument("-z", "--timezone", default="Asia/Jerusalem",
                   help="time zone of the CSV timestamps, e.g. Asia/Jerusalem or UTC+3 "
                        "(default: %(default)s)")
    p.add_argument("-b", "--by-class", action="store_true",
                   help="make one label per value of the class column, named <name>-<value>")
    p.add_argument("-C", "--class-column", default="class", help="column used by --by-class (default: class)")
    p.add_argument("-o", "--on-conflict", choices=("overwrite", "add"),
                   help="what to do when another coloring rule already uses the color, instead of asking")
    p.add_argument("-l", "--last", action="store_true",
                   help="put the label after the other labels, so it only colors packets "
                        "that no other label matches (default: first, winning over other labels)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("list", help="show the installed labels")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("remove", help="remove one or more labels")
    p.add_argument("names", nargs="+", metavar="name")
    p.set_defaults(func=cmd_remove)

    p = sub.add_parser("uninstall", help="remove the plugin and all labels from Wireshark")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_uninstall)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args, wireshark.locate(args.wireshark_dir))
    except (UserError, csv_reader.CsvError, wireshark.WiresharkError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

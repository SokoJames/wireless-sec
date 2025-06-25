# utils.py
# Shared utility functions and constants for Wi-Fi Traffic Analyzer

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

# Color codes for traffic types and alerts
TRAFFIC_COLOR_MAP = {
    'browsing': '36',     # cyan
    'streaming': '35',    # magenta
    'attack': '31',       # red
    'anomaly': '33',      # yellow
    'intrusion': '41;97', # white on red bg
    'normal': '32',       # green
    'unknown': '37',      # white
}

COLORS = {
    'info': '36',        # cyan
    'anomaly': '33',     # yellow
    'attack': '31',      # red
    'intrusion': '41;97',# white on red bg
    'success': '32',     # green
    'summary': '1;34',   # bold blue
    'traffic': '35',     # magenta
    'pattern': '1;30',   # bold black
}

def print_table(title, rows, columns=None, color_map=None):
    print(f"\n--- {title} ---")
    if not rows:
        print("(none)")
        return
    if columns is None:
        columns = list(rows[0].keys())
    col_widths = [max(len(str(col)), max(len(str(row.get(col,''))) for row in rows)) for col in columns]
    sep = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    fmt = "| " + " | ".join([f"{{:<{w}}}" for w in col_widths]) + " |"
    print(sep)
    print(fmt.format(*columns))
    print(sep)
    for row in rows:
        vals = [str(row.get(col,'')) for col in columns]
        if color_map:
            # Use color_map to color the row based on a key (e.g., traffic type)
            key = row.get('Type') or row.get('type') or row.get('Event') or row.get('event_type') or row.get('Traffic')
            color_code = color_map.get(str(key).lower(), None)
            if color_code:
                print(color_text(fmt.format(*vals), color_code))
            else:
                print(fmt.format(*vals))
        else:
            print(fmt.format(*vals))
    print(sep)

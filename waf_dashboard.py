"""WAF dashboard - server-rendered HTML."""
import html as _html_module

CONFIG = {
    "page_title":        "WAF Event Log",
    "header_link_text":  "Back to BookWorm",
    "header_link_url":   "http://127.0.0.1:8000/",
    "refresh_seconds":   10,                    # auto-reload interval
    "control_endpoint":  "/waf_control",
    "secret_param":      "supersecretwafkey",  # must match waf_proxy.py
    "max_events_shown":  100,
}
#מוגן מxxs
def _esc(value):
    return _html_module.escape(str(value), quote=True)


def _hidden(name, value):
    return f'<input type="hidden" name="{_esc(name)}" value="{_esc(value)}">'

def section_heading(title):
    return f'<div class="section-title">{_esc(title)}</div>'


def config_card(*groups):
    body = "\n".join(groups)
    return f'<div class="config-box">\n{body}\n</div>'

#כפתורים
def control_form(action_name, submit_label, css_class="config-btn",
                 extra_fields=None, inline_input=None):
    fields = {"action": action_name, "secret": CONFIG["secret_param"]}
    if extra_fields:
        fields.update(extra_fields)
    hidden = "\n  ".join(_hidden(k, v) for k, v in fields.items())

    visible_input = ""
    form_style = "display:inline"
    if inline_input is not None:
        name, placeholder = inline_input
        visible_input = (
            f'<input type="text" name="{_esc(name)}" '
            f'class="blacklist-input" placeholder="{_esc(placeholder)}" required>'
        )
        form_style = "margin-top:8px; display:flex; gap:6px;"

    return f"""
<form action="{_esc(CONFIG["control_endpoint"])}" method="get" style="{form_style}">
  {hidden}
  {visible_input}
  <button type="submit" class="{_esc(css_class)}">{_esc(submit_label)}</button>
</form>
"""


def mode_badge(mode):
    if mode == "dry_run":
        return '<span class="mode-indicator mode-dryrun">Dry Run (detect only)</span>'
    return '<span class="mode-indicator mode-blocking">Blocking (active)</span>'


def reason_badge(reason):
    return f'<span class="badge badge-{classify_reason(reason)}">{_esc(reason)}</span>'


# ─── Sections ────────────────────────────────────────────────────
# Copy one of these to add a new control panel.

def _mode_section(mode):
    return f"""
<div class="config-group">
  <h3>WAF Mode</h3>
  {mode_badge(mode)}
  {control_form("toggle_mode", "Toggle Mode")}
</div>
"""


def _blacklist_row(entry):
    return f"""
<div class="blacklist-row">
  <span>{_esc(entry["ip"])}</span>
  <span style="color:#999;font-size:11px;">(expires in {_esc(entry["expires_in"])}s)</span>
  {control_form(
      "remove_blacklist",
      "Remove",
      css_class="remove-btn",
      extra_fields={"ip": entry["ip"]},
  )}
</div>
"""


def _blacklist_section(blacklist):
    if not blacklist:
        rows = '<em style="color:#999;font-size:13px;">No IPs blacklisted</em>'
    else:
        rows = "\n".join(_blacklist_row(e) for e in blacklist)

    add_form = control_form(
        "add_blacklist",
        "Add IP",
        css_class="add-btn",
        inline_input=("ip", "e.g. 1.2.3.4"),
    )
    return f"""
<div class="config-group">
  <h3>IP Blacklist</h3>
  {rows}
  {add_form}
</div>
"""


def _events_table(events):
    if not events:
        body = '<tr><td colspan="5" class="empty-msg">No events recorded yet.</td></tr>'
    else:
        body = "\n".join(_event_row(ev) for ev in events)
    return f"""
<div class="events-box">
  <table>
    <thead>
      <tr>
        <th style="width:50px">#</th>
        <th style="width:160px">Time</th>
        <th style="width:110px">IP</th>
        <th>URL</th>
        <th style="width:260px">Reason</th>
      </tr>
    </thead>
    <tbody>
{body}
    </tbody>
  </table>
</div>
"""


def _event_row(ev):
    return f"""<tr>
  <td>{_esc(ev["id"])}</td>
  <td>{_esc(ev["timestamp"])}</td>
  <td>{_esc(ev["ip"])}</td>
  <td>{_esc(ev["url"])}</td>
  <td>{reason_badge(ev["reason"])}</td>
</tr>"""


# ─── Page chrome ─────────────────────────────────────────────────

def _html_page(title, refresh_seconds, body_parts):
    body = "\n".join(body_parts)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="{refresh_seconds}">
  <title>{_esc(title)}</title>
  <style>{_STYLES}</style>
</head>
<body>
{body}
</body>
</html>"""


def _header_bar(title, link_text, link_url):
    return f"""
<div class="header">
  <span>{_esc(title)}</span>
  <a href="{_esc(link_url)}">{_esc(link_text)}</a>
</div>
"""


def _container(children):
    return f'<div class="container">\n' + "\n".join(children) + "\n</div>"

def draw_dashboard(mode, blacklist, events):
    events = events[: CONFIG["max_events_shown"]]
    return _html_page(
        title=CONFIG["page_title"],
        refresh_seconds=CONFIG["refresh_seconds"],
        body_parts=[
            _header_bar(
                CONFIG["page_title"],
                CONFIG["header_link_text"],
                CONFIG["header_link_url"],
            ),
            _container([
                section_heading("WAF Configuration"),
                config_card(
                    _mode_section(mode),
                    _blacklist_section(blacklist),
                ),
                section_heading(
                    f'Live Events (auto-refreshes every {CONFIG["refresh_seconds"]} seconds)'
                ),
                _events_table(events),
            ]),
        ],
    )

#עיצוב
_REASON_KEYWORDS = [
    (("sqli", "sql"),                "sqli"),
    (("xss",),                       "xss"),
    (("traversal",),                 "traversal"),
    (("rate limit", "rate limiting"), "rate"),
    (("ddos", "challenge"),          "ddos"),
    (("blacklist",),                 "blacklist"),
    (("header", "body", "large", "size"), "size"),
]


def classify_reason(reason):
    r = reason.lower()
    for keywords, css_class in _REASON_KEYWORDS:
        if any(kw in r for kw in keywords):
            return css_class
    return "other"

_STYLES = """
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: Arial, sans-serif;
      background: #f5f5f5;
      color: #333;
    }

    .header {
      background: #2c3e50;
      color: white;
      padding: 16px 24px;
      font-size: 20px;
      font-weight: bold;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header a { color: #aaa; font-size: 13px; text-decoration: none; }
    .header a:hover { color: white; }

    .container {
      max-width: 1100px;
      margin: 20px auto;
      padding: 0 16px;
    }

    .section-title {
      font-size: 18px;
      font-weight: bold;
      margin: 0 0 12px 0;
      padding-bottom: 6px;
      border-bottom: 2px solid #2c3e50;
    }

    .mode-indicator {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 12px;
    }
    .mode-dryrun   { background: #d4edda; color: #155724; }
    .mode-blocking { background: #f8d7da; color: #721c24; }

    .config-box {
      background: white;
      border: 1px solid #ddd;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
    }
    .config-group { flex: 1; min-width: 280px; }
    .config-group h3 { font-size: 14px; margin-bottom: 8px; }

    .config-btn {
      padding: 6px 14px;
      border: 1px solid #999;
      border-radius: 4px;
      background: white;
      cursor: pointer;
      font-size: 13px;
    }
    .config-btn:hover { background: #eee; }

    .blacklist-row {
      display: flex;
      align-items: center;
      gap: 6px;
      margin: 4px 0;
      font-size: 13px;
    }
    .blacklist-input {
      padding: 5px 8px;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 13px;
      width: 160px;
    }

    .add-btn {
      padding: 5px 12px;
      background: #2c3e50;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    .add-btn:hover { background: #1a252f; }

    .remove-btn {
      padding: 2px 8px;
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    .remove-btn:hover { background: #c0392b; }

    .events-box {
      background: white;
      border: 1px solid #ddd;
      border-radius: 6px;
      overflow-y: auto;
      max-height: 600px;
      margin-bottom: 40px;
    }

    table { width: 100%; border-collapse: collapse; }
    thead th {
      text-align: left;
      padding: 8px 12px;
      font-size: 12px;
      background: #f0f0f0;
      border-bottom: 2px solid #ddd;
      position: sticky;
      top: 0;
    }
    tbody td {
      padding: 6px 12px;
      font-size: 13px;
      border-bottom: 1px solid #eee;
    }
    tbody tr:nth-child(even) { background: #fafafa; }

    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: bold;
    }
    .badge-sqli      { background: #fde8e8; color: #e74c3c; }
    .badge-xss       { background: #fef5ec; color: #e67e22; }
    .badge-traversal { background: #f3e8fd; color: #9b59b6; }
    .badge-rate      { background: #ebf5fb; color: #3498db; }
    .badge-ddos      { background: #eaf2f8; color: #2c3e50; }
    .badge-blacklist { background: #eafaf1; color: #27ae60; }
    .badge-size      { background: #fdeef5; color: #e84393; }
    .badge-other     { background: #f0f0f0; color: #666;    }

    .empty-msg { text-align: center; padding: 24px; color: #999; }
"""

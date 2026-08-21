"""
Regex lab — learn `re` on this project's own log lines.

Not part of the pipeline. Run it, read it, break it, re-run it:

    python3 regex_lab.py

Each section prints what it demonstrates. The exercises at the bottom are
deliberately failing until you fix them.
"""

import re

SEP = "\n" + "=" * 70


# ---------------------------------------------------------------------------
# 1. A regex is a pattern that describes the SHAPE of text.
# ---------------------------------------------------------------------------
#
#   Literal characters match themselves.  `port` matches the word "port".
#
#   The building blocks you need for logs, and nothing more:
#
#     \d      one digit                     0-9
#     \w      one "word" char               letter, digit or underscore
#     \s      one whitespace char           space, tab
#     \S      one NON-whitespace char       <- the workhorse for log tokens
#     .       any character at all
#     [abc]   one of a, b or c              a "character class"
#     [^abc]  anything EXCEPT a, b or c
#     [0-9.]  one digit or a dot            ranges work inside classes
#
#   Quantifiers say HOW MANY of the thing before them:
#
#     +       one or more        \d+     "22", "54321"
#     *       zero or more
#     ?       zero or one        colou?r  "color" and "colour"
#     {2,4}   between 2 and 4
#
#   Anchors:
#
#     ^       start of string
#     $       end of string
#
#   Escape a character to match it literally:  \.  is a real dot, not "any".

def section_1_matching():
    print(SEP)
    print("1. MATCHING — does this line have the shape I expect?\n")

    line = "Failed password for root from 192.0.2.3 port 54323 ssh2"

    checks = [
        (r"Failed password",  "literal text"),
        (r"port \d+",         r"\d+ = one or more digits"),
        (r"port \d",          "one digit is enough to match — \\d+ is greedy but \\d isn't required to be"),
        (r"^Failed",          "^ anchors to the start"),
        (r"ssh2$",            "$ anchors to the end"),
        (r"^Accepted",        "does NOT match — line starts with 'Failed'"),
    ]

    for pattern, why in checks:
        hit = re.search(pattern, line)
        print(f"  {'MATCH  ' if hit else 'no     '} {pattern:<20} {why}")

    print("\n  re.search() looks anywhere in the string.")
    print("  re.match()  only at the start. Prefer search() + ^ if you mean it.")


# ---------------------------------------------------------------------------
# 2. Capturing — pull values OUT instead of just testing.
# ---------------------------------------------------------------------------
#
#   Parentheses create a capture group. Whatever the group matched is
#   retrievable afterwards. This is the part that replaces
#   `parts[parts.index("from") + 1]`.

def section_2_capturing():
    print(SEP)
    print("2. CAPTURING — parentheses pull values out\n")

    line = "Failed password for root from 192.0.2.3 port 54323 ssh2"

    m = re.search(r"for (\S+) from (\S+) port (\d+)", line)
    print(f"  pattern: for (\\S+) from (\\S+) port (\\d+)")
    print(f"  group(1) = {m.group(1)!r}   <- username")
    print(f"  group(2) = {m.group(2)!r}   <- source ip")
    print(f"  group(3) = {m.group(3)!r}   <- port")
    print(f"  groups() = {m.groups()}")

    print("\n  Numbered groups break the moment you add a group in the middle.")
    print("  Name them instead:  (?P<name>...)\n")

    m = re.search(
        r"for (?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)",
        line
    )
    print(f"  m.group('username') = {m.group('username')!r}")
    print(f"  m.groupdict()       = {m.groupdict()}")

    print("\n  ^ That dict is the whole point. It goes straight into create_event().")


# ---------------------------------------------------------------------------
# 3. Optional parts — one pattern, many line variants.
# ---------------------------------------------------------------------------
#
#   This is what the current token-index parser cannot do.
#
#     (?:...)    a group that does NOT capture — just for grouping
#     (?:...)?   ...and is optional
#     a|b        alternation: a or b
#
#   sshd writes the same event several ways:
#
#     Failed password for root from 1.2.3.4 port 22 ssh2
#     Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
#                        ^^^^^^^^^^^^^ present only sometimes

def section_3_optional():
    print(SEP)
    print("3. OPTIONAL PARTS — (?:...)? absorbs line variants\n")

    pattern = re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) "
        r"from (?P<source_ip>\S+) port (?P<port>\d+)"
    )

    for line in [
        "Failed password for root from 192.0.2.3 port 54323 ssh2",
        "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    ]:
        m = pattern.search(line)
        print(f"  {m.groupdict()}")
        print(f"    from: {line[:64]}")

    print("\n  One pattern. Both variants. No if-branch.")


# ---------------------------------------------------------------------------
# 4. Be specific — describe the SHAPE, don't just grab a token.
# ---------------------------------------------------------------------------
#
#   \S+ means "any run of non-space". It will happily capture the word
#   "port" as an IP address. That is exactly how the current parser ends up
#   with source_ip="user".
#
#   Describing what an IP actually looks like makes the regex refuse the
#   wrong answer — and lets it BACKTRACK to the right one.

IP = r"(?P<source_ip>[0-9a-fA-F.:]+)"   # ipv4 dotted, or ipv6 hex/colons


def section_4_be_specific():
    print(SEP)
    print("4. BE SPECIFIC — let the pattern reject wrong answers\n")

    line = "Connection closed by 192.0.2.1 port 22 [preauth]"

    loose = re.search(r"closed by (?P<username>\S+) (?P<source_ip>\S+)", line)
    print(f"  loose  \\S+ \\S+   -> {loose.groupdict()}")
    print("                     ^ wrong: no username on this line at all\n")

    tight = re.search(r"closed by (?:(?P<username>\S+) )?" + IP + r" port", line)
    print(f"  tight  IP-shaped -> {tight.groupdict()}")
    print("                     ^ right: username is None, ip is the ip")

    print("\n  Why it works: the optional username group tries '192.0.2.1' first,")
    print("  then needs the IP group to match 'port' — 'p','o','r','t' are not")
    print("  in [0-9a-fA-F.:], so it fails, backtracks, and drops the username.")
    print("  Backtracking is the engine trying alternatives for you.")


# ---------------------------------------------------------------------------
# 5. Greedy vs lazy.
# ---------------------------------------------------------------------------
#
#     .+   greedy — takes as much as possible, then gives back
#     .+?  lazy   — takes as little as possible, then grows
#
#   Matters whenever the delimiter can appear inside the value.

def section_5_greedy():
    print(SEP)
    print("5. GREEDY vs LAZY\n")

    line = "sshd-session[1234]: error: kex_exchange: [1.2.3.4] no matching"

    greedy = re.search(r"\[(.+)\]", line).group(1)
    lazy   = re.search(r"\[(.+?)\]", line).group(1)

    print(f"  \\[(.+)\\]   -> {greedy!r}")
    print("               ^ swallowed everything up to the LAST ]")
    print(f"  \\[(.+?)\\]  -> {lazy!r}")
    print("               ^ stopped at the FIRST ]  <- usually what you want")


# ---------------------------------------------------------------------------
# 6. The real thing: a pattern table replaces the if-chain.
# ---------------------------------------------------------------------------
#
#   identify_event() is currently ~35 lines of ordered `elif "..." in line`.
#   Order is load-bearing and easy to break.
#
#   A table is data: one row per event type. Adding an event type is adding
#   a row, not editing control flow. Docker, apache and syslog become new
#   tables, not new if-chains.
#
#   re.compile() once at import; the compiled object is reused per line.

SSH_PATTERNS = [
    ("successful_login", re.compile(
        r"Accepted (?P<auth_method>\S+) for (?P<username>\S+) "
        r"from " + IP + r" port (?P<port>\d+)")),

    ("failed_login", re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) "
        r"from " + IP + r" port (?P<port>\d+)")),

    ("invalid_user", re.compile(
        r"Invalid user (?:(?P<username>\S+) )?"
        r"from " + IP + r" port (?P<port>\d+)")),

    ("connection_closed", re.compile(
        r"Connection closed by (?:(?:invalid|authenticating) user )?"
        r"(?:(?P<username>\S+) )?" + IP + r" port (?P<port>\d+)")),

    ("session_opened", re.compile(
        r"session opened for user (?P<username>[^(\s]+)"
        r"(?:\(uid=(?P<uid>\d+)\))?")),

    ("multiple_auth_failures", re.compile(
        r"PAM (?P<count>\d+) more authentication failures")),

    ("authentication_failure", re.compile(
        r"pam_unix\([^)]+\): authentication failure;.*?rhost=(?P<rhost>\S*)")),

    ("user_unknown", re.compile(
        r"pam_unix\([^)]+\): check pass; user unknown")),
]


def identify(message):
    """First pattern that matches wins. Returns (event_type, fields) or None."""

    for event_type, pattern in SSH_PATTERNS:
        m = pattern.search(message)
        if m:
            return event_type, {k: v for k, v in m.groupdict().items() if v}

    return None


def section_6_table():
    print(SEP)
    print("6. PATTERN TABLE — the shape the parser should take\n")

    lines = [
        "Connection closed by authenticating user root 192.0.2.1 port 54321 [preauth]",
        "Connection closed by invalid user admin 192.0.2.2 port 54322 [preauth]",
        "Connection closed by engineer 192.0.2.90 port 51110",
        "Connection closed by 192.0.2.7 port 54327 [preauth]",
        "Failed password for root from 192.0.2.3 port 54323 ssh2",
        "Failed password for invalid user admin from 192.0.2.5 port 54325 ssh2",
        "Accepted publickey for deploy from 192.0.2.4 port 54324 ssh2: RSA SHA256:abc",
        "Accepted password for analyst from 192.0.2.10 port 38922 ssh2",
        "Invalid user admin from 185.12.41.55 port 51432",
        "Invalid user from 192.0.2.6 port 54326",
        "pam_unix(sshd:auth): check pass; user unknown",
        "pam_unix(sshd:session): session opened for user analyst(uid=1000) by (uid=0)",
        "PAM 4 more authentication failures; logname= uid=0 rhost=203.0.113.40",
    ]

    for line in lines:
        result = identify(line)
        if result is None:
            print(f"  --                        {line[:58]}")
        else:
            event_type, fields = result
            print(f"  {event_type:<24}  {fields}")

    print("\n  Every variant the token parser mangled is handled, including the")
    print("  publickey login and the no-username 'Invalid user from ...' form.")


# ---------------------------------------------------------------------------
# 7. Sanity checks — these MUST pass. Break a pattern above and see them fail.
# ---------------------------------------------------------------------------

def checks():
    cases = [
        ("Connection closed by authenticating user root 192.0.2.1 port 22 [preauth]",
         "connection_closed", {"username": "root", "source_ip": "192.0.2.1"}),

        ("Connection closed by invalid user admin 192.0.2.2 port 22 [preauth]",
         "connection_closed", {"username": "admin", "source_ip": "192.0.2.2"}),

        ("Connection closed by 192.0.2.7 port 22 [preauth]",
         "connection_closed", {"source_ip": "192.0.2.7"}),

        ("Accepted publickey for deploy from 192.0.2.4 port 22 ssh2: RSA SHA256:x",
         "successful_login", {"username": "deploy", "source_ip": "192.0.2.4",
                              "auth_method": "publickey"}),

        ("Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
         "failed_login", {"username": "admin", "source_ip": "1.2.3.4"}),

        ("Invalid user from 192.0.2.6 port 54326",
         "invalid_user", {"source_ip": "192.0.2.6"}),
    ]

    for line, want_type, want_fields in cases:
        got = identify(line)
        assert got is not None, f"no match: {line}"
        got_type, got_fields = got
        assert got_type == want_type, f"{line}\n  want {want_type}, got {got_type}"
        for key, value in want_fields.items():
            assert got_fields.get(key) == value, (
                f"{line}\n  {key}: want {value!r}, got {got_fields.get(key)!r}"
            )

    # the no-username variants must NOT invent one
    assert "username" not in identify("Invalid user from 192.0.2.6 port 1")[1]
    assert "username" not in identify("Connection closed by 192.0.2.7 port 1")[1]

    print(SEP)
    print(f"7. CHECKS — all {len(cases) + 2} passed.")


# ---------------------------------------------------------------------------
# 8. YOUR TURN. Each of these is a real sshd line the table above misses.
#    Add a pattern for it, then flip the assert at the bottom.
# ---------------------------------------------------------------------------

EXERCISES = [
    # 1. Extract user and ip. Note "port" comes before "ssh2" here too.
    "Disconnected from authenticating user root 192.0.2.1 port 54321 [preauth]",

    # 2. Extract the signal number.
    "Received signal 15; terminating.",

    # 3. Extract the listen address and port. Two variants: 0.0.0.0 and ::
    "Server listening on 0.0.0.0 port 22.",

    # 4. Harder — extract user, ip and the key fingerprint separately.
    "Accepted publickey for deploy from 192.0.2.4 port 54324 ssh2: RSA SHA256:AbCd123",

    # 5. Hardest — this is a Docker line, not ssh. Extract container and action.
    "container start 4f2b1c9a8e7d (image=nginx:latest, name=web-01)",
]


def section_8_exercises():
    print(SEP)
    print("8. EXERCISES — add patterns for these, then re-run\n")

    for i, line in enumerate(EXERCISES, 1):
        status = "handled" if identify(line) else "TODO   "
        print(f"  {status}  {i}. {line[:60]}")

    print("\n  Hints:")
    print(r"    \d+           digits          (?P<signal>\d+)")
    print(r"    [^,]+         up to a comma   (?P<image>[^,]+)")
    print(r"    (?:a|b)       either          (?:0\.0\.0\.0|::)")
    print(r"    \s+           one or more spaces (logs pad inconsistently)")


if __name__ == "__main__":
    section_1_matching()
    section_2_capturing()
    section_3_optional()
    section_4_be_specific()
    section_5_greedy()
    section_6_table()
    checks()
    section_8_exercises()
    print()

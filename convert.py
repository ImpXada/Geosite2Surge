"""
Convert v2fly/domain-list-community (geosite) lists into Surge rule sets.

Source data is parsed and resolved the same way upstream's main.go does it:
every list is parsed first, affiliations (`&list`) are applied, inclusions
(`include:list @attr @-attr`) are resolved recursively on the parsed entries
with their attribute filters, and only then is each resolved list written out
in Surge format.
"""
import os
import shutil

try:  # Python 3.11+
    from re import _parser as sre_parse
    from re import _constants as sre_constants
except ImportError:  # pragma: no cover
    import sre_parse
    import sre_constants

TYPE_DOMAIN = "domain"
TYPE_FULL = "full"
TYPE_KEYWORD = "keyword"
TYPE_REGEXP = "regexp"
TYPE_INCLUDE = "include"

# Upper bound of concrete alternatives a single regexp may expand into.
MAX_EXPANSIONS = 256
# Character classes larger than this are written as a single "?" wildcard
# instead of being enumerated.
MAX_CLASS_SIZE = 16
# Bounded repeats with a larger upper bound are treated as unbounded.
MAX_REPEAT_EXPAND = 8
# A DOMAIN-WILDCARD rule must keep at least this many literal characters
# outside its last label, otherwise it matches far too many hostnames
# (e.g. "*????.com" matches nearly every .com domain).
MIN_WILDCARD_LITERALS = 2

DOMAIN_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-._")
WILDCARD_CHARS = set("?*")
START = "\x01"  # "^" anchor marker inside expanded alternatives
END = "\x02"    # "$" anchor marker inside expanded alternatives


class ConvertError(Exception):
    pass


class Entry:
    __slots__ = ("type", "value", "attrs", "plain")

    def __init__(self, typ, value, attrs):
        self.type = typ
        self.value = value
        self.attrs = tuple(sorted(set(attrs)))
        plain = f"{typ}:{value}"
        if self.attrs:
            plain += ":" + ",".join("@" + a for a in self.attrs)
        self.plain = plain


class Inclusion:
    __slots__ = ("source", "must", "ban")

    def __init__(self, source, must, ban):
        self.source = source
        self.must = must
        self.ban = ban


class ParsedList:
    def __init__(self):
        self.entries = []
        self.inclusions = []
        self.resolving = False
        self.rough = None  # dict plain -> Entry, set after resolving


# ---------------------------------------------------------------------------
# Parsing and resolving (mirrors upstream main.go)
# ---------------------------------------------------------------------------

def parse_rule(line):
    """Split a comment-free source line into (type, value, extra fields)."""
    typ, sep, rule = line.partition(":")
    if not sep:
        typ, rule = TYPE_DOMAIN, line
    else:
        typ = typ.strip().lower()
    parts = rule.split()
    if not parts:
        raise ConvertError(f"empty rule: {line!r}")
    return typ, parts[0], parts[1:]


def load_lists(geosite_dir):
    lists = {}

    def get(name):
        return lists.setdefault(name, ParsedList())

    for file in sorted(os.listdir(geosite_dir)):
        path = os.path.join(geosite_dir, file)
        if not os.path.isfile(path):
            continue
        name = file.lower()
        pl = get(name)
        with open(path, "r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                where = f"{file}:{lineno}"
                typ, value, fields = parse_rule(line)
                if typ == TYPE_INCLUDE:
                    must, ban = [], []
                    for field in fields:
                        if not field.startswith("@"):
                            raise ConvertError(f"{where}: unknown field {field!r}")
                        attr = field[1:].lower()
                        if attr.startswith("-"):
                            ban.append(attr[1:])
                        else:
                            must.append(attr)
                    pl.inclusions.append(Inclusion(value.lower(), must, ban))
                    continue
                if typ not in (TYPE_DOMAIN, TYPE_FULL, TYPE_KEYWORD, TYPE_REGEXP):
                    raise ConvertError(f"{where}: unknown rule type {typ!r}")
                if typ != TYPE_REGEXP:
                    value = value.lower()
                attrs, affs = [], []
                for field in fields:
                    if field.startswith("@"):
                        attrs.append(field[1:].lower())
                    elif field.startswith("&"):
                        affs.append(field[1:].lower())
                    else:
                        raise ConvertError(f"{where}: unknown field {field!r}")
                entry = Entry(typ, value, attrs)
                pl.entries.append(entry)
                for aff in affs:
                    get(aff).entries.append(entry)
    return lists


def match_attr_filters(entry, inc):
    if not entry.attrs:
        return not inc.must
    return all(a in entry.attrs for a in inc.must) and not any(
        a in entry.attrs for a in inc.ban
    )


def resolve_list(lists, name):
    pl = lists.get(name)
    if pl is None:
        raise ConvertError(f"list {name!r} not found")
    if pl.rough is not None:
        return pl
    if pl.resolving:
        raise ConvertError(f"circular inclusion in {name!r}")
    pl.resolving = True
    rough = {e.plain: e for e in pl.entries}
    for inc in pl.inclusions:
        try:
            ipl = resolve_list(lists, inc.source)
        except ConvertError as e:
            raise ConvertError(f"{name}: failed to resolve include:{inc.source}: {e}")
        full = not inc.must and not inc.ban
        for plain, entry in ipl.rough.items():
            if full or match_attr_filters(entry, inc):
                rough[plain] = entry
    pl.rough = rough
    pl.resolving = False
    return pl


def polish(entries):
    """
    Drop domain/full entries already covered by a parent domain entry and sort
    the rest. Attributes are ignored here because Surge rules carry none.
    """
    domains = {e.value for e in entries if e.type == TYPE_DOMAIN}
    seen = set()
    result = []
    for e in sorted(entries, key=lambda e: (e.type, e.value)):
        key = (e.type, e.value)
        if key in seen:
            continue
        seen.add(key)
        if e.type in (TYPE_DOMAIN, TYPE_FULL):
            labels = e.value.split(".")
            start = 1 if e.type == TYPE_DOMAIN else 0
            if any(".".join(labels[i:]) in domains for i in range(start, len(labels))):
                continue
        result.append(e)
    return result


# ---------------------------------------------------------------------------
# Regexp -> Surge rules
# ---------------------------------------------------------------------------

CATEGORY_CHARS = {
    sre_constants.CATEGORY_DIGIT: set("0123456789"),
    sre_constants.CATEGORY_WORD: set("abcdefghijklmnopqrstuvwxyz0123456789_"),
}


def class_chars(items):
    """Return the set of domain characters a character class matches, or None."""
    chars = set()
    for op, av in items:
        if op == sre_constants.NEGATE:
            return None
        if op == sre_constants.LITERAL:
            chars.add(chr(av).lower())
        elif op == sre_constants.RANGE:
            lo, hi = av
            chars.update(chr(c).lower() for c in range(lo, hi + 1))
        elif op == sre_constants.CATEGORY and av in CATEGORY_CHARS:
            chars.update(CATEGORY_CHARS[av])
        else:
            return None
    return chars & DOMAIN_CHARS


def generalize(node):
    """Collapse a regex node into a single wildcard string (a superset)."""
    if isinstance(node, sre_parse.SubPattern):
        return "".join(generalize(item) for item in node)
    op, av = node
    if op == sre_constants.LITERAL:
        return chr(av).lower()
    if op in (sre_constants.ANY, sre_constants.IN, sre_constants.NOT_LITERAL,
              sre_constants.CATEGORY):
        return "?"
    if op == sre_constants.AT:
        if av in (sre_constants.AT_BEGINNING, sre_constants.AT_BEGINNING_STRING):
            return START
        if av in (sre_constants.AT_END, sre_constants.AT_END_STRING):
            return END
        return ""
    if op == sre_constants.SUBPATTERN:
        return generalize(av[-1])
    if op == sre_constants.BRANCH:
        alts = {generalize(alt) for alt in av[1]}
        if len(alts) == 1:
            return alts.pop()
        lengths = {len(a) for a in alts}
        if len(lengths) == 1 and not any(c in a for a in alts for c in "*" + START + END):
            return "?" * lengths.pop()
        return "*"
    if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
        lo, hi, sub = av
        g = generalize(sub)
        return g * lo if lo == hi else g * lo + "*"
    return "*"


def leading_run(pattern):
    """The run of "?"/"*" wildcards a pattern starts with."""
    return pattern[:len(pattern) - len(pattern.lstrip("?*"))]


def expand_seq(nodes, class_limit):
    options = [expand(n, class_limit) for n in nodes]

    def size():
        total = 1
        for o in options:
            total *= len(o)
        return total

    while size() > MAX_EXPANSIONS:
        i = max(range(len(options)), key=lambda k: len(options[k]))
        options[i] = [generalize(nodes[i])]
    result = [""]
    for o in options:
        result = [prefix + s for prefix in result for s in o]
    return result


def expand(node, class_limit):
    """
    Expand a regex node into a list of wildcard alternatives. Character
    classes with more than class_limit characters become "?".
    """
    if isinstance(node, sre_parse.SubPattern):
        return expand_seq(list(node), class_limit)
    op, av = node
    if op == sre_constants.LITERAL:
        return [chr(av).lower()]
    if op == sre_constants.IN:
        chars = class_chars(av)
        if chars is None or not chars or len(chars) > class_limit:
            return ["?"]
        return sorted(chars)
    if op == sre_constants.SUBPATTERN:
        return expand(av[-1], class_limit)
    if op == sre_constants.BRANCH:
        result = []
        for alt in av[1]:
            result.extend(expand(alt, class_limit))
        result = list(dict.fromkeys(result))
        return result if len(result) <= MAX_EXPANSIONS else [generalize(node)]
    if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
        lo, hi, sub = av
        if hi == sre_constants.MAXREPEAT or hi > MAX_REPEAT_EXPAND:
            g = generalize(sub)
            if "*" in leading_run(g):
                # g already matches any number of repetitions of itself,
                # e.g. "(.+\.)*" -> "" or "?*."
                return ([""] if lo == 0 else []) + [g]
            return [generalize(node)]
        result = []
        for k in range(lo, hi + 1):
            result.extend(expand_seq([sub] * k, class_limit))
        result = list(dict.fromkeys(result))
        return result if len(result) <= MAX_EXPANSIONS else [generalize(node)]
    return [generalize(node)]


def normalize_wildcards(s):
    """Rewrite every run of "?"/"*" as "?...?" followed by at most one "*"."""
    out, run = [], []
    for c in s + "\0":
        if c in WILDCARD_CHARS:
            run.append(c)
            continue
        if run:
            out.append("?" * run.count("?") + ("*" if "*" in run else ""))
            run = []
        out.append(c)
    return "".join(out[:-1])


def finalize(alt):
    """Turn an expanded alternative into a full-hostname wildcard, or None."""
    if START in alt:
        i = alt.rindex(START)
        if any(c not in "*" + START for c in alt[:i]):
            return None  # something must precede "^": cannot match
        alt = alt[i + 1:]
    else:
        alt = "*" + alt
    if END in alt:
        i = alt.index(END)
        if any(c not in "*" + END for c in alt[i + 1:]):
            return None
        alt = alt[:i]
    else:
        alt = alt + "*"
    if any(c not in DOMAIN_CHARS and c not in WILDCARD_CHARS for c in alt):
        return None
    alt = normalize_wildcards(alt)
    if alt.startswith("?*."):
        alt = alt[1:]  # a hostname never starts with ".", so "?*." == "*."
    return alt


def is_specific_wildcard(pattern):
    """
    A wildcard is acceptable only if the part before its last label keeps
    enough literal characters. "*????.com" or "*1*.one" do not.

    The last label starts after the last "." or "?" (an unescaped "." in the
    source regexp becomes "?", e.g. "91cg?com").
    """
    cut = max(pattern.rfind("."), pattern.rfind("?"))
    head = pattern[:cut] if cut > 0 else ""
    literals = sum(1 for c in head if c.isalnum())
    return literals >= MIN_WILDCARD_LITERALS


def patterns_to_rules(patterns):
    pset = set(patterns)
    rules, skipped = [], []
    for p in patterns:
        if p.startswith("*.") and p[2:] in pset:
            base = p[2:]
            if not any(c in WILDCARD_CHARS for c in base):
                continue  # emitted as DOMAIN-SUFFIX with its base
            if "*" in leading_run(base):
                continue  # already covered by the base wildcard
        if any(c in WILDCARD_CHARS for c in p):
            if is_specific_wildcard(p):
                rules.append(f"DOMAIN-WILDCARD,{p}")
            else:
                skipped.append(p)
        elif "*." + p in pset:
            rules.append(f"DOMAIN-SUFFIX,{p}")
        else:
            rules.append(f"DOMAIN,{p}")
    return rules, skipped


def regexp_patterns(ast, class_limit):
    patterns = []
    for alt in expand(ast, class_limit):
        p = finalize(alt)
        if p is not None and p not in patterns:
            patterns.append(p)
    return patterns


def regexp_to_rules(regex):
    """
    Convert a geosite regexp into Surge rules.

    Returns (rules, skipped_patterns). A regexp that expands into a small
    finite set becomes exact DOMAIN / DOMAIN-SUFFIX rules. Otherwise the
    compact form (character classes written as "?") is used when every
    wildcard in it is specific enough, and the finer expansion when not.
    Wildcards that are still too broad are dropped rather than emitted.
    """
    try:
        ast = sre_parse.parse(regex)
    except Exception as e:
        raise ConvertError(f"invalid regexp {regex!r}: {e}")
    fine = patterns_to_rules(regexp_patterns(ast, MAX_CLASS_SIZE))
    if not fine[1] and not any(r.startswith("DOMAIN-WILDCARD,") for r in fine[0]):
        return fine
    coarse = patterns_to_rules(regexp_patterns(ast, 0))
    if not coarse[1]:
        return coarse
    return fine


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

skipped_regexps = []


def entry_to_rules(entry):
    if entry.type == TYPE_DOMAIN:
        return [f"DOMAIN-SUFFIX,{entry.value}"]
    if entry.type == TYPE_FULL:
        return [f"DOMAIN,{entry.value}"]
    if entry.type == TYPE_KEYWORD:
        return [f"DOMAIN-KEYWORD,{entry.value}"]
    rules, skipped = regexp_to_rules(entry.value)
    lines = list(rules)
    if skipped:
        skipped_regexps.append(entry.value)
        lines.append(f"# SKIPPED (too broad as wildcard): regexp:{entry.value}")
    return lines


def write_rules(path, entries):
    seen = set()
    with open(path, "w", encoding="utf-8") as f:
        for entry in polish(entries):
            for line in entry_to_rules(entry):
                if line not in seen:
                    seen.add(line)
                    f.write(line + "\n")


def validate_output(output_dir: str):
    """
    Build guard: fail the conversion if any emitted DOMAIN-WILDCARD rule is too
    broad (e.g. "DOMAIN-WILDCARD,?*" or "DOMAIN-WILDCARD,*????.com").
    """
    offenders = []
    for file in os.listdir(output_dir):
        file_path = os.path.join(output_dir, file)
        if not os.path.isfile(file_path):
            continue
        with open(file_path, "r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                stripped = raw.strip()
                if not stripped.startswith("DOMAIN-WILDCARD,"):
                    continue
                value = stripped[len("DOMAIN-WILDCARD,"):]
                if not is_specific_wildcard(value):
                    offenders.append(f"{file}:{lineno}: {stripped}")
    if offenders:
        raise ValueError(
            "Refusing to emit over-broad DOMAIN-WILDCARD rules:\n" + "\n".join(offenders)
        )


def convert_geosite_to_surge(geosite_dir: str, output_dir: str):
    lists = load_lists(geosite_dir)
    for name in sorted(lists):
        resolve_list(lists, name)

    written = []
    for name in sorted(lists):
        write_rules(os.path.join(output_dir, name), lists[name].rough.values())
        written.append(name)
        print(f"转换完成: {name}")

    # Legacy per-attribute files (e.g. data/ads, data/!cn): every rule carrying
    # that attribute, from all lists. Skipped when a list has the same name.
    by_attr = {}
    for pl in lists.values():
        for entry in pl.entries:
            for attr in entry.attrs:
                by_attr.setdefault(attr, {})[entry.plain] = entry
    for attr in sorted(by_attr):
        if attr in lists:
            continue
        write_rules(os.path.join(output_dir, attr), by_attr[attr].values())
        written.append(attr)
        print(f"转换完成: @{attr}")
    return written


def write_readme(files):
    with open("README.md", "w", encoding="utf-8") as f:
        f.write("# Geosite2Surge\n")
        f.write("Geosite to Surge rule converter\n")
        f.write("## Usage\n")
        f.write("```\n")
        f.write("geosite:google\n")
        f.write("RULE-SET,https://raw.githubusercontent.com/ImpXada/Geosite2Surge/refs/heads/main/data/google,PROXY\n")
        f.write("geosite:xxxxxx\n")
        f.write("RULE-SET,https://raw.githubusercontent.com/ImpXada/Geosite2Surge/refs/heads/main/data/xxxxxx,PROXY\n")
        f.write("```\n")
        f.write("\n")
        f.write("## Rules\n")
        f.write("| geosite name | surge config url |\n")
        f.write("|--------------|------------------|\n")
        for file in sorted(set(files)):
            url = f"https://raw.githubusercontent.com/ImpXada/Geosite2Surge/refs/heads/main/data/{file}"
            f.write(f"| {file} | {url} |\n")


if __name__ == "__main__":
    geosite_dir = "domain-list-community/data"
    output_dir = "data"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    files = convert_geosite_to_surge(geosite_dir, output_dir)
    if skipped_regexps:
        print(f"{len(set(skipped_regexps))} 条 regexp 有部分无法精确转换，已跳过过宽的通配规则")
    validate_output(output_dir)
    write_readme(files)

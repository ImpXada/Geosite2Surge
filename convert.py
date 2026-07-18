import os
import shutil
import re
import sre_parse
import sre_constants

unfinished_files = []
finished_files = []
skipped_regexps = []

def wildcard_has_literal(wildcard: str) -> bool:
    """
    Return True if the wildcard pattern is constrained by at least one
    literal (non-wildcard) domain character.

    A pattern built only from the wildcard metacharacters '*' and '?'
    (e.g. "?*", "*", "**") matches (almost) every hostname. Emitting such
    a pattern as a DOMAIN-WILDCARD rule would silently swallow all traffic
    and turn every rule below it — including FINAL — into dead code, so
    these must never be written out. An empty string (produced when a regex
    fails to parse) is likewise treated as having no literal.
    """
    stripped = wildcard.replace("*", "").replace("?", "")
    return any(c.isalnum() for c in stripped)

def regex_ast_to_wildcard(regex: str) -> str:
    """
    Convert a regular expression to a wildcard pattern.
    
    Args:
        regex: A regular expression string
    
    Returns:
        A wildcard pattern string
    """
    # Remove leading and trailing slashes
    clean_regex = re.sub(r'^\/|\/$', '', regex)
    
    try:
        # Parse the regex into an AST
        ast = sre_parse.parse(clean_regex)
        return convert_node_to_wildcard(ast)
    except Exception as error:
        print(f"Error parsing regex: {error}")
        return ""

def convert_node_to_wildcard(node) -> str:
    """
    Convert an SRE parse tree node to a wildcard pattern.
    
    Args:
        node: An SRE parse tree node
    
    Returns:
        A wildcard pattern string
    """
    if isinstance(node, sre_parse.SubPattern):
        return ''.join(convert_node_to_wildcard(item) for item in node)
    
    if isinstance(node, tuple):
        op, value = node
        
        # Map SRE_TOKEN operations to wildcard patterns
        if op == sre_constants.LITERAL:
            return chr(value)
        elif op == sre_constants.ANY:
            return "?"
        elif op in (sre_constants.IN, sre_constants.CATEGORY):
            return "?"
        elif op == sre_constants.BRANCH:
            return "*"
        elif op == sre_constants.SUBPATTERN:
            # SUBPATTERN structure varies by Python version:
            #   <3.6: (group_number, subpattern)
            #   >=3.6: (group_number, add_flags, del_flags, subpattern)
            # The actual sub-pattern is always the last element.
            subpattern = value[-1]
            return convert_node_to_wildcard(subpattern)
        elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
            # MIN_REPEAT/MAX_REPEAT structure: (min_count, max_count, subpattern)
            return "*"
        elif op == sre_constants.AT:
            # Anchors like ^ and $ don't add characters
            return ""
        elif op == sre_constants.GROUPREF:
            return "*"
        else:
            # For any other token, use a generic wildcard
            return "?"
    
    return ""

def process_line(line: str):
    comment = ""
    tags = []
    tag_in_line = False
    raw_line = line.strip()

    # Handle comments
    if "#" in raw_line:
        parts = raw_line.split("#", 1)
        line_without_comment = parts[0].strip()
        comment_part = parts[1].strip()
        
        # Check if there are any @ in the comment section
        current_section = ""
        
        for char in comment_part:
            if char == '@':
                # Save accumulated text as comment if it's the first @
                if not tag_in_line and current_section:
                    comment = current_section.strip()
                # Start a new tag
                current_section = '@'
                tag_in_line = True
            else:
                current_section += char
        
        # Process the last section
        if current_section.startswith('@'):
            potential_tag = current_section[1:].strip()
            # Skip tags that appear to be URLs
            if not (potential_tag.startswith('http://') or
                   potential_tag.startswith('https://') or
                   potential_tag.startswith('www.')):
                tags.append(potential_tag)
            else:
                # If it's a URL, consider it part of the comment
                if comment:
                    comment += current_section
                else:
                    comment = current_section.strip()
        elif not tag_in_line:
            comment = current_section.strip()
        
        line = line_without_comment
    else:
        line = raw_line
    
    # Check for @ tags in the main part of the line
    if "@" in line:
        main_parts = []
        current_part = ""
        
        for char in line:
            if char == '@':
                if current_part:
                    main_parts.append(current_part.strip())
                current_part = '@'
                tag_in_line = True
            else:
                current_part += char
        
        # Process the last part
        if current_part.startswith('@'):
            potential_tag = current_part[1:].strip()
            # Skip tags that appear to be URLs
            if not (potential_tag.startswith('http://') or 
                   potential_tag.startswith('https://') or
                   potential_tag.startswith('www.')):
                tags.append(potential_tag)
            else:
                # If it's a URL and there are main parts, add it to the last one
                if main_parts:
                    main_parts[-1] += current_part
                else:
                    main_parts.append(current_part)
        else:
            main_parts.append(current_part.strip())
        
        # Use the first part as our domain line
        line = main_parts[0] if main_parts else ""
    
    # Format the comment for the output
    if comment:
        formatted_comment = f"    #{comment}\n"
    else:
        formatted_comment = "\n"
    
    # Process the line based on its prefix
    if line.startswith("regexp:"):
        pattern = line[7:]
        wildcard = regex_ast_to_wildcard(pattern)
        if wildcard_has_literal(wildcard):
            res = f"DOMAIN-WILDCARD,{wildcard}{formatted_comment}"
        else:
            # The regex converts to an unconstrained wildcard (e.g. "?*" from
            # a dotless-domain regex) that would match every hostname. Skip it
            # instead of emitting a catch-all rule; leave a comment for
            # visibility. Surge/Shadowrocket wildcard syntax cannot faithfully
            # express such patterns anyway.
            skipped_regexps.append(pattern)
            res = f"# SKIPPED (unconvertible regexp): {pattern}\n"
    elif line.startswith("full:"):
        res = f"DOMAIN,{line[5:]}{formatted_comment}"
    else:
        res = f"DOMAIN-SUFFIX,{line}{formatted_comment}"
    
    # Write to each tag file if tags were found
    if tags:
        for tag in tags:
            if tag:  # Ensure tag is not empty
                finished_files.append(tag)
                tag_filename = os.path.join(output_dir, tag)
                with open(tag_filename, "a", encoding="utf-8") as tag_f:
                    tag_f.write(res)
    
    return res



def convert_geosite_to_surge(geosite_dir: str, output_dir: str):
    for file in os.listdir(geosite_dir):
        file_path = os.path.join(geosite_dir, file)

        if not os.path.isfile(file_path):
            continue

        lines = []
        # 读取 Geosite 规则文件
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # 生成 Surge 规则文件
        surge_file = os.path.join(output_dir, file)
        with open(surge_file, "w", encoding="utf-8") as f:
            need_break = False
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") :
                    f.write(line + "\n")
                    continue

                if line.startswith("include:"):
                    included_file = line.split(':')[1].strip()
                    included_path = os.path.join(output_dir, included_file)
                    if os.path.exists(included_path):
                        with open(included_path, 'r', encoding='utf-8') as inc_f:
                            for inc_line in inc_f:
                                f.write(inc_line)
                        f.write(f"#end include:{included_file}\n")
                        continue
                    else:
                        unfinished_files.append(file)
                        os.remove(surge_file)
                        need_break = True
                        break

                f.write(process_line(line))

            if need_break:
                continue
        finished_files.append(file)
        print(f"转换完成: {file} → {surge_file}")

def convert_unfinished_files(geosite_dir: str, output_dir: str):
    for file in unfinished_files:
        file_path = os.path.join(geosite_dir, file)
        # 读取 Geosite 规则文件
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        surge_file = os.path.join(output_dir, file)
        with open(surge_file, "w", encoding="utf-8") as f:
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") :
                    f.write(line + "\n")
                    continue

                if line.startswith("include:"):
                    included_file = line.split(':')[1].strip()
                    included_path = os.path.join(output_dir, included_file)
                    if os.path.exists(included_path):
                        f.write(f"#include:{included_file}\n")
                        with open(included_path, 'r', encoding='utf-8') as inc_f:
                            for inc_line in inc_f:
                                f.write(inc_line)
                        f.write(f"#end include:{included_file}\n")
                        continue
                    else:
                        continue

                f.write(process_line(line))
        unfinished_files.remove(file)
        finished_files.append(file)
        print(f"转换完成: {file} → {surge_file}")

def validate_output(output_dir: str):
    """
    Build guard: fail the conversion if any emitted DOMAIN-WILDCARD rule is an
    unconstrained catch-all (no literal characters), e.g. "DOMAIN-WILDCARD,?*".
    Such a rule matches every hostname and would silently swallow all traffic.
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
                # value is everything after the type, before any trailing comment
                value = stripped[len("DOMAIN-WILDCARD,"):].split("#", 1)[0].strip()
                if not wildcard_has_literal(value):
                    offenders.append(f"{file}:{lineno}: {stripped}")
    if offenders:
        raise ValueError(
            "Refusing to emit catch-all DOMAIN-WILDCARD rules "
            "(no literal characters):\n" + "\n".join(offenders)
        )

if __name__ == "__main__":
    geosite_dir = "test/data"
    geosite_dir = "domain-list-community/data"


    output_dir = "data"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    convert_geosite_to_surge(geosite_dir, output_dir)
    while unfinished_files:
        convert_unfinished_files(geosite_dir, output_dir)

    if skipped_regexps:
        print(f"跳过 {len(skipped_regexps)} 条无法转换的 regexp（避免生成 catch-all 规则）")
    validate_output(output_dir)

    finished_files = list(set(finished_files))
    finished_files.sort()
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
        for file in finished_files:
            url = f"https://raw.githubusercontent.com/ImpXada/Geosite2Surge/refs/heads/main/data/{file}"
            f.write(f"| {file} | {url} |\n")

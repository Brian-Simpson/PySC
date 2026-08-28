import re
import sys
import os

def process_audit_content(content):
    """
    Parses the file sequentially to maintain structure, including <if>, <then>, 
    <else>, and collapses multi-line text strings to prevent syntax crashes.
    """
    fields_to_collapse = ['description', 'info', 'solution', 'see_also']
    for field in fields_to_collapse:
        pattern = re.compile(rf'({field}\s*:\s*")([^"]*?)(")', re.DOTALL)
        def collapse_match(m):
            cleaned_text = re.sub(r'\s+', ' ', m.group(2)).strip()
            return f'{m.group(1)}{cleaned_text}{m.group(3)}'
        content = pattern.sub(collapse_match, content)

    block_pattern = re.compile(
        r'(<custom_item>.*?</custom_item>|<if>|<then>|</then>|<else>|</else>|</if>|<check_type[^>]*>|</check_type>|<group_policy[^>]*>|</group_policy>)', 
        re.DOTALL
    )
    
    tokens = block_pattern.findall(content)
    output_lines = []
    
    if not tokens:
        tokens = re.compile(r'(<custom_item>.*?</custom_item>)', re.DOTALL).findall(content)
        if not tokens:
            return content

    for token in tokens:
        token_strip = token.strip()
        if not token_strip.startswith('<custom_item>'):
            output_lines.append(token_strip)
            continue
            
        item_dict = {}
        lines = token_strip.replace('<custom_item>', '').replace('</custom_item>', '').strip().split('\n')
        
        for line in lines:
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip()
                val = val.strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                item_dict[key] = val
                
        if item_dict:
            converted_block = convert_item_to_powershell(item_dict)
            output_lines.append(converted_block)

    return "\n\n".join(output_lines)

def should_emit_can_be_null(item, check_type, ps_args):
    """Return True when the generated PowerShell check may legitimately yield null/empty output."""
    if not ps_args:
        return False

    if check_type == 'AUDIT_POWERSHELL':
        return False

    normalized_ps_args = ps_args.lower()

    if check_type == 'REGISTRY_SETTING':
        return True

    if check_type == 'USER_RIGHTS_POLICY':
        return True

    if check_type == 'PASSWORD_POLICY':
        return False

    null_indicators = [
        'erroraction silentlycontinue',
        'test-path',
        'get-itemproperty',
        'get-item ',
        'get-childitem',
        'get-content',
        'select-object -last 1',
        'where-object',
        'if([string]::isnullorwhitespace',
        'if ($null -eq',
        'if (-not (test-path',
    ]

    return any(indicator in normalized_ps_args for indicator in null_indicators)


def escape_audit_string(value):
    return value.replace('"', '\\"')


def convert_item_to_powershell(item):
    """
    Transforms custom items to AUDIT_POWERSHELL while escaping quotes 
    and correcting native Tenable data logic types to textual responses.
    """
    check_type = item.get('type', '')
    description = escape_audit_string(item.get('description', 'Converted PowerShell Check'))
    info = escape_audit_string(item.get('info', ''))
    solution = escape_audit_string(item.get('solution', ''))
    reference = escape_audit_string(item.get('reference', ''))
    value_data = escape_audit_string(item.get('value_data', ''))
    v_type = "POLICY_TEXT"
    
    range_match = re.match(r'\[\s*(\d+)\s*\.\.\s*(\d+)\s*\]', value_data)
    ps_range_eval = ""
    if range_match:
        min_val, max_val = range_match.group(1), range_match.group(2)
        ps_range_eval = f" | Where-Object {{ $_ -ge {min_val} -and $_ -le {max_val} }}"
        value_data = "True"
    elif value_data == "MUST_EXIST":
        ps_range_eval = " | ForEach-Object { if($_) { 'True' } else { 'False' } }"
        value_data = "True"

    if check_type == 'AUDIT_POWERSHELL':
        ps_args = item.get('powershell_args', '')
        v_type = item.get('value_type', 'POLICY_TEXT')
    elif check_type == 'REGISTRY_SETTING':
        reg_key = item.get('reg_key', '').replace('HKLM\\', 'HKLM:\\')
        reg_item = item.get('reg_item', '')
        ps_args = f"(Get-ItemProperty -Path '{reg_key}' -Name '{reg_item}' -ErrorAction SilentlyContinue).{reg_item}"
        if ps_range_eval:
            ps_args = f"if ({ps_args}{ps_range_eval}) {{ 'True' }} else {{ 'False' }}"
    elif check_type == 'PASSWORD_POLICY':
        policy_name = item.get('password_policy', '')
        mapping = {
            'MINIMUM_PASSWORD_LENGTH': "Minimum password length",
            'PASSWORD_HISTORY_SIZE': "Length of password history",
            'MINIMUM_PASSWORD_AGE': "Minimum password age (days)",
            'MAXIMUM_PASSWORD_AGE': "Maximum password age (days)",
            'LOCKOUT_BAD_COUNT': "Lockout threshold"
        }
        search_str = mapping.get(policy_name, "Minimum password length")
        ps_args = f"[int]((net accounts | Select-String '{search_str}') -replace '.*:\\s+','')"
        if ps_range_eval:
            ps_args = f"if ({ps_args}{ps_range_eval}) {{ 'True' }} else {{ 'False' }}"
    elif check_type == 'USER_RIGHTS_POLICY':
        right_name = item.get('user_right', '')
        ps_args = f"(([WmiClass]'Win32_SecurityDescriptorHelper').GetSecurityDescriptor('{right_name}').Descriptor.Owner.Name)"
        if "||" in value_data:
            value_data = value_data.replace('"', '').strip()
    else:
        ps_args = f"# Manual conversion required for legacy type: {check_type}"

    ps_args_escaped = escape_audit_string(ps_args)
    powershell_option_line = ''
    if should_emit_can_be_null(item, check_type, ps_args):
        powershell_option_line = '\n      powershell_option    : CAN_BE_NULL'

    return f"""    <custom_item>
      type                 : AUDIT_POWERSHELL
      description          : "{description}"
      info                 : "{info}"
      solution             : "{solution}"
      reference            : "{reference}"
      value_type           : {v_type}
      powershell_args      : "{ps_args_escaped}"
      value_data           : "{value_data}"{powershell_option_line}
    </custom_item>"""

def main():
    print("=== Tenable Audit PowerShell Converter ===")
    
    # Prompt the user for the input file path natively
    input_filename = input("Enter or paste the full path to your source .audit file:\n> ").strip()
    # Strip wrapping quotes if you drag-and-drop the file into the terminal window
    input_filename = input_filename.strip('"').strip("'")

    if not os.path.exists(input_filename):
        print(f"\nError: The input file '{input_filename}' does not exist.")
        input("\nPress Enter to exit...")
        return

    # Automatically derive the output file destination name next to the original file
    dir_name, file_name = os.path.split(input_filename)
    base_name, _ = os.path.splitext(file_name)
    output_filename = os.path.join(dir_name, f"{base_name}_powershell.audit")

    try:
        with open(input_filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"\nError reading file: {e}")
        input("\nPress Enter to exit...")
        return

    print("\nParsing file structure and fixing syntax dependencies...")
    final_output = process_audit_content(content)
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(final_output)
        print(f"\nSuccess! New file successfully created at:\n{output_filename}")
    except Exception as e:
        print(f"\nError writing file: {e}")
        
    input("\nConversion finished. Press Enter to close...")

if __name__ == "__main__":
    main()

import re
import os

def count_numbered_audits():
    # Prompt the user for the file path
    file_path = input("Enter the path to your .audit file: ").strip()
    
    # Clean up drag-and-dropped file paths
    file_path = file_path.strip("'\"")

    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return

    # Match description fields, identifying if they have a leading '#'
    # Group 1 captures the optional '#' comment symbol
    # Group 2 captures the actual description text inside quotes
    desc_regex = re.compile(r'^\s*(#)?\s*description\s*:\s*["\']?(.*?)["\']?\s*$')
    
    # Check if text starts with a digit
    numbered_regex = re.compile(r'^\d')

    # Counters
    total_custom_items = 0
    active_numbered_count = 0
    commented_numbered_count = 0
    
    in_custom_item = False
    current_description = None
    is_commented_block = False

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                # Detect the start of a block and see if the tag itself is commented
                if '<custom_item>' in line:
                    in_custom_item = True
                    current_description = None
                    # If the opening tag line starts with a hash, default the block to commented
                    is_commented_block = line.strip().startswith('#')
                    total_custom_items += 1
                    continue
                
                if in_custom_item:
                    desc_match = desc_regex.match(line)
                    if desc_match:
                        # If the description line itself has a '#', mark the block as commented
                        if desc_match.group(1) == '#':
                            is_commented_block = True
                        current_description = desc_match.group(2).strip()
                    
                    # Evaluate on block close
                    if '</custom_item>' in line:
                        in_custom_item = False
                        
                        if current_description and numbered_regex.match(current_description):
                            if is_commented_block:
                                commented_numbered_count += 1
                            else:
                                active_numbered_count += 1
                            
        print(f"\n[+] Analysis Complete for: {os.path.basename(file_path)}")
        print(f"    Total <custom_item> blocks found: {total_custom_items}")
        print(f"    ----------------------------------------")
        print(f"    Active numbered custom audits:     {active_numbered_count}")
        print(f"    Commented (#) numbered custom audits: {commented_numbered_count}")
        
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

if __name__ == "__main__":
    count_numbered_audits()

import os
import re

def invert_custom_items():
    # Prompt the user for the input file path
    input_file_path = input("Enter the path to the audit file: ").strip()

    # Validate that the file actually exists before processing
    if not os.path.isfile(input_file_path):
        print(f"Error: The file '{input_file_path}' does not exist.")
        return

    # Automatically generate output file names to protect the original
    base_name, file_extension = os.path.splitext(input_file_path)
    output_file_path = f"{base_name}_inverted{file_extension}"
    summary_file_path = f"{base_name}_extracted_ids_summary.txt"

    # Match blocks that START with or without a comment symbol
    start_commented = re.compile(r'^\s*#\s*(<custom_item>)\s*$')
    start_uncommented = re.compile(r'^\s*(<custom_item>)\s*$')
    
    # Match blocks that END with or without a comment symbol
    end_commented = re.compile(r'^\s*#\s*(</custom_item>)\s*$')
    end_uncommented = re.compile(r'^\s*(</custom_item>)\s*$')
    
    # Regex to extract the leading number inside the description quotes
    description_pattern = re.compile(r'^\s*#?\s*description\s*:\s*"\s*([\d\.]+)')
    
    # State tracking variables
    in_block = False
    block_mode = None  # 'uncommenting' or 'commenting'
    block_buffer = []  # Holds lines of the current block
    
    output_lines = []
    newly_uncommented_ids = []
    newly_commented_ids = []

    # Read the original file
    with open(input_file_path, 'r', encoding='utf-8') as infile:
        for line in infile:
            
            # --- DETECT BLOCK START ---
            if not in_block and start_commented.match(line):
                in_block = True
                block_mode = 'uncommenting'
                block_buffer = [line]
                continue
                
            if not in_block and start_uncommented.match(line):
                in_block = True
                block_mode = 'commenting'
                block_buffer = [line]
                continue

            # --- PROCESS LINES INSIDE BLOCKS ---
            if in_block:
                block_buffer.append(line)
                
                # Check for block closure
                if (block_mode == 'uncommenting' and end_commented.match(line)) or \
                   (block_mode == 'commenting' and end_uncommented.match(line)):
                    
                    # Evaluate the gathered block buffer for a numeric ID description
                    has_numeric_id = False
                    extracted_id = None
                    
                    for b_line in block_buffer:
                        match = description_pattern.match(b_line)
                        if match:
                            has_numeric_id = True
                            extracted_id = match.group(1)
                            break
                    
                    # If valid description pattern is found, process and invert the block
                    if has_numeric_id:
                        if block_mode == 'uncommenting':
                            newly_uncommented_ids.append(extracted_id)
                            for b_line in block_buffer:
                                # Strip the leading comment mark
                                output_lines.append(b_line.replace('#', '', 1))
                        else:
                            newly_commented_ids.append(extracted_id)
                            for b_line in block_buffer:
                                # Add the leading comment mark neatly
                                if b_line.strip():
                                    if '<custom_item>' in b_line or '</custom_item>' in b_line:
                                        output_lines.append(b_line.replace('<custom_item>', '# <custom_item>', 1).replace('</custom_item>', '# </custom_item>', 1))
                                    else:
                                        output_lines.append(re.sub(r'^(\s*)', r'\1# ', b_line))
                                else:
                                    output_lines.append(b_line)
                    else:
                        # Non-matching descriptions are left untouched
                        output_lines.extend(block_buffer)
                        
                    # Reset block tracking variables
                    in_block = False
                    block_mode = None
                    block_buffer = []
                continue
            
            # --- OUTSIDE OF ANY CUSTOM_ITEM BLOCK ---
            output_lines.append(line)

    # Write the modified data out to the brand new inverted file
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        outfile.writelines(output_lines)

    # Write the consolidated lists with headers to a single summary file
    with open(summary_file_path, 'w', encoding='utf-8') as sf:
        sf.write("[NEWLY UNCOMMENTED IDs]\n")
        if newly_uncommented_ids:
            sf.write(",".join(newly_uncommented_ids) + "\n")
        else:
            sf.write("(None)\n")
            
        sf.write("\n[NEWLY COMMENTED IDs]\n")
        if newly_commented_ids:
            sf.write(",".join(newly_commented_ids) + "\n")
        else:
            sf.write("(None)\n")

    # Print summary results
    print(f"\nSuccess! Process complete.")
    print(f"Inverted file saved to: {output_file_path}")
    print(f"Consolidated ID report saved to: {summary_file_path}")
    print(f"  -> Newly Uncommented: {len(newly_uncommented_ids)} items")
    print(f"  -> Newly Commented: {len(newly_commented_ids)} items")

if __name__ == "__main__":
    invert_custom_items()

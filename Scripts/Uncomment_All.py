import os
import re

def uncomment_custom_items():
    # Prompt the user for the input file path
    input_file_path = input("Enter the path to the audit file: ").strip()

    # Validate that the file actually exists before processing
    if not os.path.isfile(input_file_path):
        print(f"Error: The file '{input_file_path}' does not exist.")
        return

    # Automatically generate new file names to protect the original
    base_name, file_extension = os.path.splitext(input_file_path)
    output_file_path = f"{base_name}_uncommented{file_extension}"
    ids_file_path = f"{base_name}_extracted_ids.txt"

    # Regex to identify the start and end of commented custom items
    start_pattern = re.compile(r'^\s*#\s*(<custom_item>)\s*$')
    end_pattern = re.compile(r'^\s*#\s*(</custom_item>)\s*$')
    
    # Regex to extract the leading number inside the description quotes
    # Matches line with optional comment symbol, description keyword, and captures the leading digits/dots
    description_pattern = re.compile(r'^\s*#?\s*description\s*:\s*"\s*([\d\.]+)')
    
    uncommenting = False
    output_lines = []
    extracted_ids = []

    # Read the original file
    with open(input_file_path, 'r', encoding='utf-8') as infile:
        for line in infile:
            if start_pattern.match(line):
                uncommenting = True
                clean_line = line.replace('#', '', 1)
                output_lines.append(clean_line)
                continue
                
            if end_pattern.match(line):
                uncommenting = False
                clean_line = line.replace('#', '', 1)
                output_lines.append(clean_line)
                continue

            if uncommenting:
                # Look for description lines inside the uncommented block
                match = description_pattern.match(line)
                if match:
                    extracted_ids.append(match.group(1))
                
                clean_line = line.replace('#', '', 1)
                output_lines.append(clean_line)
            else:
                output_lines.append(line)

    # Write the modified audit data out to the new file
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        outfile.writelines(output_lines)

    # Write the extracted numbers to a comma-delimited text file
    if extracted_ids:
        with open(ids_file_path, 'w', encoding='utf-8') as id_file:
            id_file.write(",".join(extracted_ids))

    print(f"\nSuccess! The original file was not modified.")
    print(f"New uncommented file saved to: {output_file_path}")
    if extracted_ids:
        print(f"Extracted IDs list saved to: {ids_file_path}")
    else:
        print("No description numbers were found inside the uncommented sections.")

if __name__ == "__main__":
    uncomment_custom_items()

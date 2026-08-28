"""
This script processes inventory CSV files, compares hashes, and updates
a previously scanned items file with new data and VirusTotal findings.
Any items found in the combined, deduplicated inventory but not in the
previously scanned items will be placed in a CSV file named For_Submission.csv.
The script will also write the complete deduplicated inventory to
a file named all_identified.csv.
It includes robust handling for potential UnicodeDecodeErrors by attempting
to read CSV files with 'utf-8' and falling back to 'cp1252' encoding,
which is common for files from Windows systems.

NOTE: Code has been updated to force consistent string formatting (strip whitespace,
lowercase, and string type) to prevent duplicate errors.
"""
# Standard library imports
import logging
import shutil
import os
from pathlib import Path
import tempfile

# Third-party imports
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="{asctime} - {levelname} - {message}",
    style='{',
    handlers=[
        logging.FileHandler("inventory_processing.log", mode='w'),
        logging.StreamHandler()
    ]
)

def append_vt_found_to_previous_scanned(previous_scanned_path,
                                        all_scanned_path):
    """
    Finds rows in the 'all_scanned' file that are new and haveHTH
    'VT_Status' of 'Found in VirusTotal'. Appends these rows to the
    'previously_scanned' file by using a local temporary file as a cache.
    """
    logging.info(
        "Starting new VirusTotal findings"
        " append process with local cache"
    )

    # Load previously scanned items
    processed_hashes = set()
    try:
        if previous_scanned_path.exists():
            # Try to read with cp1252 encoding to handle Windows-created files
            previous_df = pd.read_csv(previous_scanned_path, encoding='cp1252')
            logging.info(
                "Previous file loaded. Columns: %s", list(previous_df.columns)
            )
            if 'SHA256Hash' in previous_df.columns:
                # Force standard formatting to avoid comparison errors
                previous_df['SHA256Hash'] = previous_df['SHA256Hash'].astype(str).str.strip().str.lower()
                processed_hashes = set(previous_df['SHA256Hash'].unique())
                logging.info(
                    "Loaded %d unique hashes from %s.",
                    len(processed_hashes), previous_scanned_path.name
                )
            else:
                logging.warning(
                    "%s has no 'SHA256Hash' column. All items will"
                    " be considered new.",
                    previous_scanned_path.name
                )
        else:
            logging.warning(
                "File not found: %s. All items will be considered new.",
                previous_scanned_path.name
            )
    except pd.errors.EmptyDataError:
        logging.warning(
            "Ignoring empty previous file: %s", previous_scanned_path.name
        )
    except FileNotFoundError:
        logging.warning(
            "File not found: %s. All items will be considered new.",
            previous_scanned_path.name
        )
    except (IOError, OSError):
        # Catch other common file system errors
        logging.exception(
            "An unexpected file system error occurred with %s.",
            previous_scanned_path.name
        )
        return

    # Load all scanned items
    try:
        # Try to read with cp1252 encoding to handle Windows-created files
        all_scanned_df = pd.read_csv(all_scanned_path, encoding='cp1252')
        logging.info(
            "'All_Scanned_Items' file loaded. Columns: %s",
            list(all_scanned_df.columns)
        )
        logging.info(
            "'All_Scanned_Items' has %d total rows.",
            len(all_scanned_df)
        )
    except (
        FileNotFoundError,
        pd.errors.ParserError,
        pd.errors.EmptyDataError,
    ):
        # Specific exceptions for CSV reading
        logging.exception(
            "Error reading 'All_Scanned_Items' from %s. Skipping append.",
            all_scanned_path
        )
        return

    if ('SHA256Hash' not in all_scanned_df.columns or
            'VT_Status' not in all_scanned_df.columns):
        logging.error(
            "'All_Scanned_Items' is missing required columns "
            "('SHA256Hash' or 'VT_Status')."
        )
        return
    
    # Force standard formatting on the all_scanned_df hashes too
    all_scanned_df['SHA256Hash'] = all_scanned_df['SHA256Hash'].astype(str).str.strip().str.lower()


    # Filter for new items with 'Found in VirusTotal' VT_Status
    is_new = ~all_scanned_df['SHA256Hash'].isin(processed_hashes)
    is_vt_found = (
        all_scanned_df['VT_Status'].str.strip() == 'Found in VirusTotal'
    )
    new_vt_found_items = all_scanned_df[is_new & is_vt_found]

    logging.info(
        "Number of new items (not in previously scanned): %d", is_new.sum()
    )
    logging.info(
        "Number of items with VT_Status 'Found in VirusTotal': %d",
        is_vt_found.sum()
    )
    logging.info(
        "Number of filtered rows to append: %d", len(new_vt_found_items)
    )

    if new_vt_found_items.empty:
        logging.info("No new items with a 'Found in VirusTotal'"
                     "VT_Status were identified.")
        return

    # Use a temporary file for appending
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            delete=False,
            suffix='.csv',
            encoding='utf-8'
        ) as tmp:
            tmp_path = Path(tmp.name)
            # Write the new data to the temporary file
            # Note: We ensure headers are NOT written here as we are appending to an existing file
            new_vt_found_items.to_csv(
                tmp_path,
                index=False,
                mode='w',
                header=False 
            )

        # Now append the temporary file to the network file
        with open(previous_scanned_path, 'a', encoding='utf-8') as target_file:
            with open(tmp_path, 'r', encoding='utf-8') as source_file:
                shutil.copyfileobj(source_file, target_file)

        logging.info(
            "Successfully appended %d new findings to %s.",
            len(new_vt_found_items),
            previous_scanned_path.name
        )
    except (IOError, OSError):
        # Catch specific I/O-related errors during the temporary file process
        logging.exception(
            "An I/O or OS error occurred while appending data using "
            "the temporary file. Attempting to clean up."
        )
        raise
    finally:
        # Clean up the temporary file whether an error occurred or not
        if tmp_path and tmp_path.exists():
            try:
                os.remove(tmp_path)
            except OSError:
                logging.warning("Failed to clean up temporary file: %s",
                                tmp_path)


def create_submission_file(inventory_df,
                           previous_scanned_path,
                           submission_path):
    """
    Compares the combined, deduplicated inventory with previously scanned
    items and creates a CSV of all new items that need to be submitted for
    scanning.
    """
    logging.info("Starting submission file creation process.")

    processed_hashes = set()
    try:
        # Check if previous scanned file exists and has the 'SHA256Hash' column
        if previous_scanned_path.exists():
            # Try to read the previous file, handling encoding errors
            try:
                previous_df = pd.read_csv(previous_scanned_path, encoding='utf-8')
            except UnicodeDecodeError:
                logging.warning(
                    f"UnicodeDecodeError with {previous_scanned_path.name}, attempting 'cp1252' encoding."
                )
                previous_df = pd.read_csv(previous_scanned_path, encoding='cp1252')

            if 'SHA256Hash' not in previous_df.columns:
                logging.warning(
                    "%s has no 'SHA256Hash' column. Will assume all items are new.",
                    previous_scanned_path.name
                )
                processed_hashes = set()
            else:
                # IMPORTANT: Normalize hash values for robust comparison
                previous_df['SHA256Hash'] = previous_df['SHA256Hash'].astype(str).str.strip().str.lower()
                processed_hashes = set(previous_df['SHA256Hash'].unique())
                logging.info(
                    "Loaded %d hashes from previous scan.",
                    len(processed_hashes)
                )
        else:
            logging.warning(
                "%s not found. All inventory items will be considered for submission.",
                previous_scanned_path.name
            )
            processed_hashes = set()
    
    except (IOError, OSError, pd.errors.EmptyDataError, pd.errors.ParserError):
        # Catch various errors and reset processed_hashes if history can't be read
        logging.exception(
            "An error occurred while reading the previous scanned file. "
            "Proceeding assuming no history."
        )
        processed_hashes = set()


    # Identify items in the current inventory not found in the history
    if 'SHA256Hash' not in inventory_df.columns:
        logging.error("Input inventory DataFrame is missing the 'SHA256Hash' column.")
        return

    # IMPORTANT: Normalize current inventory hash values for robust comparison
    inventory_df['SHA256Hash'] = inventory_df['SHA256Hash'].astype(str).str.strip().str.lower()

    # Use boolean indexing to filter out previously scanned hashes
    # This guarantees no overlap between previous scans and the submission list
    is_new = ~inventory_df['SHA256Hash'].isin(processed_hashes)
    submission_df = inventory_df[is_new]

    logging.info(
        "Identified %d items for submission (Total inventory size: %d).",
        len(submission_df),
        len(inventory_df)
    )

    if submission_df.empty:
        logging.info("No new items require submission. Skipping file creation.")
        # Ensure the file is not left over from previous runs
        if submission_path.exists():
            os.remove(submission_path)
            logging.info("Removed old %s as no new items were found.", submission_path.name)
        return

    # Write the filtered data to the submission file
    try:
        submission_df.to_csv(submission_path, index=False, encoding='utf-8')
        logging.info("Successfully created submission file: %s with %d entries.",
                     submission_path.name, len(submission_df))
    except (IOError, OSError):
        logging.exception("Error writing submission file to %s.", submission_path)


def find_and_process_inventory(base_path):
    """
    Recursively searches for CSV files matching the pattern
    '*_Inventory.csv', logs their name and row count, combines, deduplicates
    the inventory, and then saves and processes it.
    """
    logging.info("Searching for all inventory files in %s", base_path)
    inventory_files = list(base_path.rglob('*_Inventory.csv'))
    combined_df = pd.DataFrame()

    if not inventory_files:
        logging.warning("No inventory files (*_Inventory.csv) found in %s.",
                        base_path)
        return

    for filepath in inventory_files:
        try:
            # Attempt to read the CSV with standard utf-8 encoding
            try:
                df = pd.read_csv(filepath, encoding='utf-8')
            except UnicodeDecodeError:
                logging.warning(
                    f"UnicodeDecodeError with {filepath.name},"
                    " attempting 'cp1252' encoding."
                )
                df = pd.read_csv(filepath, encoding='cp1252')

            row_count = len(df)
            logging.info(f"Found file: {filepath.name} with {row_count} rows. Full path: {filepath}")

            # Concatenate the dataframe to the combined dataframe
            combined_df = pd.concat([combined_df, df], ignore_index=True)

        except (pd.errors.ParserError,
                pd.errors.EmptyDataError,
                FileNotFoundError):
            logging.exception(f"Error processing inventory file: "
                              "{filepath.name}")

    if combined_df.empty:
        logging.error("No data could be read from any inventory files.")
        return

    logging.info(f"Combined data from all inventory files has {len(combined_df)} rows.")

    # Deduplicate the combined dataframe
    # Assuming 'SHA256Hash' is the column to deduplicate by
    if 'SHA256Hash' in combined_df.columns:
        # Normalize hashes before deduplication
        combined_df['SHA256Hash'] = combined_df['SHA256Hash'].astype(str).str.strip().str.lower()
        
        initial_row_count = len(combined_df)
        combined_df.drop_duplicates(subset='SHA256Hash', keep='first',
                                    inplace=True)
        final_row_count = len(combined_df)
        logging.info(
            f"Deduplicated combined inventory. Removed {initial_row_count - final_row_count} duplicates."
        )

        # Write the final deduplicated inventory to a new CSV file
        all_identified_file = base_path / 'all_identified.csv'
        combined_df.to_csv(all_identified_file, index=False)
        logging.info(f"Wrote deduplicated inventory to {all_identified_file.name}.")

    else:
        logging.warning("Combined inventory lacks 'SHA256Hash' column."
                        " Skipping deduplication and not writing"
                        " all_identified.csv.")
    
    # Define file paths for the next steps
    previous_scanned_file = base_path / 'Previously_Scanned.csv'
    submission_file = base_path / 'For_Submission.csv'

    # Pass the combined and deduplicated dataframe to create_submission_file
    create_submission_file(combined_df, previous_scanned_file, submission_file)

    # Check for the results file and update history if present
    all_scanned_file = base_path / 'All_Scanned_Items.csv'
    if all_scanned_file.exists():
        append_vt_found_to_previous_scanned(previous_scanned_file,
                                            all_scanned_file,
                                            )
    else:
        logging.warning("All_Scanned_Items.csv not found. Skipping VirusTotal"
                        " findings update.")


if __name__ == "__main__":
    # Define the base network directory where all files are located
    BASE_DIRECTORY = (
        r'\\hilltop.global\HTHShares\Departmental\IT'
        r'\Windows10Logs\AppInventoryScript'
    )
    base_path_obj = Path(BASE_DIRECTORY)

    # Call the main processing function
    find_and_process_inventory(base_path_obj)

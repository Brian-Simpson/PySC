
import pandas as pd
import requests

# **1. Define Console URL and API Token**
CONSOLE_URL = "https://usea1-017.sentinelone.net"
# e.g., "https://yourcompany.sentinelone.net"
API_TOKEN = (
    "eyJraWQiOiJ1cy1lYXN0LTEtcHJvZC0wIiwiYWxnIjoiRVMyNTYifQ"
    ".eyJzdWIiOiJzZXJ2aWNldXNlci0zNjZmNDFiMS1mY2JjLTQ5ZmUtOG"
    "Q0Yi1lOWVjODZiYzUzMGRAbWdtdC03NzM0Ny5zZW50aW5lbG9uZS5uZX"
    "QiLCJpc3MiOiJhdXRobi11cy1lYXN0LTEtcHJvZCIsImRlcGxveW1lbnR"
    "faWQiOiI3NzM0NyIsInR5cGUiOiJ1c2VyIiwiZXhwIjoxODEyNTYwODQ4L"
    "CJpYXQiOjE3NDk0ODg5NTgsImp0aSI6ImE2NWJmMTgyLTJjZTYtNDc5NS05"
    "YjI4LTNhZjUwNjQxMzkzMCJ9.EIVrr8v_xU3VXEEH3dmMn9KFSyAvZW9cRj"
    "Lzg3-JfueWeEKllN5nJbvKR_KF32ym9ZgSHEYzqj-G2_cR4vi1qw"
)


# **2. Read Approved Applications from Excel**
approved_file = "C:\\PySC\\approved_applications_list.xlsx"
try:
    print(f"Reading approved applications list from {approved_file}...")
    # Add a message before reading the file
    Approved_Applications_List = pd.read_excel(approved_file)
    print("Finished reading approved applications list.")

except FileNotFoundError:
    print(f"Error: Approved applications file not found at {approved_file}")
    exit()
except Exception as e:
    print(f"Error reading Excel file: {e}")
    exit()

# Extract the list of approved application names (assuming the column is named 'applicationName')
approved_app_names = Approved_Applications_List['applicationName'].tolist()

# **3. Query SentinelOne Application Inventory API with Pagination**
api_endpoint = f"{CONSOLE_URL}/web/api/v2.1/application-management/inventory"

headers = {
    "Content-type": "application/json",
    "Authorization": f"APIToken {API_TOKEN}"
}

all_inventory_data = []  # To store all results across pages
cursor = None  # Initialize cursor for the first request

print("Fetching application inventory from SentinelOne API...")
records_fetched = 0

while True:
    params = {}
    if cursor:
        params['cursor'] = cursor
        # Add cursor to parameters for subsequent requests

    try:
        response = requests.get(api_endpoint, headers=headers, params=params)
        response.raise_for_status()
        # Raise HTTPError for bad responses (4xx or 5xx)
        inventory_data = response.json()
        # Parse the JSON response

    except requests.exceptions.RequestException as e:
        print(f"Error making API request: {e}")
        exit()

    if inventory_data and 'data' in inventory_data:
        current_page_data = inventory_data['data']
        all_inventory_data.extend(current_page_data)
        # Add current page data to the list
        records_fetched += len(current_page_data)

        # Print progress after fetching a page
        if records_fetched % 1000 == 0:
             print(f"Fetched {records_fetched} application records...")

        # Check for the next cursor to continue pagination
        if 'pagination' in inventory_data and 'nextCursor' in inventory_data['pagination']:
            cursor = inventory_data['pagination']['nextCursor']
            if not cursor:  # If nextCursor is empty, we've reached the end
                break
        else:
            break
        # No pagination information, assume it's the last page or no data
    else:
        break
    # No data in the response, assume no results

print(f"Finished fetching {len(all_inventory_data)} application records.")

# 4. Process Inventory Data and Identify Unapproved Applications
unapproved_applications = []
if all_inventory_data:
    print("Processing inventory data to identify unapproved applications...")
    for app_data in all_inventory_data:
        if 'applicationName' in app_data and app_data['applicationName'] not in approved_app_names:
            unapproved_applications.append({
                "applicationName": app_data.get("applicationName", ""),
                "applicationVendor": app_data.get("applicationVendor", ""),
                "applicationVersionsCount": app_data.get("applicationVersionsCount", ""),
                "endpointsCount": app_data.get("endpointsCount", "")
            })

# 5. Create DataFrame for Unapproved Apps. and write to file with Progress
if unapproved_applications:
    Unapproved_Applications_Inventory = pd.DataFrame(unapproved_applications)

    output_file = "C:\\PySC\\Unapproved_Applications_Inventory.xlsx"
    chunk_size = 1000
    # Define the chunk size for progress notification
    total_rows = len(Unapproved_Applications_Inventory)
    rows_written = 0

    print(f"Writing unapproved applications inventory to {output_file}...")

    # Use ExcelWriter for chunked writing
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        for i in range(0, total_rows, chunk_size):
            chunk = Unapproved_Applications_Inventory[i:i + chunk_size]
            # Write the header only for the first chunk
            header = (i == 0)
            chunk.to_excel(writer, sheet_name='Sheet1', startrow=rows_written + 1, index=False, header=header)
            rows_written += len(chunk)
            print(f"Written {rows_written} of {total_rows} rows to Excel.")

    print(f"Finished writing unapproved applications inventory to {output_file}")

else:
    print("No unapproved applications found in the inventory.")

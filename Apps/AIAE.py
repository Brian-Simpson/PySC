
import requests
import pandas as pd
from datetime import datetime

# Define the API endpoints and headers
api_url = "https://usea1-017.sentinelone.net/web/api/v2.1/application-management/inventory"
endpoints_url = "https://usea1-017.sentinelone.net/web/api/v2.1/application-management/inventory/endpoints"
api_token = (
    "eyJraWQiOiJ1cy1lYXN0LTEtcHJvZC0wIiwiYWxnIjoiRVMyNTYifQ"
    ".eyJzdWIiOiJzZXJ2aWNldXNlci0zNjZmNDFiMS1mY2JjLTQ5ZmUtOG"
    "Q0Yi1lOWVjODZiYzUzMGRAbWdtdC03NzM0Ny5zZW50aW5lbG9uZS5uZX"
    "QiLCJpc3MiOiJhdXRobi11cy1lYXN0LTEtcHJvZCIsImRlcGxveW1lbnR"
    "faWQiOiI3NzM0NyIsInR5cGUiOiJ1c2VyIiwiZXhwIjoxODEyNTYwODQ4L"
    "CJpYXQiOjE3NDk0ODg5NTgsImp0aSI6ImE2NWJmMTgyLTJjZTYtNDc5NS05"
    "YjI4LTNhZjUwNjQxMzkzMCJ9.EIVrr8v_xU3VXEEH3dmMn9KFSyAvZW9cRj"
    "Lzg3-JfueWeEKllN5nJbvKR_KF32ym9ZgSHEYzqj-G2_cR4vi1qw"
)
# Replace with your actual API token

headers = {
    "Authorization": f"ApiToken {api_token}",
    "Content-Type": "application/json"
}

# Initialize variables
applications = []
cursor = None
count = 0


def fetch_data(url, cursor=None, params=None):
    """
    Function to fetch data from the API
    """
    if params is None:
        params = {"limit": 1000}
    if cursor:
        params["cursor"] = cursor
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


while True:  # Fetch and process application data
    data = fetch_data(api_url, cursor)
    applications.extend(data['data'])
    count += len(data['data'])
    print(f"Processed {count} applications")
    
    cursor = data.get('pagination', {}).get('nextCursor')
    if not cursor:
        break

# Create a DataFrame for applications
df = pd.DataFrame(applications, columns=[
    'applicationName', 'applicationVendor', 'applicationVersionsCount',
    'endpointsCount', 'estimate'
])

# Read the approved applications list
approved_file = "C:\\PySC\\approved_applications_list.xlsx"
approved_df = pd.read_excel(approved_file)

# Find unapproved applications
unapproved_df = df[~df['applicationName'].isin(approved_df['applicationName'])]

# Initialize a list to store endpoint data
endpoints_data = []
endpoint_count = 0

# Fetch endpoint data for each unapproved application
for _, row in unapproved_df.iterrows():
    app_name = row['applicationName']
    app_vendor = row['applicationVendor']
    cursor = None
    
    while True:
        params = {
            "applicationName": app_name,
            "applicationVendor": app_vendor,
            "limit": 1000
        }
        data = fetch_data(endpoints_url, cursor, params)
        endpoints_data.extend(data['data'])
        endpoint_count += len(data['data'])

        # Print the current incremented count of processed endpoint records
        print(f"Processed {endpoint_count} endpoint records")

        cursor = data.get('pagination', {}).get('nextCursor')
        if not cursor:
            break

# Create a DataFrame for endpoints
endpoints_df = pd.DataFrame(endpoints_data, columns=[
    'applicationInstallationPath', 'applicationName',
    'endpointId', 'endpointName', 'endpointType'
])

# Generate a filename with a sortable date
date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"C:\\PySC\\AppInventory_{date_str}.xlsx"

# Write to an Excel file
with pd.ExcelWriter(filename, engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name='applications', index=False)
    unapproved_df.to_excel(writer, sheet_name='UnApproved Applications', index=False)
    endpoints_df.to_excel(writer, sheet_name='Endpoints', index=False)

print(f"Data written to {filename}")

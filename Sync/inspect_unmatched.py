import pandas as pd
p=r'C:\\PySC\\Sync\\Merged-MSSRV-powershell_unmatched_20260709.xlsx'
try:
    df=pd.read_excel(p,engine='openpyxl')
    mask=df['PowerShell'].astype(str).str.contains('enablesecuritysignature',case=False,na=False)
    print(df[mask].to_string(index=False))
except Exception as e:
    print('ERROR',e)

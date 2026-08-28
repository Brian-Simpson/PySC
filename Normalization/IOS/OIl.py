import yfinance as yf
import seaborn as sns
import matplotlib.pyplot as plt
from curl_cffi.requests import Session
import pandas as pd
import urllib3
import base64
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 1. SETTINGS & BYPASS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = Session(impersonate="chrome", verify=False)
RECIPIENT_EMAIL = "partnerdproperties@gmail.com"

SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password" 

symbols = {'WTI Oil': 'CL=F', 'USD Index': 'DX-Y.NYB', 'Global Demand': '^GSPC'}

def calculate_rsi(data, window=14):
    delta = data.diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    return 100 - (100 / (1 + (gain / loss)))

def send_alert(body):
    if SENDER_EMAIL == "your_email@gmail.com":
        print("Skipping email: No credentials provided.")
        return
    msg = MIMEMultipart()
    msg['From'], msg['To'], msg['Subject'] = SENDER_EMAIL, RECIPIENT_EMAIL, "WTI OIL: Updated Weekly Prediction"
    msg.attach(MIMEText(body, 'html'))
    try:
        with smtplib.SMTP("://gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"Alert email sent to {RECIPIENT_EMAIL}")
    except Exception as e:
        print(f"Email failed: {e}")

try:
    print("Fetching 5 years of data...")
    raw_data = yf.download(list(symbols.values()), period="5y", session=session)

    if 'Adj Close' in raw_data.columns.get_level_values(0):
        df_price = raw_data['Adj Close'].rename(columns={v: k for k, v in symbols.items()}).dropna()
    else:
        df_price = raw_data['Close'].rename(columns={v: k for k, v in symbols.items()}).dropna()
    
    oil_volume = raw_data['Volume']['CL=F'].dropna()
    oil_raw = raw_data.xs('CL=F', axis=1, level=1)
    weekly_data = oil_raw.resample('W').agg({'High': 'max', 'Low': 'min', 'Close': 'last'}).dropna()

    # --- UPDATED PREDICTION LOGIC ---
    last_price = df_price['WTI Oil'].iloc[-1]
    recent_volatility = (weekly_data['High'] - weekly_data['Low']).tail(12).mean()
    momentum_factor = (weekly_data['Close'].iloc[-1] / weekly_data['Close'].iloc[-4])
    
    # Project range based on current price
    next_high = last_price + (recent_volatility * 0.6 * momentum_factor)
    next_low = last_price - (recent_volatility * 0.6 / momentum_factor)
    
    # Logical Bracketing
    if next_high <= last_price: next_high = last_price + (recent_volatility * 0.5)
    if next_low >= last_price: next_low = last_price - (recent_volatility * 0.5)
    
    # Signal Logic
    range_width = next_high - next_low
    pos = (last_price - next_low) / range_width
    if pos < 0.25: signal = "<span style='color:green;'><b>BUY</b></span> (Near Support)"
    elif pos > 0.75: signal = "<span style='color:red;'><b>SELL</b></span> (Near Resistance)"
    else: signal = "<span style='color:orange;'><b>HOLD</b></span> (Neutral)"

    # --- CHART GENERATION ---
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 20))
    plt.subplots_adjust(hspace=0.5)
    sns.heatmap(df_price.pct_change().corr(), annot=True, cmap='RdYlGn', ax=ax1)
    ax1.set_title('5-Year Correlation Matrix')
    returns = df_price.pct_change()
    rolling_corr = returns['WTI Oil'].rolling(120).corr(returns['USD Index'])
    ax2.plot(rolling_corr, color='orange', label='120D Rolling Corr')
    ax2.axhline(0, color='black', alpha=0.3)
    ax2.set_title('USD Influence Trend')
    rsi = calculate_rsi(df_price['WTI Oil'])
    ax3.plot(rsi, color='purple', label='RSI (14)')
    ax3.axhline(70, color='red', ls='--'), ax3.axhline(30, color='green', ls='--')
    ax3_v = ax3.twinx()
    ax3_v.bar(oil_volume.index, oil_volume, color='gray', alpha=0.15)
    ax3.set_title('Momentum & Volume')

    # SAVE TO HTML
    tmpfile = BytesIO()
    fig.savefig(tmpfile, format='png', bbox_inches='tight')
    encoded = base64.b64encode(tmpfile.getvalue()).decode('utf-8')
    weekly_table = weekly_data.tail(52).to_html(classes='table')
    
    prediction_html = f"""
    <div style='border: 2px solid #333; padding: 20px; font-family: sans-serif; background-color: #f9f9f9;'>
        <h2>SIGNAL: {signal}</h2>
        <p style='font-size: 1.2em;'>Current WTI Price: <b>${last_price:.2f}</b></p>
        <hr>
        <h3>FORCED WEEKLY PREDICTION</h3>
        <p style='font-size: 1.4em; color: #27ae60;'>Projected High: <b>${next_high:.2f}</b></p>
        <p style='font-size: 1.4em; color: #c0392b;'>Projected Low: <b>${next_low:.2f}</b></p>
        <p><i>Range based on current price + 12-week volatility baseline.</i></p>
        <hr>
        <h4>Weekly History (Past Year)</h4>
        <div style='height: 300px; overflow-y: scroll;'>{weekly_table}</div>
    </div>
    """

    full_html = f"<html><body><h1>WTI Oil Analysis (5-Year View)</h1><img src='data:image/png;base64,{encoded}'>{prediction_html}</body></html>"
    with open("commodity_report.html", "w") as f:
        f.write(full_html)
    print("Report saved. High/Low range now anchored to current price.")
    send_alert(full_html)

except Exception as e:
    print(f"Error: {e}")

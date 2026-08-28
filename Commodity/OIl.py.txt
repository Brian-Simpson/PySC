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

# EMAIL CONFIGURATION (Fill these in)
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password" # Use a Google App Password
RECIPIENT_EMAIL = "your_email@gmail.com"

symbols = {'WTI Oil': 'CL=F', 'USD Index': 'DX-Y.NYB', 'Global Demand': '^GSPC'}

def calculate_rsi(data, window=14):
    delta = data.diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    return 100 - (100 / (1 + (gain / loss)))

def send_alert(prediction, reason):
    msg = MIMEMultipart()
    msg['From'], msg['To'], msg['Subject'] = SENDER_EMAIL, RECIPIENT_EMAIL, "HIGH CONFIDENCE TRADE ALERT"
    body = f"Alert: High Confidence {prediction} signal detected.\nReasoning: {reason}"
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print("Alert email sent successfully.")
    except Exception as e: print(f"Email failed: {e}")

try:
    raw_data = yf.download(list(symbols.values()), period="6mo", session=session)
    df_price = (raw_data['Adj Close'] if 'Adj Close' in raw_data.columns else raw_data['Close']).rename(columns={v: k for k, v in symbols.items()}).dropna()
    oil_volume = raw_data['Volume']['CL=F'].dropna()

    # --- PLOT GENERATION ---
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 15))
    plt.subplots_adjust(hspace=0.5)

    # Plot 1: Heatmap
    sns.heatmap(df_price.pct_change().corr(), annot=True, cmap='RdYlGn', ax=ax1)
    ax1.set_title('6-Month Correlation Matrix')

    # Plot 2: Rolling Correlation
    returns = df_price.pct_change()
    rolling_corr = returns['WTI Oil'].rolling(30).corr(returns['USD Index'])
    ax2.plot(rolling_corr, color='orange', label='Oil vs USD Correlation')
    ax2.axhline(0, color='black', alpha=0.3), ax2.set_title('30D Influence Trend'), ax2.legend(loc='lower left')

    # Plot 3: RSI & Volume
    rsi = calculate_rsi(df_price['WTI Oil'])
    ax3.plot(rsi, color='purple', label='RSI (14)')
    ax3.axhline(70, color='red', ls='--'), ax3.axhline(30, color='green', ls='--')
    ax3_v = ax3.twinx()
    ax3_v.bar(oil_volume.index, oil_volume, color='gray', alpha=0.2, label='Volume')
    ax3.set_title('Momentum & Volume'), ax3.legend(loc='upper left'), ax3_v.legend(loc='upper right')

    # SAVE TO HTML
    tmpfile = BytesIO()
    fig.savefig(tmpfile, format='png')
    encoded = base64.b64encode(tmpfile.getvalue()).decode('utf-8')
    
    # Generate Window Summaries for HTML
    windows = rolling_corr.resample('30D').mean().dropna()
    summary_html = "<h3>30-Day Window Summaries</h3><ul>"
    for date, val in windows.items():
        summary_html += f"<li><b>{date.strftime('%Y-%m-%d')}</b>: Avg USD Correlation {val:.3f}</li>"
    summary_html += "</ul>"

    with open("commodity_report.html", "w") as f:
        f.write(f"<html><body><h1>Commodity Analysis Report</h1><img src='data:image/png;base64,{encoded}'>{summary_html}</body></html>")
    print("Report saved to commodity_report.html")

    # --- PREDICTION & ALERT ---
    last_rsi, last_corr, last_vol_change = rsi.iloc[-1], rolling_corr.iloc[-1], oil_volume.pct_change().iloc[-1]
    prediction, confidence, reasoning = "NEUTRAL", "Low", "Normal market flux."

    if last_rsi > 70 and last_vol_change > 0:
        prediction, confidence, reasoning = "BEARISH", "High Confidence", "Overbought RSI with surging volume."
    elif last_corr < -0.90:
        prediction, confidence, reasoning = "USD-DRIVEN", "High Confidence", "Extreme USD inverse correlation."

    if confidence == "High Confidence":
        send_alert(prediction, reasoning)

except Exception as e: print(f"Error: {e}")

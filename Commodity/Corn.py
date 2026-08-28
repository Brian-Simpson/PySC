import yfinance as yf
import seaborn as sns
import matplotlib.pyplot as plt
from curl_cffi.requests import Session
import pandas as pd
import urllib3
import base64
from io import BytesIO

# 1. SETTINGS & BYPASS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = Session(impersonate="chrome", verify=False)

# Corn Tickers: ZC=F (Corn Futures), ZS=F (Soybeans), DX-Y.NYB (USD), CL=F (Oil/Ethanol)
symbols = {'Corn': 'ZC=F', 'Soybeans': 'ZS=F', 'USD Index': 'DX-Y.NYB', 'Crude Oil': 'CL=F'}

def calculate_rsi(data, window=14):
    delta = data.diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    return 100 - (100 / (1 + (gain / loss)))

try:
    print("Fetching 5 years of Corn data...")
    raw_data = yf.download(list(symbols.values()), period="5y", session=session)

    # Correct for Multi-Index
    price_col = 'Adj Close' if 'Adj Close' in raw_data.columns.get_level_values(0) else 'Close'
    df_price = raw_data[price_col].rename(columns={v: k for k, v in symbols.items()}).dropna()
    corn_volume = raw_data['Volume']['ZC=F'].dropna()
    corn_raw = raw_data.xs('ZC=F', axis=1, level=1)
    
    # --- RATIO & PREDICTION ---
    df_price['CornSoyRatio'] = df_price['Soybeans'] / df_price['Corn']
    last_price = df_price['Corn'].iloc[-1]
    current_ratio = df_price['CornSoyRatio'].iloc[-1]
    
    # Weekly Data for Prediction (Anchored to current price)
    weekly_data = corn_raw.resample('W').agg({'High': 'max', 'Low': 'min', 'Close': 'last'}).dropna()
    recent_vol = (weekly_data['High'] - weekly_data['Low']).tail(12).mean()
    momentum = (weekly_data['Close'].iloc[-1] / weekly_data['Close'].iloc[-4])
    
    next_high = last_price + (recent_vol * 0.6 * momentum)
    next_low = last_price - (recent_vol * 0.6 / momentum)

    # --- CHARTS ---
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 20))
    plt.subplots_adjust(hspace=0.5)

    # 1. 5-Year Correlation Heatmap
    sns.heatmap(df_price.pct_change().corr(), annot=True, cmap='YlGn', ax=ax1)
    ax1.set_title('5-Year Corn Influence Correlation Matrix')

    # 2. Corn-Soy Ratio Trend
    ax2.plot(df_price['CornSoyRatio'], color='green', label='Corn-Soy Ratio')
    ax2.axhline(2.5, color='blue', ls='--', label='Classic Pivot (2.5)')
    ax2.axhline(2.3, color='red', ls='--', label='Modern Pivot (2.3)')
    ax2.set_title('Planting Sentiment: Corn vs Soybean Price Ratio')
    ax2.legend()

    # 3. RSI & Volume
    rsi = calculate_rsi(df_price['Corn'])
    ax3.plot(rsi, color='gold', label='Corn RSI')
    ax3.axhline(70, color='red', ls='--'), ax3.axhline(30, color='green', ls='--')
    ax3_v = ax3.twinx()
    ax3_v.bar(corn_volume.index, corn_volume, color='gray', alpha=0.15)
    ax3.set_title('Corn Momentum & Trading Volume')

    # SAVE & DISPLAY
    tmpfile = BytesIO()
    fig.savefig(tmpfile, format='png', bbox_inches='tight')
    encoded = base64.b64encode(tmpfile.getvalue()).decode('utf-8')
    
    ratio_signal = "FAVORS SOYBEANS" if current_ratio > 2.5 else "FAVORS CORN" if current_ratio < 2.3 else "NEUTRAL"
    
    prediction_html = f"""
    <div style='border: 2px solid #333; padding: 20px; font-family: sans-serif; background-color: #fdfdfd;'>
        <h2>CORN-SOY RATIO: {current_ratio:.2f} (<span style='color:blue;'>{ratio_signal}</span>)</h2>
        <p>Current Corn Price: <b>${last_price:.2f}</b></p>
        <hr>
        <h3>NEXT WEEK RANGE FORECAST</h3>
        <p style='font-size: 1.4em; color: green;'>Projected High: <b>${next_high:.2f}</b></p>
        <p style='font-size: 1.4em; color: red;'>Projected Low: <b>${next_low:.2f}</b></p>
        <hr>
        <h4>Weekly History (Past Year)</h4>
        <div style='height: 300px; overflow-y: scroll;'>{weekly_data.tail(52).to_html(classes='table')}</div>
    </div>
    """

    with open("corn_analysis_report.html", "w") as f:
        f.write(f"<html><body><h1>5-Year Corn Market Analysis</h1><img src='data:image/png;base64,{encoded}'>{prediction_html}</body></html>")
    print("Corn analysis saved to corn_analysis_report.html")

except Exception as e:
    print(f"Error: {e}")

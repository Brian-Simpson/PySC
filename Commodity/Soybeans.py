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

# Choose your target here: 'Soybeans', 'Wheat', or 'Sugar'
target_mode = 'Soybeans' 

# Define Tickers for all three versions
configs = {
    'Soybeans': {'Primary': 'ZS=F', 'Influences': ['CL=F', 'DX-Y.NYB', '^GSPC', 'ZC=F']},
    'Wheat': {'Primary': 'ZW=F', 'Influences': ['CL=F', 'DX-Y.NYB', '^GSPC', 'ZS=F']},
    'Sugar': {'Primary': 'SB=F', 'Influences': ['CL=F', 'DX-Y.NYB', '^GSPC', 'BRLUSD=X']}
}

selected = configs[target_mode]
symbols = {target_mode: selected['Primary'], **{f"Inf_{i}": ticker for i, ticker in enumerate(selected['Influences'])}}

def calculate_rsi(data, window=14):
    delta = data.diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    return 100 - (100 / (1 + (gain / loss)))

try:
    print(f"Fetching 5 years of {target_mode} data...")
    raw_data = yf.download(list(symbols.values()), period="5y", session=session)

    # Clean multi-index data
    price_col = 'Adj Close' if 'Adj Close' in raw_data.columns.get_level_values(0) else 'Close'
    df_price = raw_data[price_col].rename(columns={v: k for k, v in symbols.items()}).dropna()
    primary_vol = raw_data['Volume'][selected['Primary']].dropna()
    primary_raw = raw_data.xs(selected['Primary'], axis=1, level=1)

    # --- FORCED PREDICTION LOGIC ---
    last_price = df_price[target_mode].iloc[-1]
    weekly_data = primary_raw.resample('W').agg({'High': 'max', 'Low': 'min', 'Close': 'last'}).dropna()
    recent_vol = (weekly_data['High'] - weekly_data['Low']).tail(12).mean()
    momentum = (weekly_data['Close'].iloc[-1] / weekly_data['Close'].iloc[-4])
    
    next_high = last_price + (recent_vol * 0.6 * momentum)
    next_low = last_price - (recent_vol * 0.6 / momentum)

    # --- PLOTS ---
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 18))
    plt.subplots_adjust(hspace=0.4)

    # 1. 5-Year Correlation
    sns.heatmap(df_price.pct_change().corr(), annot=True, cmap='RdYlGn', ax=ax1)
    ax1.set_title(f'5-Year {target_mode} Correlation Matrix')

    # 2. Rolling Influence (120-day)
    returns = df_price.pct_change()
    rolling_corr = returns[target_mode].rolling(120).corr(returns['Inf_1']) # Inf_1 is typically USD Index
    ax2.plot(rolling_corr, color='orange', label='120D Rolling Corr (Primary vs USD)')
    ax2.axhline(0, color='black', alpha=0.3)
    ax2.set_title('Long-Term USD Influence Trend')

    # 3. RSI & Volume
    rsi = calculate_rsi(df_price[target_mode])
    ax3.plot(rsi, color='purple', label='RSI (14)')
    ax3.axhline(70, color='red', ls='--'), ax3.axhline(30, color='green', ls='--')
    ax3_v = ax3.twinx()
    ax3_v.bar(primary_vol.index, primary_vol, color='gray', alpha=0.15)
    ax3.set_title('Momentum & Trading Volume')

    plt.show()

    # SAVE HTML
    tmpfile = BytesIO()
    fig.savefig(tmpfile, format='png', bbox_inches='tight')
    encoded = base64.b64encode(tmpfile.getvalue()).decode('utf-8')
    
    with open(f"{target_mode.lower()}_report.html", "w") as f:
        f.write(f"<html><body><h1>{target_mode} Analysis</h1><img src='data:image/png;base64,{encoded}'><h2>Prediction: High ${next_high:.2f} | Low ${next_low:.2f}</h2></body></html>")
    print(f"Report saved: {target_mode.lower()}_report.html")

except Exception as e: print(f"Error: {e}")

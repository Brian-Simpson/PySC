import yfinance as yf
import seaborn as sns
import matplotlib.pyplot as plt
from curl_cffi.requests import Session
import pandas as pd
import numpy as np
import urllib3
import base64
from io import BytesIO
from datetime import datetime
import warnings

# ==========================================
# 1. SETTINGS & CORPORATE BYPASS
# ==========================================
warnings.simplefilter(action='ignore', category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = Session(impersonate="chrome", verify=False)
timestamp = datetime.now().strftime("%Y-%m-%d %I:%M %p")
jan_1_date = "2026-01-02"

# ==========================================
# 2. CONTRACT SPECIFICATIONS (For Margin Calculation)
# ==========================================
# Unit size, Tick value, and Margin estimates per exchange
contract_specs = {
    'CL=F': {'unit': 1000, 'label': 'Barrels', 'tick': 10.00, 'initial': 6500, 'maint': 6000},
    'ZC=F': {'unit': 5000, 'label': 'Bushels', 'tick': 12.50, 'initial': 2500, 'maint': 2200},
    'ZS=F': {'unit': 5000, 'label': 'Bushels', 'tick': 12.50, 'initial': 3300, 'maint': 3000},
    'ZW=F': {'unit': 5000, 'label': 'Bushels', 'tick': 12.50, 'initial': 3000, 'maint': 2800},
    'LE=F': {'unit': 40000, 'label': 'Pounds', 'tick': 10.00, 'initial': 2800, 'maint': 2500},
    'SB=F': {'unit': 112000, 'label': 'Pounds', 'tick': 11.20, 'initial': 1500, 'maint': 1300}
}

ticker_glossary = {
    'CL=F': 'Crude Oil (WTI) Futures',
    'DX-Y.NYB': 'US Dollar Index (DXY) - Exchange: NY Board of Trade',
    '^GSPC': 'S&P 500 Index - US Demand Proxy',
    'ZC=F': 'Corn Futures (CBOT)',
    'ZS=F': 'Soybean Futures (CBOT)',
    'ZW=F': 'Wheat Futures (CBOT)',
    'LE=F': 'Live Cattle Futures (CME)',
    'SB=F': 'Sugar No. 11 Futures (ICE)',
    'BRLUSD=X': 'BRL/USD Exchange Rate'
}

# ==========================================
# 3. TOP 10 INFLUENCERS (EXPLICIT)
# ==========================================
oil_top10 = ["1. Hormuz security", "2. OPEC+ quotas", "3. 2026 Surplus", "4. AI Power", "5. Shale growth", "6. EV adoption", "7. SPR refills", "8. Carbon price", "9. China demand", "10. USD Index"]
cattle_top10 = ["1. Low herd inventory", "2. Beef demand", "3. Heifer retention", "4. Feed costs", "5. Pasture health", "6. Carcass weight", "7. Mexico trade", "8. Asia exports", "9. Fund positioning", "10. Labor supply"]
corn_top10 = ["1. 2026 Acreage", "2. Input costs", "3. 45Z Biofuel", "4. China pledges", "5. Soy-Corn ratio", "6. Stocks-to-use", "7. La Niña", "8. Brazil crop", "9. Logistics", "10. Interest rates"]
soy_top10 = ["1. China imports", "2. Brazil dominance", "3. Renewable diesel", "4. Acreage targets", "5. S. American yield", "6. Global stocks", "7. Cost squeeze", "8. USD volatility", "9. Palm oil", "10. EPA mandates"]
wheat_top10 = ["1. Russia/Ukraine", "2. Low acres", "3. Russian quotas", "4. Black Sea security", "5. US drought", "6. Fertilizer costs", "7. Net-shorts", "8. Australia capacity", "9. China demand", "10. Freight rates"]
sugar_top10 = ["1. Brazil sugar/ethanol", "2. BRL exchange", "3. India policy", "4. Weather cycles", "5. Global surplus", "6. Energy prices", "7. Consumption taxes", "8. EU quotas", "9. Red Sea logistics", "10. Short covering"]

# ==========================================
# 4. TECHNICAL ENGINE FUNCTIONS
# ==========================================
def calculate_rsi(data, window=14):
    delta = data.diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    rs = gain / loss
    return 100 - (100 / (1 + rs))

def calculate_mfi(df, ticker, window=14):
    high = df['High'][ticker].iloc[:, 0] if isinstance(df['High'][ticker], pd.DataFrame) else df['High'][ticker]
    low = df['Low'][ticker].iloc[:, 0] if isinstance(df['Low'][ticker], pd.DataFrame) else df['Low'][ticker]
    close = df['Close'][ticker].iloc[:, 0] if isinstance(df['Close'][ticker], pd.DataFrame) else df['Close'][ticker]
    volume = df['Volume'][ticker].iloc[:, 0] if isinstance(df['Volume'][ticker], pd.DataFrame) else df['Volume'][ticker]
    tp = (high + low + close) / 3
    mf = tp * volume
    pos_flow = mf.where(tp > tp.shift(1), 0).rolling(window=window).sum()
    neg_flow = mf.where(tp < tp.shift(1), 0).rolling(window=window).sum()
    return 100 - (100 / (1 + (pos_flow / neg_flow)))
def get_clean_series(df, ticker, col='Adj Close'):
    try:
        target = df[col][ticker] if isinstance(df.columns, pd.MultiIndex) else df[col]
        if isinstance(target, pd.DataFrame): target = target.iloc[:, 0]
        return target.dropna()
    except KeyError:
        target = df['Close'][ticker] if isinstance(df.columns, pd.MultiIndex) else df['Close']
        if isinstance(target, pd.DataFrame): target = target.iloc[:, 0]
        return target.dropna()

def get_base64(fig):
    buffer = BytesIO()
    fig.savefig(buffer, format='png', bbox_inches='tight')
    plt.close(fig)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

# ==========================================
# 5. COMMODITY ANALYSIS ENGINE (FINANCIAL)
# ==========================================
def run_commodity_analysis(name, ticker, influences, top10):
    print(f"Manual Trace Analysis: Generating Financial Signal for {name}...")
    raw_max = yf.download(ticker, period="max", session=session)
    raw_5y = yf.download([ticker] + list(influences.values()), period="5y", session=session)
    
    p_ser = get_clean_series(raw_5y, ticker)
    v_ser = get_clean_series(raw_5y, ticker, col='Volume')
    curr_p = float(p_ser.iloc[-1])

    # Stats & Trending Logic
    ath = float(raw_max['Close'].max())
    atl = float(raw_max['Close'].min())
    avg = float(raw_max['Close'].mean())
    p_2y = p_ser.tail(504)
    h2y, l2y, a2y = float(p_2y.max()), float(p_2y.min()), float(p_2y.mean())
    t_at_icon = "↑" if curr_p > avg else "↓"
    t_2y_icon = "↑" if curr_p > a2y else "↓"

    # technical indicators
    rsi_s = calculate_rsi(p_ser); mfi_s = calculate_mfi(raw_5y, ticker)
    c_rsi, c_mfi = float(rsi_s.iloc[-1]), float(mfi_s.iloc[-1])
    v5, v20 = float(v_ser.tail(5).mean()), float(v_ser.tail(20).mean())
    vt = "RISING" if v5 > v20 else "FALLING"

    # Forecast Logic
    wk_df = raw_5y.xs(ticker, axis=1, level=1).resample('W').agg({'High':'max','Low':'min','Close':'last'}).dropna()
    v_rng = float((wk_df['High']-wk_df['Low']).tail(12).mean())
    mom = float(wk_df['Close'].iloc[-1]/wk_df['Close'].iloc[-4])
    ph, pl = curr_p + (v_rng*0.6*mom), curr_p - (v_rng*0.6/mom)

    # SEASONAL BACK-CHECK & FINANCIAL EXPLANATION
    hist_txt = "No direct monthly seasonal match found."
    financial_breakdown = ""
    seasonal_move = 0.0
    
    if c_rsi < 35 or c_rsi > 65:
        m = datetime.now().month
        hits = rsi_s[(rsi_s.index.month == m) & (rsi_s.index.year < 2026) & (abs(rsi_s - c_rsi) < 12)]
        if not hits.empty:
            dt = hits.index[-1]
            p_then = p_ser.loc[dt]
            p_later = p_ser.shift(-20).loc[dt]
            seasonal_move = float(((p_later - p_then) / p_then) * 100)
            hist_txt = f"SEASONAL MATCH: In {dt.strftime('%B %Y')}, RSI was similar. Price moved {seasonal_move:+.2f}% in 30 days."
            
            # --- CONSTRUCT REQUESTED FINANCIAL EXPLANATION ---
            spec = contract_specs.get(ticker, {'unit': 1, 'label': 'Units', 'tick': 0.01, 'initial': 0, 'maint': 0})
            notional = curr_p * spec['unit']
            price_drop = curr_p * (seasonal_move / 100)
            dollar_impact = abs(spec['unit'] * price_drop)
            
            financial_breakdown = f"""
            <strong>Contract & Price Details:</strong><br>
            Contract Size: {spec['unit']:,} {spec['label']} (Standard for {ticker}).<br>
            Current Notional Value: ${notional:,.2f} (${curr_p:.4f} per unit × {spec['unit']:,} units).<br>
            Tick Value: ${spec['tick']:.2f} (Smallest move of 0.01).<br><br>
            <strong>Margin Requirements (Estimates):</strong><br>
            Initial Margin: Approx. ${spec['initial']:,} (Amount to open trade).<br>
            Maintenance Margin: Approx. ${spec['maint']:,} (Minimum balance to hold).<br><br>
            <strong>Impact of a {seasonal_move:+.2f}% Move (Seasonal Match):</strong><br>
            Target Price Shift: ${price_drop:+.4f} (Bringing price to approx. ${curr_p + price_drop:.4f}).<br>
            Dollar Impact per Contract: ${dollar_impact:,.2f}.<br>
            Margin Impact: This {'loss' if seasonal_move < 0 else 'gain'} would affect your equity. If balance drops below maintenance, a margin call occurs.<br><br>
            <strong>Analysis of the Signal:</strong><br>
            RSI ({c_rsi:.1f}) & MFI ({c_mfi:.1f}): Technical extremes reached.<br>
            Risk: The Seasonal Back-Check shows that even at these levels, history resulted in a {seasonal_move:+.2f}% move.<br>
            Conviction: {'Strong' if vt == 'RISING' else 'Weak'} (Confirmed by Volume Trend).
            """

    # Recommendation
    rec, r_cls = ("OVERSOLD (BUY)", "buy") if c_rsi < 35 else ("OVERBOUGHT (SELL)", "sell") if c_rsi > 65 else ("NEUTRAL (HOLD)", "hold")
    
    # Execution Points
    day_h, day_l = float(raw_5y['High'][ticker].iloc[-1]), float(raw_5y['Low'][ticker].iloc[-1])
    pp = (day_h + day_l + curr_p) / 3
    s1, r1 = (2 * pp) - day_h, (2 * pp) - day_l

    try:
        j_p = float(p_ser.truncate(before=jan_1_date).iloc)
        ytd = ((curr_p - j_p) / j_p) * 100
    except: ytd = 0.0

    return {
        'name': name, 'rsi': c_rsi, 'mfi': c_mfi, 'vt': vt, 'high': ph, 'low': pl, 
        'curr': curr_p, 'raw': raw_5y, 'p_ser': p_ser, 'alert': rec, 'a_cls': r_cls, 
        'conf': "Moderate", 'ath': ath, 'atl': atl, 'at_avg': avg, 'h2y': h2y, 'l2y': l2y, 
        'avg2y': a2y, 't_at': t_at_icon, 't_2y': t_2y_icon, 'logic': financial_breakdown, 
        'hist': hist_txt, 'top10': top10, 'ticker': ticker, 'inf': influences, 
        's1': s1, 'r1': r1, 't_v': v20*1.3, 'ytd': ytd, 'act_h': day_h, 'act_l': day_l
    }

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO SIGNING
// ═══════════════════════════════════════════════════════════════════════════
function hmacB64(msg, s) { return crypto.createHmac('sha256', s).update(msg).digest('base64'); }
function hmacHex(msg, s) { return crypto.createHmac('sha256', s).update(msg).digest('hex'); }
function kcH(method, ep, body, k, s, p) {
  const ts = Date.now().toString();
  const m = ts + method.toUpperCase() + ep + (body ? JSON.stringify(body) : '');
  return { 'KC-API-KEY': k, 'KC-API-SIGN': hmacB64(m, s), 'KC-API-TIMESTAMP': ts, 'KC-API-PASSPHRASE': hmacB64(p, s), 'KC-API-KEY-VERSION': '2', 'Content-Type': 'application/json' };
}
async function safeJSON(r) {
  const t = await r.text(); if (!t) throw new Error('Empty response');
  try { return JSON.parse(t); } catch { throw new Error('Invalid JSON (status ' + r.status + ')'); }
}

// ═══════════════════════════════════════════════════════════════════════════
// TECHNICAL INDICATORS
// ═══════════════════════════════════════════════════════════════════════════
const TA = {
  sma(d, p) { const r = []; for (let i = p - 1; i < d.length; i++) r.push(d.slice(i - p + 1, i + 1).reduce((a, b) => a + b, 0) / p); return r; },
  ema(d, p) {
    if (d.length < p) return [];
    const k = 2 / (p + 1), e = [d.slice(0, p).reduce((a, b) => a + b, 0) / p];
    for (let i = p; i < d.length; i++) e.push(d[i] * k + e[e.length - 1] * (1 - k));
    return e;
  },
  rsi(c, p = 14) {
    if (c.length < p + 1) return [];
    let ag = 0, al = 0;
    for (let i = 1; i <= p; i++) { const d = c[i] - c[i - 1]; d > 0 ? ag += d : al -= d; }
    ag /= p; al /= p;
    const r = [al === 0 ? 100 : 100 - 100 / (1 + ag / al)];
    for (let i = p + 1; i < c.length; i++) {
      const d = c[i] - c[i - 1];
      ag = (ag * (p - 1) + Math.max(d, 0)) / p;
      al = (al * (p - 1) + Math.max(-d, 0)) / p;
      r.push(al === 0 ? 100 : 100 - 100 / (1 + ag / al));
    }
    return r;
  },
  atr(h, l, c, p = 14) {
    const tr = [];
    for (let i = 1; i < h.length; i++) tr.push(Math.max(h[i] - l[i], Math.abs(h[i] - c[i - 1]), Math.abs(l[i] - c[i - 1])));
    let a = tr.slice(0, p).reduce((x, y) => x + y, 0) / p;
    const r = [a];
    for (let i = p; i < tr.length; i++) { a = (a * (p - 1) + tr[i]) / p; r.push(a); }
    return r;
  },
  macd(c, fast = 12, slow = 26, sig = 9) {
    const ef = TA.ema(c, fast), es = TA.ema(c, slow);
    const offset = slow - fast, line = [];
    for (let i = 0; i < es.length; i++) line.push(ef[i + offset] - es[i]);
    const signal = TA.ema(line, sig);
    const hist = [];
    const sOff = line.length - signal.length;
    for (let i = 0; i < signal.length; i++) hist.push(line[i + sOff] - signal[i]);
    return { line, signal, hist };
  },
  bollinger(c, p = 20, mult = 2) {
    const sma = TA.sma(c, p), upper = [], lower = [];
    for (let i = p - 1; i < c.length; i++) {
      const slice = c.slice(i - p + 1, i + 1);
      const mean = sma[i - p + 1];
      const std = Math.sqrt(slice.reduce((a, v) => a + (v - mean) ** 2, 0) / p);
      upper.push(mean + mult * std);
      lower.push(mean - mult * std);
    }
    return { sma, upper, lower };
  },
  stochRSI(c, rsiP = 14, stochP = 14, kP = 3, dP = 3) {
    const rsi = TA.rsi(c, rsiP); if (rsi.length < stochP) return { k: [], d: [] };
    const stoch = [];
    for (let i = stochP - 1; i < rsi.length; i++) {
      const slice = rsi.slice(i - stochP + 1, i + 1);
      const min = Math.min(...slice), max = Math.max(...slice);
      stoch.push(max === min ? 50 : ((rsi[i] - min) / (max - min)) * 100);
    }
    return { k: TA.sma(stoch, kP), d: TA.sma(TA.sma(stoch, kP), dP) };
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// MARKET ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function analyzeCandles(candles) {
  const c = candles.map(x => x.close), h = candles.map(x => x.high), l = candles.map(x => x.low);
  const ema9 = TA.ema(c, 9), ema21 = TA.ema(c, 21), ema50 = TA.ema(c, 50);
  const rsi = TA.rsi(c), atr = TA.atr(h, l, c);
  const macd = TA.macd(c);
  const bb = TA.bollinger(c);
  const stochRsi = TA.stochRSI(c);
  const last = (a) => a.length ? a[a.length - 1] : null;
  const prev = (a) => a.length > 1 ? a[a.length - 2] : null;

  // Market condition
  const e9 = last(ema9), e21 = last(ema21), e50 = last(ema50), r = last(rsi);
  let condition = 'neutral';
  if (e9 && e21 && e50 && r !== null) {
    const diff = ((e9 - e21) / e21) * 100;
    if (Math.abs(diff) < 0.3 && r > 40 && r < 60) condition = 'sideways';
    else if (e9 > e21 && e21 > e50 && r > 50) condition = 'bullish';
    else if (e9 < e21 && e21 < e50 && r < 50) condition = 'bearish';
    else if (e9 > e21) condition = 'mildly_bullish';
    else condition = 'mildly_bearish';
  }

  // Support / Resistance (simple pivot-based)
  const recentH = h.slice(-20), recentL = l.slice(-20);
  const resistance = Math.max(...recentH);
  const support = Math.min(...recentL);

  return {
    price: last(c), condition, ema9: last(ema9), ema21: last(ema21), ema50: last(ema50),
    rsi: last(rsi), prevRsi: prev(rsi), atr: last(atr),
    macdLine: last(macd.line), macdSignal: last(macd.signal), macdHist: last(macd.hist), prevMacdHist: prev(macd.hist),
    bbUpper: last(bb.upper), bbLower: last(bb.lower), bbSma: last(bb.sma),
    stochK: last(stochRsi.k), stochD: last(stochRsi.d),
    support, resistance, candles: candles.slice(-50)
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// TRADING STRATEGIES
// ═══════════════════════════════════════════════════════════════════════════
const STRATEGIES = {
  // EMA crossover + RSI confirmation
  ema_rsi(a) {
    const { ema9, ema21, rsi, prevRsi, condition } = a;
    if (!ema9 || !ema21 || rsi === null) return 'hold';
    if (condition === 'sideways') return 'hold';
    // Buy: EMA9 crosses above EMA21, RSI rising from below 45
    if (ema9 > ema21 && rsi > 40 && rsi < 70 && (prevRsi === null || rsi > prevRsi)) return 'buy';
    // Sell: EMA9 crosses below EMA21, RSI falling from above 55
    if (ema9 < ema21 && rsi < 60 && rsi > 30 && (prevRsi === null || rsi < prevRsi)) return 'sell';
    return 'hold';
  },
  // MACD + Bollinger Bands
  macd_bb(a) {
    const { macdHist, prevMacdHist, price, bbUpper, bbLower, rsi } = a;
    if (macdHist === null || prevMacdHist === null || !price) return 'hold';
    // Buy: MACD histogram turns positive + price near lower BB
    if (macdHist > 0 && prevMacdHist <= 0 && price < bbLower * 1.02 && rsi < 45) return 'buy';
    // Sell: MACD histogram turns negative + price near upper BB
    if (macdHist < 0 && prevMacdHist >= 0 && price > bbUpper * 0.98 && rsi > 55) return 'sell';
    return 'hold';
  },
  // RSI + Stochastic RSI (mean reversion / scalping)
  scalp_rsi(a) {
    const { rsi, stochK, stochD, condition } = a;
    if (rsi === null || stochK === null) return 'hold';
    // Buy: RSI oversold + StochRSI cross up
    if (rsi < 35 && stochK < 25 && stochK > stochD) return 'buy';
    // Sell: RSI overbought + StochRSI cross down
    if (rsi > 65 && stochK > 75 && stochK < stochD) return 'sell';
    return 'hold';
  },
  // Trend following (EMA50 + MACD)
  trend(a) {
    const { price, ema50, macdHist, prevMacdHist, rsi, condition } = a;
    if (!ema50 || !price || macdHist === null) return 'hold';
    // Only trade with the trend
    if (price > ema50 && macdHist > 0 && prevMacdHist <= 0 && rsi > 45 && rsi < 75) return 'buy';
    if (price < ema50 && macdHist < 0 && prevMacdHist >= 0 && rsi > 25 && rsi < 55) return 'sell';
    return 'hold';
  },
  // Combined (consensus of strategies)
  combined(a) {
    const signals = [STRATEGIES.ema_rsi(a), STRATEGIES.macd_bb(a), STRATEGIES.scalp_rsi(a), STRATEGIES.trend(a)];
    const buys = signals.filter(s => s === 'buy').length;
    const sells = signals.filter(s => s === 'sell').length;
    if (buys >= 2) return 'buy';
    if (sells >= 2) return 'sell';
    return 'hold';
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// BOT STATE
// ═══════════════════════════════════════════════════════════════════════════
const bot = {
  running: false,
  mode: 'paper',
  tradingType: 'spot',
  strategy: 'combined',
  symbols: ['BTC-USDT'],
  intervalMs: 60000,
  intervalId: null,
  // Risk
  riskPct: 2,
  maxDrawdownPct: 15,
  slATR: 1.5,
  tpATR: 3.0,
  trailingStop: true,
  trailATR: 1.0,
  maxOpenTrades: 3,
  // Futures
  leverage: 5,
  futuresMargin: 'cross',
  // State
  paperUSD: 10000,
  startingBalance: 10000,
  peakBalance: 10000,
  openTrades: [],
  history: [],
  totalPnL: 0,
  winCount: 0,
  lossCount: 0,
  lastAnalysis: {},
  credentials: null,
  log: [],
  overtradeCooldown: {},
};

function botLog(msg) {
  const entry = { time: new Date().toISOString(), msg };
  bot.log.push(entry);
  if (bot.log.length > 200) bot.log.shift();
  console.log(`[BOT] ${entry.time} — ${msg}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// FETCH CANDLES
// ═══════════════════════════════════════════════════════════════════════════
async function fetchKlines(symbol, type = '15min', limit = 100) {
  const end = Math.floor(Date.now() / 1000);
  const mins = type === '1min' ? 1 : type === '5min' ? 5 : type === '15min' ? 15 : type === '1hour' ? 60 : type === '4hour' ? 240 : 1440;
  const start = end - limit * mins * 60;
  const url = `https://api.kucoin.com/api/v1/market/candles?type=${type}&symbol=${symbol}&startAt=${start}&endAt=${end}`;
  const r = await fetch(url);
  const d = await safeJSON(r);
  if (d.code !== '200000' || !d.data) throw new Error('Candle fetch failed');
  return d.data.reverse().map(c => ({ time: +c[0] * 1000, open: +c[1], close: +c[2], high: +c[3], low: +c[4], volume: +c[5] }));
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVE ORDER EXECUTION (KuCoin Spot)
// ═══════════════════════════════════════════════════════════════════════════
async function placeSpotOrder(side, symbol, amount) {
  if (!bot.credentials) throw new Error('No credentials');
  const { apiKey, apiSecret, passphrase } = bot.credentials;
  const ep = '/api/v1/orders';
  const body = { clientOid: crypto.randomUUID(), side, symbol, type: 'market', size: String(amount) };
  const r = await fetch('https://api.kucoin.com' + ep, { method: 'POST', headers: kcH('POST', ep, body, apiKey, apiSecret, passphrase), body: JSON.stringify(body) });
  const d = await safeJSON(r);
  if (d.code !== '200000') throw new Error(d.msg || 'Order failed: ' + d.code);
  return d.data;
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVE ORDER EXECUTION (KuCoin Futures)
// ═══════════════════════════════════════════════════════════════════════════
async function placeFuturesOrder(side, symbol, leverage, size) {
  if (!bot.credentials) throw new Error('No credentials');
  const { apiKey, apiSecret, passphrase } = bot.credentials;
  // Futures API uses different base
  const ep = '/api/v1/orders';
  const futSymbol = symbol.replace('-', '') + 'M'; // e.g. BTCUSDTM
  const body = { clientOid: crypto.randomUUID(), side, symbol: futSymbol, type: 'market', leverage: String(leverage), size };
  const base = 'https://api-futures.kucoin.com';
  const r = await fetch(base + ep, { method: 'POST', headers: kcH('POST', ep, body, apiKey, apiSecret, passphrase), body: JSON.stringify(body) });
  const d = await safeJSON(r);
  if (d.code !== '200000') throw new Error(d.msg || 'Futures order failed: ' + d.code);
  return d.data;
}

// ═══════════════════════════════════════════════════════════════════════════
// PAPER TRADE EXECUTION
// ═══════════════════════════════════════════════════════════════════════════
function paperBuy(symbol, price, usdAmount, sl, tp, type = 'spot') {
  const qty = usdAmount / price;
  const lev = type === 'futures' ? bot.leverage : 1;
  const margin = type === 'futures' ? usdAmount / lev : usdAmount;
  bot.paperUSD -= margin;
  const trade = {
    id: crypto.randomUUID().slice(0, 8),
    symbol, side: 'buy', type, leverage: lev,
    entryPrice: price, qty, usdAmount, margin,
    sl, tp, trailingSl: bot.trailingStop ? sl : null, highSince: price,
    openTime: new Date().toISOString(), status: 'open'
  };
  bot.openTrades.push(trade);
  botLog(`PAPER BUY ${symbol} @ $${price.toFixed(2)} | qty: ${qty.toFixed(6)} | SL: $${sl.toFixed(2)} | TP: $${tp.toFixed(2)} | ${type} ${lev}x`);
  return trade;
}

function paperSell(symbol, price, usdAmount, sl, tp, type = 'spot') {
  if (type !== 'futures') return null; // spot short not supported
  const qty = usdAmount / price;
  const margin = usdAmount / bot.leverage;
  bot.paperUSD -= margin;
  const trade = {
    id: crypto.randomUUID().slice(0, 8),
    symbol, side: 'sell', type: 'futures', leverage: bot.leverage,
    entryPrice: price, qty, usdAmount, margin,
    sl, tp, trailingSl: bot.trailingStop ? sl : null, lowSince: price,
    openTime: new Date().toISOString(), status: 'open'
  };
  bot.openTrades.push(trade);
  botLog(`PAPER SHORT ${symbol} @ $${price.toFixed(2)} | qty: ${qty.toFixed(6)} | SL: $${sl.toFixed(2)} | TP: $${tp.toFixed(2)} | futures ${bot.leverage}x`);
  return trade;
}

function closeTrade(trade, price, reason) {
  trade.status = 'closed';
  trade.exitPrice = price;
  trade.closeTime = new Date().toISOString();
  trade.reason = reason;
  const dir = trade.side === 'buy' ? 1 : -1;
  const rawPnl = (price - trade.entryPrice) * trade.qty * dir;
  trade.pnl = trade.type === 'futures' ? rawPnl * trade.leverage : rawPnl;
  trade.pnlPct = ((trade.exitPrice - trade.entryPrice) / trade.entryPrice * 100 * dir * (trade.type === 'futures' ? trade.leverage : 1));
  bot.paperUSD += trade.margin + trade.pnl;
  bot.totalPnL += trade.pnl;
  if (trade.pnl > 0) bot.winCount++; else bot.lossCount++;
  bot.openTrades = bot.openTrades.filter(t => t.id !== trade.id);
  bot.history.push(trade);
  if (bot.history.length > 500) bot.history.shift();
  botLog(`CLOSE ${trade.side.toUpperCase()} ${trade.symbol} @ $${price.toFixed(2)} | PnL: $${trade.pnl.toFixed(2)} (${trade.pnlPct.toFixed(1)}%) | ${reason}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// BOT TICK — runs every interval
// ═══════════════════════════════════════════════════════════════════════════
async function botTick() {
  try {
    for (const symbol of bot.symbols) {
      const candles = await fetchKlines(symbol, '15min', 100);
      const analysis = analyzeCandles(candles);
      bot.lastAnalysis[symbol] = analysis;
      const { price, atr } = analysis;
      if (!price || !atr) continue;

      // ── Check open trades for SL / TP / Trailing ──
      for (const trade of [...bot.openTrades]) {
        if (trade.symbol !== symbol) continue;
        // Update trailing stop
        if (bot.trailingStop && trade.trailingSl !== null) {
          if (trade.side === 'buy') {
            if (price > (trade.highSince || trade.entryPrice)) trade.highSince = price;
            const newTrail = trade.highSince - atr * bot.trailATR;
            if (newTrail > trade.trailingSl) trade.trailingSl = newTrail;
            // Check trailing SL
            if (price <= trade.trailingSl) { closeTrade(trade, price, 'trailing_sl'); continue; }
          } else {
            if (price < (trade.lowSince || trade.entryPrice)) trade.lowSince = price;
            const newTrail = trade.lowSince + atr * bot.trailATR;
            if (newTrail < trade.trailingSl) trade.trailingSl = newTrail;
            if (price >= trade.trailingSl) { closeTrade(trade, price, 'trailing_sl'); continue; }
          }
        }
        // Check fixed SL
        if (trade.side === 'buy' && price <= trade.sl) { closeTrade(trade, price, 'stop_loss'); continue; }
        if (trade.side === 'sell' && price >= trade.sl) { closeTrade(trade, price, 'stop_loss'); continue; }
        // Check TP
        if (trade.side === 'buy' && price >= trade.tp) { closeTrade(trade, price, 'take_profit'); continue; }
        if (trade.side === 'sell' && price <= trade.tp) { closeTrade(trade, price, 'take_profit'); continue; }
      }

      // ── Drawdown check ──
      const curBalance = getCurrentBalance();
      if (curBalance > bot.peakBalance) bot.peakBalance = curBalance;
      const drawdown = ((bot.peakBalance - curBalance) / bot.peakBalance) * 100;
      if (drawdown >= bot.maxDrawdownPct) {
        botLog(`MAX DRAWDOWN REACHED (${drawdown.toFixed(1)}%) — pausing new trades`);
        continue;
      }

      // ── Overtrading filter (max 1 trade per symbol per 30min) ──
      const cooldownKey = symbol;
      if (bot.overtradeCooldown[cooldownKey] && Date.now() - bot.overtradeCooldown[cooldownKey] < 30 * 60 * 1000) continue;

      // ── Check max open trades ──
      if (bot.openTrades.length >= bot.maxOpenTrades) continue;
      // Don't open duplicate symbol
      if (bot.openTrades.some(t => t.symbol === symbol)) continue;

      // ── Get signal ──
      const strat = STRATEGIES[bot.strategy] || STRATEGIES.combined;
      const signal = strat(analysis);
      if (signal === 'hold') continue;

      // ── Calculate position size ──
      const balance = getCurrentBalance();
      const riskUSD = balance * (bot.riskPct / 100);
      const slDist = atr * bot.slATR;
      const positionUSD = Math.min(riskUSD / (slDist / price), balance * 0.25); // max 25% per trade

      if (positionUSD < 10) { botLog(`Position too small ($${positionUSD.toFixed(2)}) — skipping`); continue; }

      const sl = signal === 'buy' ? price - slDist : price + slDist;
      const tp = signal === 'buy' ? price + atr * bot.tpATR : price - atr * bot.tpATR;

      // ── Execute ──
      if (bot.mode === 'paper') {
        if (signal === 'buy') {
          paperBuy(symbol, price, positionUSD, sl, tp, bot.tradingType);
        } else if (signal === 'sell') {
          if (bot.tradingType === 'futures' || bot.tradingType === 'combined') {
            paperSell(symbol, price, positionUSD, sl, tp, 'futures');
          }
        }
      } else if (bot.mode === 'live') {
        try {
          if (signal === 'buy') {
            if (bot.tradingType === 'futures' || bot.tradingType === 'combined') {
              await placeFuturesOrder('buy', symbol, bot.leverage, Math.floor(positionUSD / price * 100));
            } else {
              const base = symbol.split('-')[0];
              const qty = (positionUSD / price).toFixed(6);
              await placeSpotOrder('buy', symbol, qty);
            }
            bot.openTrades.push({
              id: crypto.randomUUID().slice(0, 8), symbol, side: 'buy', type: bot.tradingType,
              entryPrice: price, qty: positionUSD / price, usdAmount: positionUSD, margin: positionUSD,
              sl, tp, leverage: bot.tradingType === 'futures' ? bot.leverage : 1,
              openTime: new Date().toISOString(), status: 'open', highSince: price,
              trailingSl: bot.trailingStop ? sl : null
            });
            botLog(`LIVE BUY ${symbol} @ $${price.toFixed(2)}`);
          }
        } catch (err) {
          botLog(`LIVE ORDER ERROR: ${err.message}`);
        }
      }
      bot.overtradeCooldown[cooldownKey] = Date.now();
    }
  } catch (err) {
    botLog(`TICK ERROR: ${err.message}`);
  }
}

function getCurrentBalance() {
  let bal = bot.paperUSD;
  for (const t of bot.openTrades) {
    const a = bot.lastAnalysis[t.symbol];
    if (!a) { bal += t.margin; continue; }
    const dir = t.side === 'buy' ? 1 : -1;
    const upnl = (a.price - t.entryPrice) * t.qty * dir * (t.type === 'futures' ? t.leverage : 1);
    bal += t.margin + upnl;
  }
  return bal;
}

// ═══════════════════════════════════════════════════════════════════════════
// BACKTESTING ENGINE
// ═══════════════════════════════════════════════════════════════════════════
async function runBacktest(symbol, strategy, periods = 500, riskPct = 2, slATR = 1.5, tpATR = 3.0) {
  const candles = await fetchKlines(symbol, '15min', periods);
  if (candles.length < 60) throw new Error('Not enough data');

  let balance = 10000, peak = 10000, maxDD = 0;
  const trades = [];
  let openTrade = null;

  for (let i = 55; i < candles.length; i++) {
    const slice = candles.slice(0, i + 1);
    const analysis = analyzeCandles(slice);
    const { price, atr } = analysis;
    if (!price || !atr) continue;

    // Check open trade
    if (openTrade) {
      if (openTrade.side === 'buy') {
        if (price <= openTrade.sl) {
          const pnl = (price - openTrade.entry) * openTrade.qty;
          balance += openTrade.cost + pnl;
          trades.push({ ...openTrade, exit: price, pnl, pnlPct: (pnl / openTrade.cost) * 100, reason: 'sl', time: candles[i].time });
          openTrade = null;
        } else if (price >= openTrade.tp) {
          const pnl = (price - openTrade.entry) * openTrade.qty;
          balance += openTrade.cost + pnl;
          trades.push({ ...openTrade, exit: price, pnl, pnlPct: (pnl / openTrade.cost) * 100, reason: 'tp', time: candles[i].time });
          openTrade = null;
        }
      } else {
        if (price >= openTrade.sl) {
          const pnl = (openTrade.entry - price) * openTrade.qty;
          balance += openTrade.cost + pnl;
          trades.push({ ...openTrade, exit: price, pnl, pnlPct: (pnl / openTrade.cost) * 100, reason: 'sl', time: candles[i].time });
          openTrade = null;
        } else if (price <= openTrade.tp) {
          const pnl = (openTrade.entry - price) * openTrade.qty;
          balance += openTrade.cost + pnl;
          trades.push({ ...openTrade, exit: price, pnl, pnlPct: (pnl / openTrade.cost) * 100, reason: 'tp', time: candles[i].time });
          openTrade = null;
        }
      }
    }

    if (balance > peak) peak = balance;
    const dd = ((peak - balance) / peak) * 100;
    if (dd > maxDD) maxDD = dd;

    if (openTrade) continue;

    const strat = STRATEGIES[strategy] || STRATEGIES.combined;
    const signal = strat(analysis);
    if (signal === 'hold') continue;

    const riskUSD = balance * (riskPct / 100);
    const slDist = atr * slATR;
    const cost = Math.min(riskUSD / (slDist / price), balance * 0.25);
    if (cost < 10) continue;

    const qty = cost / price;
    const sl = signal === 'buy' ? price - slDist : price + slDist;
    const tp = signal === 'buy' ? price + atr * tpATR : price - atr * tpATR;
    balance -= cost;
    openTrade = { side: signal, symbol, entry: price, qty, cost, sl, tp, openTime: candles[i].time };
  }

  // Close any remaining trade at last price
  if (openTrade) {
    const lastPrice = candles[candles.length - 1].close;
    const dir = openTrade.side === 'buy' ? 1 : -1;
    const pnl = (lastPrice - openTrade.entry) * openTrade.qty * dir;
    balance += openTrade.cost + pnl;
    trades.push({ ...openTrade, exit: lastPrice, pnl, pnlPct: (pnl / openTrade.cost) * 100, reason: 'end' });
  }

  const wins = trades.filter(t => t.pnl > 0);
  const losses = trades.filter(t => t.pnl <= 0);
  const grossProfit = wins.reduce((a, t) => a + t.pnl, 0);
  const grossLoss = Math.abs(losses.reduce((a, t) => a + t.pnl, 0));
  const avgWin = wins.length ? grossProfit / wins.length : 0;
  const avgLoss = losses.length ? grossLoss / losses.length : 0;

  return {
    symbol, strategy, periods: candles.length,
    startBalance: 10000, endBalance: Math.round(balance * 100) / 100,
    totalReturn: Math.round((balance - 10000) / 100) / 100,
    totalReturnPct: Math.round((balance - 10000) / 100) / 100,
    totalTrades: trades.length,
    wins: wins.length, losses: losses.length,
    winRate: trades.length ? Math.round((wins.length / trades.length) * 10000) / 100 : 0,
    profitFactor: grossLoss > 0 ? Math.round((grossProfit / grossLoss) * 100) / 100 : grossProfit > 0 ? 999 : 0,
    avgWin: Math.round(avgWin * 100) / 100,
    avgLoss: Math.round(avgLoss * 100) / 100,
    maxDrawdown: Math.round(maxDD * 100) / 100,
    trades: trades.slice(-50)
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// Connect exchange
app.post('/api/bot/connect', (req, res) => {
  const { apiKey, apiSecret, passphrase } = req.body || {};
  if (!apiKey || !apiSecret || !passphrase) return res.status(400).json({ error: 'All fields required' });
  bot.credentials = { apiKey, apiSecret, passphrase };
  botLog('Exchange credentials connected');
  res.json({ success: true });
});

// Start bot
app.post('/api/bot/start', (req, res) => {
  if (bot.running) return res.json({ success: true, msg: 'Already running' });
  bot.running = true;
  botLog(`Bot STARTED — mode: ${bot.mode} | strategy: ${bot.strategy} | symbols: ${bot.symbols.join(', ')} | type: ${bot.tradingType}`);
  // Run immediately then on interval
  botTick();
  bot.intervalId = setInterval(botTick, bot.intervalMs);
  res.json({ success: true });
});

// Stop bot
app.post('/api/bot/stop', (req, res) => {
  bot.running = false;
  if (bot.intervalId) { clearInterval(bot.intervalId); bot.intervalId = null; }
  botLog('Bot STOPPED');
  res.json({ success: true });
});

// Get status
app.get('/api/bot/status', (req, res) => {
  const balance = getCurrentBalance();
  const drawdown = bot.peakBalance > 0 ? ((bot.peakBalance - balance) / bot.peakBalance) * 100 : 0;
  const totalTrades = bot.winCount + bot.lossCount;
  res.json({
    running: bot.running, mode: bot.mode, strategy: bot.strategy, tradingType: bot.tradingType,
    symbols: bot.symbols, leverage: bot.leverage,
    balance: Math.round(balance * 100) / 100,
    startingBalance: bot.startingBalance,
    paperUSD: Math.round(bot.paperUSD * 100) / 100,
    totalPnL: Math.round(bot.totalPnL * 100) / 100,
    totalPnLPct: bot.startingBalance > 0 ? Math.round(((balance - bot.startingBalance) / bot.startingBalance) * 10000) / 100 : 0,
    winCount: bot.winCount, lossCount: bot.lossCount,
    winRate: totalTrades > 0 ? Math.round((bot.winCount / totalTrades) * 10000) / 100 : 0,
    drawdown: Math.round(drawdown * 100) / 100,
    maxDrawdownPct: bot.maxDrawdownPct,
    openTrades: bot.openTrades.map(t => ({
      ...t,
      currentPrice: bot.lastAnalysis[t.symbol]?.price || t.entryPrice,
      unrealizedPnl: (() => {
        const cp = bot.lastAnalysis[t.symbol]?.price || t.entryPrice;
        const dir = t.side === 'buy' ? 1 : -1;
        return Math.round((cp - t.entryPrice) * t.qty * dir * (t.type === 'futures' ? t.leverage : 1) * 100) / 100;
      })()
    })),
    recentHistory: bot.history.slice(-20).reverse(),
    analysis: bot.lastAnalysis,
    log: bot.log.slice(-30).reverse(),
    hasCredentials: !!bot.credentials,
    settings: {
      riskPct: bot.riskPct, maxDrawdownPct: bot.maxDrawdownPct,
      slATR: bot.slATR, tpATR: bot.tpATR, trailingStop: bot.trailingStop,
      trailATR: bot.trailATR, maxOpenTrades: bot.maxOpenTrades,
      leverage: bot.leverage, intervalMs: bot.intervalMs
    }
  });
});

// Update settings
app.post('/api/bot/settings', (req, res) => {
  const s = req.body || {};
  if (s.mode && ['paper', 'live'].includes(s.mode)) bot.mode = s.mode;
  if (s.tradingType && ['spot', 'futures', 'combined'].includes(s.tradingType)) bot.tradingType = s.tradingType;
  if (s.strategy && STRATEGIES[s.strategy]) bot.strategy = s.strategy;
  if (s.symbols && Array.isArray(s.symbols)) bot.symbols = s.symbols;
  if (s.riskPct !== undefined) bot.riskPct = Math.max(0.5, Math.min(5, +s.riskPct));
  if (s.maxDrawdownPct !== undefined) bot.maxDrawdownPct = Math.max(5, Math.min(30, +s.maxDrawdownPct));
  if (s.slATR !== undefined) bot.slATR = Math.max(0.5, Math.min(5, +s.slATR));
  if (s.tpATR !== undefined) bot.tpATR = Math.max(1, Math.min(10, +s.tpATR));
  if (s.trailingStop !== undefined) bot.trailingStop = !!s.trailingStop;
  if (s.trailATR !== undefined) bot.trailATR = Math.max(0.3, Math.min(3, +s.trailATR));
  if (s.maxOpenTrades !== undefined) bot.maxOpenTrades = Math.max(1, Math.min(10, +s.maxOpenTrades));
  if (s.leverage !== undefined) bot.leverage = Math.max(1, Math.min(20, +s.leverage));
  if (s.intervalMs !== undefined) bot.intervalMs = Math.max(30000, Math.min(300000, +s.intervalMs));
  // Reset paper balance if requested
  if (s.resetPaper) {
    bot.paperUSD = s.paperBalance || 10000;
    bot.startingBalance = bot.paperUSD;
    bot.peakBalance = bot.paperUSD;
    bot.openTrades = [];
    bot.history = [];
    bot.totalPnL = 0;
    bot.winCount = 0;
    bot.lossCount = 0;
    botLog('Paper trading reset');
  }
  // Restart interval if changed
  if (s.intervalMs && bot.running && bot.intervalId) {
    clearInterval(bot.intervalId);
    bot.intervalId = setInterval(botTick, bot.intervalMs);
  }
  botLog(`Settings updated: ${JSON.stringify(s)}`);
  res.json({ success: true });
});

// Analysis endpoint
app.get('/api/bot/analysis/:symbol', async (req, res) => {
  try {
    const candles = await fetchKlines(req.params.symbol, '15min', 100);
    const analysis = analyzeCandles(candles);
    const signals = {};
    for (const [name, fn] of Object.entries(STRATEGIES)) {
      if (name !== 'combined') signals[name] = fn(analysis);
    }
    signals.combined = STRATEGIES.combined(analysis);
    res.json({ success: true, analysis, signals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Backtest endpoint
app.post('/api/bot/backtest', async (req, res) => {
  try {
    const { symbol = 'BTC-USDT', strategy = 'combined', periods = 500 } = req.body || {};
    const result = await runBacktest(symbol, strategy, periods, bot.riskPct, bot.slATR, bot.tpATR);
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Close specific trade manually
app.post('/api/bot/close/:id', async (req, res) => {
  const trade = bot.openTrades.find(t => t.id === req.params.id);
  if (!trade) return res.status(404).json({ error: 'Trade not found' });
  const analysis = bot.lastAnalysis[trade.symbol];
  const price = analysis?.price || trade.entryPrice;
  closeTrade(trade, price, 'manual_close');
  res.json({ success: true });
});

// ── Prices (legacy) ──
app.get('/api/prices', async (req, res) => {
  try {
    const r = await fetch('https://api.kucoin.com/api/v1/market/allTickers');
    const d = await safeJSON(r);
    if (d.code !== '200000') return res.status(502).json({ error: 'Price feed error' });
    const prices = {};
    const WATCH = ['BTC-USDT','ETH-USDT','SOL-USDT','BNB-USDT','XRP-USDT','ADA-USDT','DOGE-USDT','LINK-USDT'];
    for (const t of d.data.ticker) {
      if (WATCH.includes(t.symbol)) prices[t.symbol] = { price: +t.last, change: +t.changeRate * 100, vol: +t.volValue };
    }
    res.json({ success: true, prices });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Balance ──
app.post('/api/kucoin/balance', async (req, res) => {
  const { apiKey, apiSecret, passphrase } = req.body || {};
  if (!apiKey || !apiSecret || !passphrase) return res.status(400).json({ error: 'All fields required' });
  try {
    const ep = '/api/v1/accounts?type=trade';
    const r = await fetch('https://api.kucoin.com' + ep, { headers: kcH('GET', ep, null, apiKey, apiSecret, passphrase) });
    const d = await safeJSON(r);
    if (d.code !== '200000') {
      const msg = d.code === '400003' ? 'Invalid API key.' : d.code === '400004' ? 'Invalid passphrase.' : d.code === '400005' ? 'Invalid API signature.' : d.msg || 'KuCoin error';
      return res.status(400).json({ error: msg });
    }
    const balances = {};
    for (const a of d.data) { const v = parseFloat(a.available); if (v > 0) balances[a.currency] = (balances[a.currency] || 0) + v; }
    let totalUSD = 0;
    try {
      const pr = await fetch('https://api.kucoin.com/api/v1/market/allTickers');
      const pd = await safeJSON(pr);
      const pm = { USDT: 1, USDC: 1 };
      if (pd.code === '200000') for (const t of pd.data.ticker) { if (t.symbol.endsWith('-USDT')) pm[t.symbol.replace('-USDT', '')] = +t.last || 0; }
      for (const [c, a] of Object.entries(balances)) totalUSD += (pm[c] || 0) * a;
    } catch {}
    res.json({ success: true, balances, totalUSD });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`TradeMatrix Pro v2 running → http://localhost:${PORT}`));

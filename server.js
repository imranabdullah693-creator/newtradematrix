const express=require('express'),crypto=require('crypto'),path=require('path');
const app=express();
app.use(express.json());

// ═══ AUTH ═══
const fs=require('fs');
const AUTH_FILE=path.join(__dirname,'.auth.json');
let AUTH={email:null,password:null,tokens:[]};
try{if(fs.existsSync(AUTH_FILE))AUTH=JSON.parse(fs.readFileSync(AUTH_FILE,'utf8'))}catch{}
function saveAuth(){try{fs.writeFileSync(AUTH_FILE,JSON.stringify(AUTH))}catch(e){console.log('Auth save error:',e.message)}}
function hashPw(pw){return crypto.createHash('sha256').update(pw+'tradematrix-salt').digest('hex')}
function genToken(){const t=crypto.randomBytes(32).toString('hex');AUTH.tokens.push(t);if(AUTH.tokens.length>10)AUTH.tokens=AUTH.tokens.slice(-10);saveAuth();return t}
function authMW(req,res,next){
  if(!AUTH.password)return next();
  const t=(req.headers.authorization||'').replace('Bearer ','');
  if(!t||!AUTH.tokens.includes(t))return res.status(401).json({error:'unauthorized'});
  next();
}
app.post('/api/auth/setup',(req,res)=>{
  if(AUTH.password)return res.status(400).json({error:'Account already exists. Please login.'});
  const{email,password}=req.body||{};
  if(!email||!email.includes('@'))return res.status(400).json({error:'Valid email required'});
  if(!password||password.length<4)return res.status(400).json({error:'Password must be 4+ characters'});
  AUTH.email=email;AUTH.password=hashPw(password);
  const token=genToken();
  console.log('Account created for:',email);
  res.json({success:true,token});
});
app.post('/api/auth/login',(req,res)=>{
  if(!AUTH.password)return res.json({success:true,needsSetup:true});
  const{email,password}=req.body||{};
  if(!email||!password)return res.status(400).json({error:'Email and password required'});
  if(email!==AUTH.email)return res.status(401).json({error:'Email not found'});
  if(hashPw(password)!==AUTH.password)return res.status(401).json({error:'Wrong password'});
  const token=genToken();
  res.json({success:true,token});
});
app.get('/api/auth/check',(req,res)=>{
  if(!AUTH.password)return res.json({needsSetup:true});
  const t=(req.headers.authorization||'').replace('Bearer ','');
  res.json({authenticated:!!t&&AUTH.tokens.includes(t),needsSetup:false});
});

// ═══ SIGNING ═══
function hmacB64(m,s){return crypto.createHmac('sha256',s).update(m).digest('base64')}
function kcH(mt,ep,body,k,s,p){const ts=Date.now().toString();const m=ts+mt.toUpperCase()+ep+(body?JSON.stringify(body):'');return{'KC-API-KEY':k,'KC-API-SIGN':hmacB64(m,s),'KC-API-TIMESTAMP':ts,'KC-API-PASSPHRASE':hmacB64(p,s),'KC-API-KEY-VERSION':'2','Content-Type':'application/json'}}
async function safeJSON(r){const t=await r.text();if(!t)throw new Error('Empty response');try{return JSON.parse(t)}catch{throw new Error('Invalid JSON ('+r.status+')')}}

// ═══ INDICATORS ═══
const TA={
  sma(d,p){const r=[];for(let i=p-1;i<d.length;i++)r.push(d.slice(i-p+1,i+1).reduce((a,b)=>a+b,0)/p);return r},
  ema(d,p){if(d.length<p)return[];const k=2/(p+1),e=[d.slice(0,p).reduce((a,b)=>a+b,0)/p];for(let i=p;i<d.length;i++)e.push(d[i]*k+e[e.length-1]*(1-k));return e},
  rsi(c,p=14){if(c.length<p+1)return[];let ag=0,al=0;for(let i=1;i<=p;i++){const d=c[i]-c[i-1];d>0?ag+=d:al-=d}ag/=p;al/=p;const r=[al===0?100:100-100/(1+ag/al)];for(let i=p+1;i<c.length;i++){const d=c[i]-c[i-1];ag=(ag*(p-1)+Math.max(d,0))/p;al=(al*(p-1)+Math.max(-d,0))/p;r.push(al===0?100:100-100/(1+ag/al))}return r},
  atr(h,l,c,p=14){const tr=[];for(let i=1;i<h.length;i++)tr.push(Math.max(h[i]-l[i],Math.abs(h[i]-c[i-1]),Math.abs(l[i]-c[i-1])));let a=tr.slice(0,p).reduce((x,y)=>x+y,0)/p;const r=[a];for(let i=p;i<tr.length;i++){a=(a*(p-1)+tr[i])/p;r.push(a)}return r},
  macd(c,f=12,s=26,sg=9){const ef=TA.ema(c,f),es=TA.ema(c,s),off=s-f,line=[];for(let i=0;i<es.length;i++)line.push(ef[i+off]-es[i]);const sig=TA.ema(line,sg),hist=[],sO=line.length-sig.length;for(let i=0;i<sig.length;i++)hist.push(line[i+sO]-sig[i]);return{line,signal:sig,hist}},
  bollinger(c,p=20,m=2){const sma=TA.sma(c,p),u=[],lo=[];for(let i=p-1;i<c.length;i++){const sl=c.slice(i-p+1,i+1),mn=sma[i-p+1],std=Math.sqrt(sl.reduce((a,v)=>a+(v-mn)**2,0)/p);u.push(mn+m*std);lo.push(mn-m*std)}return{sma,upper:u,lower:lo}},
  stochRSI(c,rP=14,sP=14,kP=3,dP=3){const rsi=TA.rsi(c,rP);if(rsi.length<sP)return{k:[],d:[]};const st=[];for(let i=sP-1;i<rsi.length;i++){const sl=rsi.slice(i-sP+1,i+1),mn=Math.min(...sl),mx=Math.max(...sl);st.push(mx===mn?50:((rsi[i]-mn)/(mx-mn))*100)}return{k:TA.sma(st,kP),d:TA.sma(TA.sma(st,kP),dP)}},
  fibonacci(h,l,c){const hi=Math.max(...h.slice(-50)),lo=Math.min(...l.slice(-50)),diff=hi-lo,price=c[c.length-1];const levels={0:hi,0.236:hi-diff*0.236,0.382:hi-diff*0.382,0.5:hi-diff*0.5,0.618:hi-diff*0.618,0.786:hi-diff*0.786,1:lo};const ext={1.272:hi+diff*0.272,1.618:hi+diff*0.618};const all=Object.values(levels);const sup=all.filter(v=>v<price).sort((a,b)=>b-a)[0]||lo;const res=all.filter(v=>v>price).sort((a,b)=>a-b)[0]||hi;const gp1=hi-diff*0.618,gp2=hi-diff*0.65;return{levels,extensions:ext,nearestSupport:sup,nearestResistance:res,inGoldenPocket:price>=gp1&&price<=gp2,high:hi,low:lo}},
  vwap(h,l,c,v){let cv=0,ct=0;const r=[];for(let i=0;i<c.length;i++){const tp=(h[i]+l[i]+c[i])/3;ct+=tp*v[i];cv+=v[i];r.push(cv>0?ct/cv:tp)}return r},
  adx(h,l,c,p=14){if(h.length<p+1)return{adx:[],diPlus:[],diMinus:[]};const dP=[],dM=[],tr=[];for(let i=1;i<h.length;i++){const u=h[i]-h[i-1],d=l[i-1]-l[i];dP.push(u>d&&u>0?u:0);dM.push(d>u&&d>0?d:0);tr.push(Math.max(h[i]-l[i],Math.abs(h[i]-c[i-1]),Math.abs(l[i]-c[i-1])))}const sTR=TA.ema(tr,p),sDMP=TA.ema(dP,p),sDMM=TA.ema(dM,p),len=Math.min(sTR.length,sDMP.length,sDMM.length),diP=[],diM=[],dx=[];for(let i=0;i<len;i++){const dp=sTR[i]>0?(sDMP[i]/sTR[i])*100:0,dm=sTR[i]>0?(sDMM[i]/sTR[i])*100:0;diP.push(dp);diM.push(dm);dx.push(dp+dm>0?Math.abs(dp-dm)/(dp+dm)*100:0)}return{adx:TA.ema(dx,p),diPlus:diP,diMinus:diM}},
  obv(c,v){const r=[0];for(let i=1;i<c.length;i++)r.push(c[i]>c[i-1]?r[i-1]+v[i]:c[i]<c[i-1]?r[i-1]-v[i]:r[i-1]);return r},
  volTrend(v,p=20){if(v.length<p)return'normal';const rec=v.slice(-5).reduce((a,b)=>a+b,0)/5,avg=v.slice(-p).reduce((a,b)=>a+b,0)/p;return rec>avg*1.5?'high':rec<avg*0.5?'low':'normal'}
};

// ═══ SENTIMENT ═══
let sentimentCache={value:50,label:'Neutral',updated:0};
async function getSentiment(){
  if(Date.now()-sentimentCache.updated<1800000&&sentimentCache.updated>0)return sentimentCache;
  try{const r=await fetch('https://api.alternative.me/fng/?limit=1');const d=await safeJSON(r);if(d.data&&d.data[0])sentimentCache={value:+d.data[0].value,label:d.data[0].value_classification,updated:Date.now()}}catch{}
  return sentimentCache;
}

// ═══ ANALYSIS ═══
const L=a=>a.length?a[a.length-1]:null;
const P=a=>a.length>1?a[a.length-2]:null;

async function analyze(candles){
  const c=candles.map(x=>x.close),h=candles.map(x=>x.high),l=candles.map(x=>x.low),v=candles.map(x=>x.volume);
  const ema9=TA.ema(c,9),ema21=TA.ema(c,21),ema50=TA.ema(c,50),rsi=TA.rsi(c),atr=TA.atr(h,l,c);
  const macd=TA.macd(c),bb=TA.bollinger(c),sr=TA.stochRSI(c),fib=TA.fibonacci(h,l,c);
  const vwap=TA.vwap(h,l,c,v),adx=TA.adx(h,l,c),obv=TA.obv(c,v);
  const volTrend=TA.volTrend(v),sentiment=await getSentiment();
  const adxVal=L(adx.adx),e9=L(ema9),e21=L(ema21),e50=L(ema50),r=L(rsi);
  const trendStrength=adxVal!==null?(adxVal>25?'strong':adxVal>20?'moderate':'weak'):'unknown';
  let condition='neutral';
  if(e9&&e21&&e50&&r!==null){
    const diff=((e9-e21)/e21)*100;
    if(Math.abs(diff)<0.3&&r>40&&r<60&&trendStrength==='weak')condition='sideways';
    else if(e9>e21&&e21>e50&&r>50)condition=trendStrength==='strong'?'strong_bullish':'bullish';
    else if(e9<e21&&e21<e50&&r<50)condition=trendStrength==='strong'?'strong_bearish':'bearish';
    else if(e9>e21)condition='mildly_bullish';
    else condition='mildly_bearish';
  }
  const obvSma=TA.sma(obv,20);
  return{price:L(c),condition,trendStrength,ema9:e9,ema21:e21,ema50:e50,rsi:r,prevRsi:P(rsi),atr:L(atr),macdLine:L(macd.line),macdSignal:L(macd.signal),macdHist:L(macd.hist),prevMacdHist:P(macd.hist),bbUpper:L(bb.upper),bbLower:L(bb.lower),bbSma:L(bb.sma),stochK:L(sr.k),stochD:L(sr.d),fib,vwap:L(vwap),adx:adxVal,diPlus:L(adx.diPlus),diMinus:L(adx.diMinus),obvTrend:L(obv)>L(obvSma)?'bullish':'bearish',volTrend,sentiment,support:fib.nearestSupport,resistance:fib.nearestResistance,inGoldenPocket:fib.inGoldenPocket,candles:candles.slice(-50)};
}

// ═══ CONFIDENCE SCORING ═══
function confidence(a,signal){
  if(signal==='hold')return 0;
  let s=0;const buy=signal==='buy';
  // EMA alignment (15)
  if(a.ema9&&a.ema21&&a.ema50){if(buy&&a.ema9>a.ema21&&a.ema21>a.ema50)s+=15;else if(!buy&&a.ema9<a.ema21&&a.ema21<a.ema50)s+=15;else if((buy&&a.ema9>a.ema21)||(!buy&&a.ema9<a.ema21))s+=7}
  // RSI (15)
  if(a.rsi!==null){if(buy&&a.rsi>35&&a.rsi<55)s+=15;else if(!buy&&a.rsi>55&&a.rsi<70)s+=15;else if(buy&&a.rsi<30)s+=12;else if(!buy&&a.rsi>70)s+=12}
  // MACD cross (15)
  if(a.macdHist!==null&&a.prevMacdHist!==null){if(buy&&a.macdHist>0&&a.prevMacdHist<=0)s+=15;else if(!buy&&a.macdHist<0&&a.prevMacdHist>=0)s+=15;else if((buy&&a.macdHist>0)||(!buy&&a.macdHist<0))s+=7}
  // Fibonacci (15)
  if(a.fib){if(buy&&a.inGoldenPocket)s+=15;else if(buy&&a.price<=a.support*1.01)s+=12;else if(!buy&&a.price>=a.resistance*0.99)s+=12}
  // Volume (10)
  if(a.volTrend==='high')s+=10;else if(a.volTrend==='normal')s+=5;
  // OBV (10)
  if((buy&&a.obvTrend==='bullish')||(!buy&&a.obvTrend==='bearish'))s+=10;
  // ADX trend strength (10)
  if(a.adx>25)s+=10;else if(a.adx>20)s+=5;
  // VWAP (5)
  if(a.vwap){if(buy&&a.price>a.vwap)s+=5;else if(!buy&&a.price<a.vwap)s+=5}
  // Sentiment (5)
  if(a.sentiment){if(buy&&a.sentiment.value<30)s+=5;else if(!buy&&a.sentiment.value>70)s+=5;else if(buy&&a.sentiment.value<45)s+=3;else if(!buy&&a.sentiment.value>55)s+=3}
  return Math.min(s,100);
}

// ═══ STRATEGIES ═══
const STRATS={
  ema_rsi(a){if(!a.ema9||!a.ema21||a.rsi===null)return'hold';if(a.condition==='sideways')return'hold';if(a.ema9>a.ema21&&a.rsi>40&&a.rsi<70&&(a.prevRsi===null||a.rsi>a.prevRsi))return'buy';if(a.ema9<a.ema21&&a.rsi<60&&a.rsi>30&&(a.prevRsi===null||a.rsi<a.prevRsi))return'sell';return'hold'},
  macd_bb(a){if(a.macdHist===null||a.prevMacdHist===null||!a.price)return'hold';if(a.macdHist>0&&a.prevMacdHist<=0&&a.price<a.bbLower*1.02&&a.rsi<45)return'buy';if(a.macdHist<0&&a.prevMacdHist>=0&&a.price>a.bbUpper*0.98&&a.rsi>55)return'sell';return'hold'},
  scalp_rsi(a){if(a.rsi===null||a.stochK===null)return'hold';if(a.rsi<35&&a.stochK<25&&a.stochK>a.stochD)return'buy';if(a.rsi>65&&a.stochK>75&&a.stochK<a.stochD)return'sell';return'hold'},
  trend(a){if(!a.ema50||!a.price||a.macdHist===null)return'hold';if(a.price>a.ema50&&a.macdHist>0&&a.prevMacdHist<=0&&a.rsi>45&&a.rsi<75)return'buy';if(a.price<a.ema50&&a.macdHist<0&&a.prevMacdHist>=0&&a.rsi>25&&a.rsi<55)return'sell';return'hold'},
  fib_vol(a){if(!a.fib||a.rsi===null)return'hold';if(a.inGoldenPocket&&a.rsi<45&&a.volTrend!=='low'&&a.obvTrend==='bullish')return'buy';if(a.price>=a.resistance*0.99&&a.rsi>60&&a.obvTrend==='bearish')return'sell';return'hold'},
  // Enhanced combined with confidence gate
  combined(a){
    const sigs=[STRATS.ema_rsi(a),STRATS.macd_bb(a),STRATS.scalp_rsi(a),STRATS.trend(a),STRATS.fib_vol(a)];
    const buys=sigs.filter(s=>s==='buy').length,sells=sigs.filter(s=>s==='sell').length;
    let signal='hold';
    if(buys>=2)signal='buy';if(sells>=2)signal='sell';
    // Confidence gate: only trade if confidence >= 55
    if(signal!=='hold'){const conf=confidence(a,signal);if(conf<55)signal='hold'}
    return signal;
  }
};

// ═══ BOT STATE ═══
const bot={
  running:false,mode:'paper',tradingType:'spot',strategy:'combined',
  symbols:['BTC-USDT'],intervalMs:60000,intervalId:null,
  riskPct:2,maxDrawdownPct:15,slATR:1.5,tpATR:3.0,trailingStop:true,trailATR:1.0,maxOpenTrades:3,leverage:5,
  paperUSD:10000,startBal:10000,peakBal:10000,
  openTrades:[],history:[],totalPnL:0,winCount:0,lossCount:0,
  lastAnalysis:{},log:[],cooldown:{},credentials:null,
};
function botLog(m){const e={time:new Date().toISOString(),msg:m};bot.log.push(e);if(bot.log.length>300)bot.log.shift();console.log('[BOT]',m)}

// ═══ FETCH CANDLES ═══
async function fetchKlines(sym,type='15min',limit=100){
  const end=Math.floor(Date.now()/1000),mins=type==='1min'?1:type==='5min'?5:type==='15min'?15:type==='1hour'?60:240;
  const start=end-limit*mins*60;
  const r=await fetch(`https://api.kucoin.com/api/v1/market/candles?type=${type}&symbol=${sym}&startAt=${start}&endAt=${end}`);
  const d=await safeJSON(r);if(d.code!=='200000'||!d.data)throw new Error('Candle fetch failed');
  return d.data.reverse().map(c=>({time:+c[0]*1000,open:+c[1],close:+c[2],high:+c[3],low:+c[4],volume:+c[5]}));
}

// ═══ TRADE EXECUTION ═══
function paperBuy(sym,price,usd,sl,tp,conf,type='spot'){
  const qty=usd/price,lev=type==='futures'?bot.leverage:1,margin=type==='futures'?usd/lev:usd;
  bot.paperUSD-=margin;
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'buy',type,leverage:lev,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,trailingSl:bot.trailingStop?sl:null,highSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`BUY ${sym} @$${price.toFixed(2)} | conf:${conf}% | SL:$${sl.toFixed(2)} TP:$${tp.toFixed(2)} | ${type}${lev>1?' '+lev+'x':''}`);return t;
}
function paperSell(sym,price,usd,sl,tp,conf){
  const qty=usd/price,margin=usd/bot.leverage;bot.paperUSD-=margin;
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'sell',type:'futures',leverage:bot.leverage,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,trailingSl:bot.trailingStop?sl:null,lowSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`SHORT ${sym} @$${price.toFixed(2)} | conf:${conf}% | SL:$${sl.toFixed(2)} TP:$${tp.toFixed(2)} | futures ${bot.leverage}x`);return t;
}
function closeTrade(t,price,reason){
  t.status='closed';t.exitPrice=price;t.closeTime=new Date().toISOString();t.reason=reason;
  const dir=t.side==='buy'?1:-1;const raw=(price-t.entryPrice)*t.qty*dir;
  t.pnl=t.type==='futures'?raw*t.leverage:raw;t.pnlPct=((t.exitPrice-t.entryPrice)/t.entryPrice*100*dir*(t.type==='futures'?t.leverage:1));
  bot.paperUSD+=t.margin+t.pnl;bot.totalPnL+=t.pnl;t.pnl>0?bot.winCount++:bot.lossCount++;
  bot.openTrades=bot.openTrades.filter(x=>x.id!==t.id);bot.history.push(t);if(bot.history.length>500)bot.history.shift();
  botLog(`CLOSE ${t.side} ${t.symbol} @$${price.toFixed(2)} | PnL:$${t.pnl.toFixed(2)} (${t.pnlPct.toFixed(1)}%) | ${reason}`);
}

// ═══ LIVE ORDERS ═══
async function liveOrder(side,sym,qty){
  if(!bot.credentials)throw new Error('No credentials');
  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep='/api/v1/orders',body={clientOid:crypto.randomUUID(),side,symbol:sym,type:'market',size:String(qty)};
  const r=await fetch('https://api.kucoin.com'+ep,{method:'POST',headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),body:JSON.stringify(body)});
  const d=await safeJSON(r);if(d.code!=='200000')throw new Error(d.msg||'Order failed');return d.data;
}

// ═══ BOT TICK ═══
async function tick(){
  try{
    for(const sym of bot.symbols){
      const candles=await fetchKlines(sym,'15min',100);
      const a=await analyze(candles);bot.lastAnalysis[sym]=a;
      const{price,atr}=a;if(!price||!atr)continue;

      // Check open trades
      for(const t of[...bot.openTrades]){
        if(t.symbol!==sym)continue;
        if(bot.trailingStop&&t.trailingSl!==null){
          if(t.side==='buy'){if(price>(t.highSince||t.entryPrice))t.highSince=price;const ns=t.highSince-atr*bot.trailATR;if(ns>t.trailingSl)t.trailingSl=ns;if(price<=t.trailingSl){closeTrade(t,price,'trailing_sl');continue}}
          else{if(price<(t.lowSince||t.entryPrice))t.lowSince=price;const ns=t.lowSince+atr*bot.trailATR;if(ns<t.trailingSl)t.trailingSl=ns;if(price>=t.trailingSl){closeTrade(t,price,'trailing_sl');continue}}
        }
        if(t.side==='buy'&&price<=t.sl){closeTrade(t,price,'stop_loss');continue}
        if(t.side==='sell'&&price>=t.sl){closeTrade(t,price,'stop_loss');continue}
        if(t.side==='buy'&&price>=t.tp){closeTrade(t,price,'take_profit');continue}
        if(t.side==='sell'&&price<=t.tp){closeTrade(t,price,'take_profit');continue}
      }

      // Drawdown check
      const bal=getCurBal();if(bal>bot.peakBal)bot.peakBal=bal;
      const dd=((bot.peakBal-bal)/bot.peakBal)*100;
      if(dd>=bot.maxDrawdownPct){botLog(`DRAWDOWN ${dd.toFixed(1)}% — paused`);continue}

      // Cooldown & limits
      if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<1800000)continue;
      if(bot.openTrades.length>=bot.maxOpenTrades)continue;
      if(bot.openTrades.some(t=>t.symbol===sym))continue;

      // Signal + confidence
      const strat=STRATS[bot.strategy]||STRATS.combined;
      const signal=strat(a);if(signal==='hold')continue;
      const conf=confidence(a,signal);
      if(conf<50){botLog(`${sym} ${signal} signal conf=${conf}% (too low, need 50+)`);continue}

      // Position sizing
      const riskUSD=bal*(bot.riskPct/100);const slDist=atr*bot.slATR;
      const posUSD=Math.min(riskUSD/(slDist/price),bal*0.25);
      if(posUSD<10)continue;
      const sl=signal==='buy'?price-slDist:price+slDist;
      const tp=signal==='buy'?price+atr*bot.tpATR:price-atr*bot.tpATR;

      // Execute
      if(bot.mode==='paper'){
        if(signal==='buy')paperBuy(sym,price,posUSD,sl,tp,conf,bot.tradingType);
        else if(signal==='sell'&&(bot.tradingType==='futures'||bot.tradingType==='combined'))paperSell(sym,price,posUSD,sl,tp,conf);
      }else{
        try{
          const qty=(posUSD/price).toFixed(6);
          await liveOrder(signal,sym,qty);
          bot.openTrades.push({id:crypto.randomUUID().slice(0,8),symbol:sym,side:signal,type:bot.tradingType,leverage:bot.tradingType==='futures'?bot.leverage:1,entryPrice:price,qty:posUSD/price,usdAmount:posUSD,margin:posUSD,sl,tp,confidence:conf,openTime:new Date().toISOString(),status:'open',highSince:price,trailingSl:bot.trailingStop?sl:null});
          botLog(`LIVE ${signal.toUpperCase()} ${sym} @$${price.toFixed(2)} conf=${conf}%`);
        }catch(e){botLog(`ORDER ERROR: ${e.message}`)}
      }
      bot.cooldown[sym]=Date.now();
    }
  }catch(e){botLog(`TICK ERROR: ${e.message}`)}
}

function getCurBal(){
  let b=bot.paperUSD;
  for(const t of bot.openTrades){const a=bot.lastAnalysis[t.symbol];if(!a){b+=t.margin;continue}const dir=t.side==='buy'?1:-1;b+=t.margin+(a.price-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)}
  return b;
}

// ═══ BACKTEST ═══
async function backtest(sym,strat,periods=500){
  const candles=await fetchKlines(sym,'15min',periods);if(candles.length<60)throw new Error('Not enough data');
  let bal=10000,peak=10000,maxDD=0,open=null;const trades=[];
  for(let i=55;i<candles.length;i++){
    const sl=candles.slice(0,i+1);const a=await analyze(sl);const{price,atr}=a;if(!price||!atr)continue;
    if(open){
      if(open.side==='buy'){if(price<=open.sl||price>=open.tp){const pnl=(price-open.entry)*open.qty;bal+=open.cost+pnl;trades.push({...open,exit:price,pnl,pnlPct:(pnl/open.cost)*100,reason:price<=open.sl?'sl':'tp',conf:open.conf});open=null}}
      else{if(price>=open.sl||price<=open.tp){const pnl=(open.entry-price)*open.qty;bal+=open.cost+pnl;trades.push({...open,exit:price,pnl,pnlPct:(pnl/open.cost)*100,reason:price>=open.sl?'sl':'tp',conf:open.conf});open=null}}
    }
    if(bal>peak)peak=bal;const dd=((peak-bal)/peak)*100;if(dd>maxDD)maxDD=dd;
    if(open)continue;
    const fn=STRATS[strat]||STRATS.combined;const sig=fn(a);if(sig==='hold')continue;
    const conf=confidence(a,sig);if(conf<45)continue;
    const rUSD=bal*0.02,slD=atr*1.5,cost=Math.min(rUSD/(slD/price),bal*0.25);if(cost<10)continue;
    const qty=cost/price,slP=sig==='buy'?price-slD:price+slD,tpP=sig==='buy'?price+atr*3:price-atr*3;
    bal-=cost;open={side:sig,symbol:sym,entry:price,qty,cost,sl:slP,tp:tpP,conf,openTime:candles[i].time};
  }
  if(open){const lp=candles[candles.length-1].close;const dir=open.side==='buy'?1:-1;const pnl=(lp-open.entry)*open.qty*dir;bal+=open.cost+pnl;trades.push({...open,exit:lp,pnl,pnlPct:(pnl/open.cost)*100,reason:'end',conf:open.conf})}
  const wins=trades.filter(t=>t.pnl>0),losses=trades.filter(t=>t.pnl<=0);
  const gp=wins.reduce((a,t)=>a+t.pnl,0),gl=Math.abs(losses.reduce((a,t)=>a+t.pnl,0));
  return{symbol:sym,strategy:strat,periods:candles.length,startBal:10000,endBal:Math.round(bal*100)/100,totalTrades:trades.length,wins:wins.length,losses:losses.length,winRate:trades.length?Math.round(wins.length/trades.length*10000)/100:0,profitFactor:gl>0?Math.round(gp/gl*100)/100:gp>0?999:0,avgWin:wins.length?Math.round(gp/wins.length*100)/100:0,avgLoss:losses.length?Math.round(gl/losses.length*100)/100:0,maxDrawdown:Math.round(maxDD*100)/100,avgConfidence:trades.length?Math.round(trades.reduce((a,t)=>a+(t.conf||0),0)/trades.length):0,trades:trades.slice(-50)};
}

// ═══ ROUTES ═══
app.post('/api/bot/connect',authMW,(req,res)=>{const{apiKey,apiSecret,passphrase}=req.body||{};if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All fields required'});bot.credentials={apiKey,apiSecret,passphrase};botLog('Exchange connected');res.json({success:true})});

app.post('/api/bot/start',authMW,(req,res)=>{
  if(bot.running)return res.json({success:true,msg:'Already running'});
  bot.running=true;botLog(`STARTED — ${bot.mode} | ${bot.strategy} | ${bot.symbols.join(',')} | ${bot.tradingType}`);
  tick();bot.intervalId=setInterval(tick,bot.intervalMs);res.json({success:true});
});
app.post('/api/bot/stop',authMW,(req,res)=>{bot.running=false;if(bot.intervalId){clearInterval(bot.intervalId);bot.intervalId=null}botLog('STOPPED');res.json({success:true})});

app.get('/api/bot/status',authMW,(req,res)=>{
  const bal=getCurBal(),dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0,tot=bot.winCount+bot.lossCount;
  res.json({running:bot.running,mode:bot.mode,strategy:bot.strategy,tradingType:bot.tradingType,symbols:bot.symbols,leverage:bot.leverage,
    balance:Math.round(bal*100)/100,startBal:bot.startBal,paperUSD:Math.round(bot.paperUSD*100)/100,
    totalPnL:Math.round(bot.totalPnL*100)/100,totalPnLPct:bot.startBal>0?Math.round((bal-bot.startBal)/bot.startBal*10000)/100:0,
    winCount:bot.winCount,lossCount:bot.lossCount,winRate:tot>0?Math.round(bot.winCount/tot*10000)/100:0,
    drawdown:Math.round(dd*100)/100,maxDrawdownPct:bot.maxDrawdownPct,
    openTrades:bot.openTrades.map(t=>{const cp=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;const dir=t.side==='buy'?1:-1;return{...t,currentPrice:cp,unrealizedPnl:Math.round((cp-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)*100)/100}}),
    recentHistory:bot.history.slice(-30).reverse(),analysis:bot.lastAnalysis,log:bot.log.slice(-50).reverse(),
    hasCredentials:!!bot.credentials,sentiment:sentimentCache,
    settings:{riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,intervalMs:bot.intervalMs}
  });
});

app.post('/api/bot/settings',authMW,(req,res)=>{
  const s=req.body||{};
  if(s.mode==='live'&&bot.mode!=='live')botLog('⚠ SWITCHED TO LIVE MODE');
  if(s.mode&&['paper','live'].includes(s.mode))bot.mode=s.mode;
  if(s.tradingType&&['spot','futures','combined'].includes(s.tradingType))bot.tradingType=s.tradingType;
  if(s.strategy&&STRATS[s.strategy])bot.strategy=s.strategy;
  if(s.symbols&&Array.isArray(s.symbols))bot.symbols=s.symbols;
  if(s.riskPct!==undefined)bot.riskPct=Math.max(0.5,Math.min(5,+s.riskPct));
  if(s.maxDrawdownPct!==undefined)bot.maxDrawdownPct=Math.max(5,Math.min(30,+s.maxDrawdownPct));
  if(s.slATR!==undefined)bot.slATR=Math.max(0.5,Math.min(5,+s.slATR));
  if(s.tpATR!==undefined)bot.tpATR=Math.max(1,Math.min(10,+s.tpATR));
  if(s.trailingStop!==undefined)bot.trailingStop=!!s.trailingStop;
  if(s.trailATR!==undefined)bot.trailATR=Math.max(0.3,Math.min(3,+s.trailATR));
  if(s.maxOpenTrades!==undefined)bot.maxOpenTrades=Math.max(1,Math.min(10,+s.maxOpenTrades));
  if(s.leverage!==undefined)bot.leverage=Math.max(1,Math.min(20,+s.leverage));
  if(s.intervalMs!==undefined)bot.intervalMs=Math.max(30000,Math.min(300000,+s.intervalMs));
  if(s.resetPaper){bot.paperUSD=s.paperBalance||10000;bot.startBal=bot.paperUSD;bot.peakBal=bot.paperUSD;bot.openTrades=[];bot.history=[];bot.totalPnL=0;bot.winCount=0;bot.lossCount=0;botLog('Paper reset')}
  if(s.intervalMs&&bot.running&&bot.intervalId){clearInterval(bot.intervalId);bot.intervalId=setInterval(tick,bot.intervalMs)}
  botLog('Settings updated');res.json({success:true});
});

app.get('/api/bot/analysis/:sym',authMW,async(req,res)=>{
  try{const candles=await fetchKlines(req.params.sym,'15min',100);const a=await analyze(candles);const sigs={};for(const[n,fn]of Object.entries(STRATS))sigs[n]={signal:fn(a),confidence:confidence(a,fn(a))};res.json({success:true,analysis:a,signals:sigs})}catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/bot/backtest',authMW,async(req,res)=>{
  try{const{symbol='BTC-USDT',strategy='combined',periods=500}=req.body||{};const r=await backtest(symbol,strategy,periods);res.json({success:true,result:r})}catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/bot/close/:id',authMW,(req,res)=>{
  const t=bot.openTrades.find(x=>x.id===req.params.id);if(!t)return res.status(404).json({error:'Not found'});
  closeTrade(t,bot.lastAnalysis[t.symbol]?.price||t.entryPrice,'manual');res.json({success:true});
});

// Real wallet balance
app.get('/api/bot/wallet',authMW,async(req,res)=>{
  if(!bot.credentials)return res.json({connected:false,error:'No exchange connected'});
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const ep='/api/v1/accounts?type=trade';
    const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
    const d=await safeJSON(r);
    if(d.code!=='200000')return res.json({connected:false,error:d.msg||'API error'});
    const balances={};
    for(const a of d.data){const v=parseFloat(a.available);if(v>0)balances[a.currency]=(balances[a.currency]||0)+v}
    let totalUSD=0;
    try{
      const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);
      const pm={USDT:1,USDC:1};if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;
      for(const[c,a]of Object.entries(balances))totalUSD+=(pm[c]||0)*a;
    }catch{}
    res.json({connected:true,balances,totalUSD:Math.round(totalUSD*100)/100,assets:Object.keys(balances).length});
  }catch(e){res.json({connected:false,error:e.message})}
});

// AI Advisor - sends analysis to Anthropic API
app.post('/api/bot/ai-advice',authMW,async(req,res)=>{
  const{symbol='BTC-USDT',anthropicKey}=req.body||{};
  if(!anthropicKey)return res.status(400).json({error:'Anthropic API key required'});
  try{
    const candles=await fetchKlines(symbol,'15min',100);const a=await analyze(candles);
    const sigs={};for(const[n,fn]of Object.entries(STRATS))sigs[n]={signal:fn(a),confidence:confidence(a,fn(a))};
    const prompt=`You are an expert crypto trader with 30+ years experience. Analyze this market data for ${symbol} and give a clear trading recommendation. Be specific about entry, stop loss, take profit levels. Also rate your confidence 1-10.

CURRENT DATA:
Price: $${a.price.toFixed(2)}
Market Condition: ${a.condition} (trend strength: ${a.trendStrength})
RSI(14): ${a.rsi?.toFixed(1)} | MACD Histogram: ${a.macdHist?.toFixed(4)}
EMA9: $${a.ema9?.toFixed(2)} | EMA21: $${a.ema21?.toFixed(2)} | EMA50: $${a.ema50?.toFixed(2)}
Bollinger: Upper $${a.bbUpper?.toFixed(2)} | Lower $${a.bbLower?.toFixed(2)}
ATR: $${a.atr?.toFixed(2)} | ADX: ${a.adx?.toFixed(1)}
Fibonacci: Support $${a.support?.toFixed(2)} | Resistance $${a.resistance?.toFixed(2)} | In Golden Pocket: ${a.inGoldenPocket}
VWAP: $${a.vwap?.toFixed(2)} | OBV Trend: ${a.obvTrend} | Volume: ${a.volTrend}
Fear & Greed: ${a.sentiment.value} (${a.sentiment.label})

STRATEGY SIGNALS: ${JSON.stringify(sigs)}

Give your analysis in this format:
RECOMMENDATION: [BUY/SELL/WAIT]
CONFIDENCE: [1-10]
ENTRY: [price]
STOP LOSS: [price]
TAKE PROFIT: [price]
REASONING: [2-3 sentences]
RISK: [what could go wrong]`;

    const r=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json','x-api-key':anthropicKey,'anthropic-version':'2023-06-01'},body:JSON.stringify({model:'claude-sonnet-4-20250514',max_tokens:500,messages:[{role:'user',content:prompt}]})});
    const d=await safeJSON(r);
    const text=d.content?.map(x=>x.text||'').join('\n')||'No response';
    res.json({success:true,advice:text,analysis:a,signals:sigs});
  }catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/kucoin/balance',async(req,res)=>{
  const{apiKey,apiSecret,passphrase}=req.body||{};if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All fields required'});
  try{const ep='/api/v1/accounts?type=trade';const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});const d=await safeJSON(r);
  if(d.code!=='200000')return res.status(400).json({error:d.code==='400003'?'Invalid API key':d.code==='400004'?'Invalid passphrase':d.msg||'Error'});
  const bals={};for(const a of d.data){const v=parseFloat(a.available);if(v>0)bals[a.currency]=(bals[a.currency]||0)+v}
  let total=0;try{const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);const pm={USDT:1,USDC:1};if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;for(const[c,a]of Object.entries(bals))total+=(pm[c]||0)*a}catch{}
  res.json({success:true,balances:bals,totalUSD:total})}catch(e){res.status(500).json({error:e.message})}
});

app.get('/api/prices',async(req,res)=>{
  try{const r=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const d=await safeJSON(r);if(d.code!=='200000')return res.status(502).json({error:'Price feed error'});
  const prices={},W=['BTC-USDT','ETH-USDT','SOL-USDT','BNB-USDT','XRP-USDT','ADA-USDT','DOGE-USDT','LINK-USDT'];
  for(const t of d.data.ticker)if(W.includes(t.symbol))prices[t.symbol]={price:+t.last,change:+t.changeRate*100,vol:+t.volValue};
  res.json({success:true,prices})}catch(e){res.status(500).json({error:e.message})}
});

app.get('/health',(_,res)=>res.json({status:'ok'}));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(_,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const PORT=process.env.PORT||3000;
app.listen(PORT,'0.0.0.0',()=>console.log(`TradeMatrix Pro v3 → http://localhost:${PORT}`));

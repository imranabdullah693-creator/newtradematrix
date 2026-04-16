const express=require('express'),crypto=require('crypto'),path=require('path'),fs=require('fs');
const app=express();app.use(express.json());

// ═══ AUTH ═══
const AUTH_FILE=path.join(__dirname,'.auth.json');
let AUTH={email:null,password:null,tokens:[]};
try{if(fs.existsSync(AUTH_FILE))AUTH=JSON.parse(fs.readFileSync(AUTH_FILE,'utf8'))}catch{}
function saveAuth(){try{fs.writeFileSync(AUTH_FILE,JSON.stringify(AUTH))}catch{}}
function hashPw(p){return crypto.createHash('sha256').update(p+'tmx-salt').digest('hex')}
function genToken(){const t=crypto.randomBytes(32).toString('hex');AUTH.tokens.push(t);if(AUTH.tokens.length>10)AUTH.tokens=AUTH.tokens.slice(-10);saveAuth();return t}
function mw(req,res,next){if(!AUTH.password)return next();const t=(req.headers.authorization||'').replace('Bearer ','');if(!t||!AUTH.tokens.includes(t))return res.status(401).json({error:'unauthorized'});next()}
app.post('/api/auth/setup',(req,res)=>{if(AUTH.password)return res.status(400).json({error:'Account exists. Please login.'});const{email,password}=req.body||{};if(!email||!email.includes('@'))return res.status(400).json({error:'Valid email required'});if(!password||password.length<4)return res.status(400).json({error:'Password 4+ chars'});AUTH.email=email;AUTH.password=hashPw(password);res.json({success:true,token:genToken()})});
app.post('/api/auth/login',(req,res)=>{if(!AUTH.password)return res.json({needsSetup:true});const{email,password}=req.body||{};if(!email||!password)return res.status(400).json({error:'Email and password required'});if(email!==AUTH.email)return res.status(401).json({error:'Email not found'});if(hashPw(password)!==AUTH.password)return res.status(401).json({error:'Wrong password'});res.json({success:true,token:genToken()})});
app.get('/api/auth/check',(req,res)=>{if(!AUTH.password)return res.json({needsSetup:true});const t=(req.headers.authorization||'').replace('Bearer ','');res.json({authenticated:!!t&&AUTH.tokens.includes(t),needsSetup:false})});

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
  fibonacci(h,l,c){const hi=Math.max(...h.slice(-50)),lo=Math.min(...l.slice(-50)),diff=hi-lo,price=c[c.length-1];const levels={0:hi,0.236:hi-diff*0.236,0.382:hi-diff*0.382,0.5:hi-diff*0.5,0.618:hi-diff*0.618,0.786:hi-diff*0.786,1:lo};const all=Object.values(levels);const sup=all.filter(v=>v<price).sort((a,b)=>b-a)[0]||lo;const res=all.filter(v=>v>price).sort((a,b)=>a-b)[0]||hi;const gp1=hi-diff*0.618,gp2=hi-diff*0.65;return{levels,nearestSupport:sup,nearestResistance:res,inGoldenPocket:price>=gp1&&price<=gp2,high:hi,low:lo}},
  vwap(h,l,c,v){let cv=0,ct=0;const r=[];for(let i=0;i<c.length;i++){const tp=(h[i]+l[i]+c[i])/3;ct+=tp*v[i];cv+=v[i];r.push(cv>0?ct/cv:tp)}return r},
  adx(h,l,c,p=14){if(h.length<p+1)return{adx:[],diPlus:[],diMinus:[]};const dP=[],dM=[],tr=[];for(let i=1;i<h.length;i++){const u=h[i]-h[i-1],d=l[i-1]-l[i];dP.push(u>d&&u>0?u:0);dM.push(d>u&&d>0?d:0);tr.push(Math.max(h[i]-l[i],Math.abs(h[i]-c[i-1]),Math.abs(l[i]-c[i-1])))}const sTR=TA.ema(tr,p),sDMP=TA.ema(dP,p),sDMM=TA.ema(dM,p),len=Math.min(sTR.length,sDMP.length,sDMM.length),diP=[],diM=[],dx=[];for(let i=0;i<len;i++){const dp=sTR[i]>0?(sDMP[i]/sTR[i])*100:0,dm=sTR[i]>0?(sDMM[i]/sTR[i])*100:0;diP.push(dp);diM.push(dm);dx.push(dp+dm>0?Math.abs(dp-dm)/(dp+dm)*100:0)}return{adx:TA.ema(dx,p),diPlus:diP,diMinus:diM}},
  obv(c,v){const r=[0];for(let i=1;i<c.length;i++)r.push(c[i]>c[i-1]?r[i-1]+v[i]:c[i]<c[i-1]?r[i-1]-v[i]:r[i-1]);return r},
  volTrend(v,p=20){if(v.length<p)return'normal';const rec=v.slice(-5).reduce((a,b)=>a+b,0)/5,avg=v.slice(-p).reduce((a,b)=>a+b,0)/p;return rec>avg*1.5?'high':rec<avg*0.5?'low':'normal'}
};

// ═══ NEWS + SENTIMENT ═══
let sentimentCache={value:50,label:'Neutral',updated:0};
let newsCache={articles:[],sentiment:{},overall:{score:0,bias:'neutral'},updated:0};
const BULL=['surge','rally','bullish','breakout','soar','pump','ath','gain','rise','jump','adoption','approval','etf','institutional','upgrade','partnership','launch','record','optimistic','growth','recovery','accumulate'];
const BEAR=['crash','dump','bearish','plunge','drop','fall','hack','ban','fraud','scam','regulation','crackdown','lawsuit','fine','risk','warning','decline','panic','correction','collapse','bankrupt','shutdown'];
const COINS_MAP={BTC:'bitcoin',ETH:'ethereum',SOL:'solana',XRP:'ripple',ADA:'cardano',DOGE:'dogecoin',DOT:'polkadot',LINK:'chainlink',AVAX:'avalanche',MATIC:'polygon',SHIB:'shiba',UNI:'uniswap',ATOM:'cosmos',LTC:'litecoin',FIL:'filecoin',NEAR:'near',APT:'aptos',ARB:'arbitrum',OP:'optimism',SUI:'sui',SEI:'sei',INJ:'injective',FET:'fetch',RENDER:'render',PEPE:'pepe',WIF:'dogwifhat',BONK:'bonk',FLOKI:'floki',BNB:'binance',TIA:'celestia'};
function scoreText(t){if(!t)return 0;const lo=t.toLowerCase();let s=0;for(const w of BULL)if(lo.includes(w))s++;for(const w of BEAR)if(lo.includes(w))s--;return s}

async function getSentiment(){
  if(Date.now()-sentimentCache.updated<1800000&&sentimentCache.updated>0)return sentimentCache;
  try{const r=await fetch('https://api.alternative.me/fng/?limit=7');const d=await safeJSON(r);if(d.data&&d.data[0])sentimentCache={value:+d.data[0].value,label:d.data[0].value_classification,history:d.data.map(x=>({v:+x.value,l:x.value_classification})),updated:Date.now()}}catch{}
  return sentimentCache;
}
async function fetchNews(){
  if(Date.now()-newsCache.updated<300000&&newsCache.updated>0)return newsCache;
  try{
    let articles=[];const seen=new Set();
    const MB=['rate cut','dovish','stimulus','qe','inflation cool','soft landing','peace','ceasefire','trade deal','dollar weak','dxy down','fed pause','liquidity','risk on','recovery','growth','surplus','jobs added','strong earnings','bull market','rally','tech boom','oil drop','de-escalation','agreement'];
    const MR=['rate hike','hawkish','taper','qt','recession','inflation hot','hard landing','war','attack','missile','invasion','nuclear','sanction','tariff','dollar strong','dxy up','fed tighten','risk off','default','debt ceiling','shutdown','embargo','crisis','collapse','crash','layoff','unemployment','bankruptcy','downgrade','bear market','pandemic','outbreak','conflict','escalation','coup','protest','unrest'];

    function classify(title,body,source,url,time){
      if(!title||seen.has(title))return null;seen.add(title);
      const txt=(title+' '+(body||'')).toLowerCase();
      let s=scoreText(title+' '+(body||'').slice(0,300)),ms=0;
      for(const w of MB)if(txt.includes(w))ms+=2;
      for(const w of MR)if(txt.includes(w))ms-=2;
      const worldKeys=['fed','federal reserve','central bank','interest rate','inflation','gdp','economy','war','iran','israel','china','russia','ukraine','trump','congress','tariff','sanction','opec','oil','gold','dollar','treasury','bond','imf','nato','military','attack','election','debt','employment','jobs','cpi','fomc','brics','middle east','gaza','taiwan'];
      const isWorld=worldKeys.some(w=>txt.includes(w));
      s+=ms;
      return{title,source,url,time,body:(body||'').slice(0,200),score:s,macroScore:ms,type:isWorld||ms!==0?'world':'crypto'};
    }

    // Multiple news sources — fallback if any blocked
    const fetchWithTimeout=async(url,ms=8000)=>{const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),ms);try{const r=await fetch(url,{signal:ctrl.signal});clearTimeout(to);return r}catch(e){clearTimeout(to);throw e}};

    // Source 1: CryptoCompare (often blocked in some regions)
    const cats=['','&categories=regulation,fiat,exchange','&categories=mining,trading,technology','&categories=blockchain,business,government'];
    for(const cat of cats){
      try{
        const r=await fetchWithTimeout('https://min-api.cryptocompare.com/data/v2/news/?lang=EN&sortOrder=latest'+cat);
        const d=await safeJSON(r);
        if(d.Data)for(const a of d.Data.slice(0,15)){const x=classify(a.title,a.body,a.source,a.url,a.published_on*1000);if(x)articles.push(x)}
      }catch(e){console.log('CryptoCompare err:',e.message)}
    }

    // Source 2: CoinGecko news (global, rarely blocked)
    try{
      const r=await fetchWithTimeout('https://api.coingecko.com/api/v3/news');
      const d=await safeJSON(r);
      if(d.data)for(const a of d.data.slice(0,25)){
        const time=a.updated_at?a.updated_at*1000:Date.now();
        const x=classify(a.title,a.description||'',a.news_site||'CoinGecko',a.url,time);
        if(x)articles.push(x);
      }
    }catch(e){console.log('CoinGecko news err:',e.message)}

    // Source 3: CoinPaprika events (global)
    try{
      const r=await fetchWithTimeout('https://api.coinpaprika.com/v1/coins/btc-bitcoin/events');
      const d=await safeJSON(r);
      if(Array.isArray(d))for(const a of d.slice(0,10)){
        const time=a.date?new Date(a.date).getTime():Date.now();
        const x=classify(a.name,a.description||'','CoinPaprika',a.link||'#',time);
        if(x)articles.push(x);
      }
    }catch(e){console.log('CoinPaprika err:',e.message)}

    if(!articles.length){console.log('No news articles fetched');return newsCache}
    articles.sort((a,b)=>b.time-a.time);

    const cs={};
    for(const[sym,name]of Object.entries(COINS_MAP)){const rel=articles.filter(a=>(a.title+' '+a.body).toLowerCase().includes(name)||a.title.toLowerCase().includes(sym.toLowerCase()));if(rel.length)cs[sym]={score:Math.round(rel.reduce((s,a)=>s+a.score,0)/rel.length*100)/100,n:rel.length,bias:rel.reduce((s,a)=>s+a.score,0)/rel.length>0.5?'bullish':rel.reduce((s,a)=>s+a.score,0)/rel.length<-0.5?'bearish':'neutral'}}

    const worldA=articles.filter(a=>a.type==='world'),cryptoA=articles.filter(a=>a.type==='crypto');
    const as=articles.reduce((s,a)=>s+a.score,0)/Math.max(articles.length,1);
    const wa=worldA.length?worldA.reduce((s,a)=>s+a.score,0)/worldA.length:0;
    newsCache={articles,sentiment:cs,overall:{score:Math.round(as*100)/100,bias:as>0.3?'bullish':as<-0.3?'bearish':'neutral',macroScore:Math.round(wa*100)/100,macroBias:wa>0.3?'bullish':wa<-0.3?'bearish':'neutral',worldCount:worldA.length,cryptoCount:cryptoA.length},updated:Date.now()};
    console.log('News:',articles.length,'articles',worldA.length,'world',cryptoA.length,'crypto');
  }catch(e){console.log('News err:',e.message)}
  return newsCache;
}

// ═══ ANALYSIS ═══
const L=a=>a.length?a[a.length-1]:null,P=a=>a.length>1?a[a.length-2]:null;
async function analyze(candles,sym='BTC-USDT'){
  const c=candles.map(x=>x.close),h=candles.map(x=>x.high),l=candles.map(x=>x.low),v=candles.map(x=>x.volume);
  const ema9=TA.ema(c,9),ema21=TA.ema(c,21),ema50=TA.ema(c,50),rsi=TA.rsi(c),atr=TA.atr(h,l,c);
  const macd=TA.macd(c),bb=TA.bollinger(c),sr=TA.stochRSI(c),fib=TA.fibonacci(h,l,c);
  const vwap=TA.vwap(h,l,c,v),adx=TA.adx(h,l,c),obv=TA.obv(c,v);
  const volTrend=TA.volTrend(v),sentiment=sentimentCache,news=newsCache;
  const coin=sym.split('-')[0],coinNews=(news.sentiment||{})[coin]||{score:0,n:0,bias:'neutral'};
  const adxVal=L(adx.adx),e9=L(ema9),e21=L(ema21),e50=L(ema50),r=L(rsi);
  const ts=adxVal!==null?(adxVal>25?'strong':adxVal>20?'moderate':'weak'):'unknown';
  let cond='neutral';
  if(e9&&e21&&e50&&r!==null){const diff=((e9-e21)/e21)*100;if(Math.abs(diff)<0.3&&r>40&&r<60&&ts==='weak')cond='sideways';else if(e9>e21&&e21>e50&&r>50)cond=ts==='strong'?'strong_bullish':'bullish';else if(e9<e21&&e21<e50&&r<50)cond=ts==='strong'?'strong_bearish':'bearish';else if(e9>e21)cond='mildly_bullish';else cond='mildly_bearish'}
  const obvSma=TA.sma(obv,20);
  return{price:L(c),condition:cond,trendStrength:ts,ema9:e9,ema21:e21,ema50:e50,rsi:r,prevRsi:P(rsi),atr:L(atr),macdLine:L(macd.line),macdSignal:L(macd.signal),macdHist:L(macd.hist),prevMacdHist:P(macd.hist),bbUpper:L(bb.upper),bbLower:L(bb.lower),bbSma:L(bb.sma),stochK:L(sr.k),stochD:L(sr.d),fib,vwap:L(vwap),adx:adxVal,diPlus:L(adx.diPlus),diMinus:L(adx.diMinus),obvTrend:L(obv)>L(obvSma)?'bullish':'bearish',volTrend,sentiment,news:{coin:coinNews,overall:news.overall},support:fib.nearestSupport,resistance:fib.nearestResistance,inGoldenPocket:fib.inGoldenPocket}
}

// ═══════════════════════════════════════════════════════════════════════════
// TRADING COUNCIL — 7 SPECIALIST AGENTS (BALANCED BUY/SELL)
// Each agent focuses on different indicators and votes buy/sell/hold
// Sell thresholds now match buy thresholds for balance
// ═══════════════════════════════════════════════════════════════════════════
const AGENTS={
  // Agents think in CONTEXT and can genuinely vote HOLD when truly uncertain.
  // Hold = "I don't see a clear edge here, don't count on me"

  trend_master(a){
    if(!a.ema9||!a.ema21)return{vote:'hold',confidence:0,reason:'Missing EMA data'};
    const bull=a.ema9>a.ema21, aligned=a.ema50&&((bull&&a.ema21>a.ema50)||(!bull&&a.ema21<a.ema50));
    const strong=a.adx&&a.adx>25, weak=a.adx&&a.adx<15;
    const adx=a.adx?a.adx.toFixed(0):'?';
    const emaGap=Math.abs((a.ema9-a.ema21)/a.ema21)*100;
    if(weak&&emaGap<0.2)return{vote:'hold',confidence:0,reason:'EMAs virtually flat, no trend (ADX:'+adx+', gap:'+emaGap.toFixed(2)+'%). Waiting for direction.'};
    if(bull&&aligned&&strong)return{vote:'buy',confidence:90,reason:'Textbook uptrend: EMAs stacked 9>21>50 with strong momentum (ADX:'+adx+'). Follow the trend.'};
    if(bull&&aligned)return{vote:'buy',confidence:65,reason:'Uptrend intact (ADX:'+adx+'), EMAs aligned bullish but moderate strength.'};
    if(!bull&&aligned&&strong)return{vote:'sell',confidence:90,reason:'Strong downtrend: EMAs stacked 9<21<50 (ADX:'+adx+'). Short into strength.'};
    if(!bull&&aligned)return{vote:'sell',confidence:65,reason:'Downtrend intact (ADX:'+adx+'), EMAs aligned bearish.'};
    return{vote:'hold',confidence:0,reason:'EMAs not aligned with longer-term (ADX:'+adx+'). Unclear direction, waiting.'};
  },

  momentum_hunter(a){
    if(a.rsi===null)return{vote:'hold',confidence:0,reason:'No RSI data'};
    const trend=a.condition||'neutral';const r=a.rsi;
    if(trend.includes('bullish')){
      if(r<35)return{vote:'buy',confidence:90,reason:'RSI '+r.toFixed(0)+' — oversold dip in uptrend. Prime buy-the-dip.'};
      if(r<50)return{vote:'buy',confidence:70,reason:'RSI '+r.toFixed(0)+' — healthy pullback in uptrend.'};
      if(r>75)return{vote:'sell',confidence:65,reason:'RSI '+r.toFixed(0)+' — extremely overbought even for uptrend. Short-term pullback likely.'};
      if(r>65)return{vote:'hold',confidence:0,reason:'RSI '+r.toFixed(0)+' in uptrend — extended but trends stay overbought. No clear edge.'};
      return{vote:'buy',confidence:50,reason:'RSI '+r.toFixed(0)+' in uptrend — normal range.'};
    }
    if(trend.includes('bearish')){
      if(r>65)return{vote:'sell',confidence:90,reason:'RSI '+r.toFixed(0)+' — overbought bounce in downtrend. Prime sell-the-rip.'};
      if(r>50)return{vote:'sell',confidence:70,reason:'RSI '+r.toFixed(0)+' — bear rally losing steam.'};
      if(r<25)return{vote:'buy',confidence:55,reason:'RSI '+r.toFixed(0)+' — extremely oversold, bounce possible but trend is down.'};
      if(r<35)return{vote:'hold',confidence:0,reason:'RSI '+r.toFixed(0)+' in downtrend — oversold but downtrends stay oversold. No edge.'};
      return{vote:'sell',confidence:50,reason:'RSI '+r.toFixed(0)+' in downtrend — weak momentum.'};
    }
    // Sideways/unclear — only extremes
    if(r<30)return{vote:'buy',confidence:75,reason:'RSI '+r.toFixed(0)+' in range — oversold, mean reversion.'};
    if(r>70)return{vote:'sell',confidence:75,reason:'RSI '+r.toFixed(0)+' in range — overbought, mean reversion.'};
    return{vote:'hold',confidence:0,reason:'RSI '+r.toFixed(0)+' in sideways market — no edge in the middle.'};
  },

  macd_specialist(a){
    if(a.macdHist===null)return{vote:'hold',confidence:0,reason:'No MACD data'};
    const trend=a.condition||'neutral';const h=a.macdHist;
    const growing=a.prevMacdHist!==null&&Math.abs(h)>Math.abs(a.prevMacdHist);
    const crossUp=a.prevMacdHist!==null&&h>0&&a.prevMacdHist<=0;
    const crossDn=a.prevMacdHist!==null&&h<0&&a.prevMacdHist>=0;
    if(crossUp)return{vote:'buy',confidence:85,reason:'MACD bullish crossover — fresh momentum shift up.'};
    if(crossDn)return{vote:'sell',confidence:85,reason:'MACD bearish crossover — fresh momentum shift down.'};
    if(trend.includes('bullish')){
      if(h>0&&growing)return{vote:'buy',confidence:75,reason:'MACD positive and accelerating in uptrend — bullish momentum strong.'};
      if(h<0&&!growing)return{vote:'buy',confidence:65,reason:'MACD negative but recovering in uptrend — dip with turning momentum.'};
      if(h>0)return{vote:'buy',confidence:50,reason:'MACD positive in uptrend — bullish but slowing.'};
      return{vote:'hold',confidence:0,reason:'MACD negative and falling in uptrend — pullback deepening, wait.'};
    }
    if(trend.includes('bearish')){
      if(h<0&&growing)return{vote:'sell',confidence:75,reason:'MACD negative and accelerating in downtrend — selling intensifying.'};
      if(h>0&&!growing)return{vote:'sell',confidence:65,reason:'MACD positive but fading in downtrend — bounce dying.'};
      if(h<0)return{vote:'sell',confidence:50,reason:'MACD negative in downtrend — bears in control.'};
      return{vote:'hold',confidence:0,reason:'MACD positive and growing in downtrend — possible reversal starting, need more confirmation.'};
    }
    if(Math.abs(h)<0.001)return{vote:'hold',confidence:0,reason:'MACD effectively zero — no momentum signal.'};
    if(h>0)return{vote:'buy',confidence:growing?55:40,reason:'MACD positive ('+h.toFixed(4)+').'};
    return{vote:'sell',confidence:growing?55:40,reason:'MACD negative ('+h.toFixed(4)+').'};
  },

  fibonacci_analyst(a){
    if(!a.fib||!a.price)return{vote:'hold',confidence:0,reason:'No fib data'};
    const trend=a.condition||'neutral';
    const distSup=Math.abs(a.price-a.support)/a.price*100;
    const distRes=Math.abs(a.resistance-a.price)/a.price*100;
    if(a.inGoldenPocket)return{vote:'buy',confidence:85,reason:'Golden pocket (0.618 fib) — highest probability buy zone.'};
    if(trend.includes('bullish')){
      if(distSup<1)return{vote:'buy',confidence:80,reason:'At fib support $'+a.support.toFixed(2)+' in uptrend — buy the dip.'};
      if(distRes<0.5)return{vote:'hold',confidence:0,reason:'At fib resistance in uptrend — could break up or reject. Wait for confirmation.'};
      return{vote:'buy',confidence:45,reason:'Mid-range in uptrend, no strong fib signal.'};
    }
    if(trend.includes('bearish')){
      if(distRes<1)return{vote:'sell',confidence:80,reason:'At fib resistance $'+a.resistance.toFixed(2)+' in downtrend — sell the rip.'};
      if(distSup<0.5)return{vote:'hold',confidence:0,reason:'At fib support in downtrend — could break down or bounce. Wait.'};
      return{vote:'sell',confidence:45,reason:'Mid-range in downtrend, no strong fib signal.'};
    }
    if(distSup<0.5)return{vote:'buy',confidence:65,reason:'At fib support $'+a.support.toFixed(2)+'.'};
    if(distRes<0.5)return{vote:'sell',confidence:65,reason:'At fib resistance $'+a.resistance.toFixed(2)+'.'};
    return{vote:'hold',confidence:0,reason:'Mid-range between fib levels, no edge.'};
  },

  volume_expert(a){
    if(!a.price)return{vote:'hold',confidence:0,reason:'No volume data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];
    const obvBull=a.obvTrend==='bullish',obvBear=a.obvTrend==='bearish';
    if(trend.includes('bullish')){
      if(obvBull){score+=30;reasons.push('Money flowing IN during uptrend — institutional support.')}
      else if(obvBear){score-=5;reasons.push('Warning: uptrend but money leaving — rally weak.')}
    }else if(trend.includes('bearish')){
      if(obvBear){score-=30;reasons.push('Money flowing OUT during downtrend — institutional selling.')}
      else if(obvBull){score+=5;reasons.push('Interesting: downtrend but accumulation happening.')}
    }else{
      if(obvBull)score+=20;else if(obvBear)score-=20;
    }
    if(a.vwap){if(a.price>a.vwap*1.002){score+=12;reasons.push('Above VWAP — buyers winning intraday.')}else if(a.price<a.vwap*0.998){score-=12;reasons.push('Below VWAP — sellers winning intraday.')}}
    if(a.volTrend==='high')reasons.push('Volume elevated.');
    if(Math.abs(score)<10)return{vote:'hold',confidence:0,reason:'Volume signals mixed/weak. '+reasons.join(' ')};
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  bollinger_trader(a){
    if(!a.bbUpper||!a.bbLower||!a.price)return{vote:'hold',confidence:0,reason:'No BB data'};
    const trend=a.condition||'neutral';
    const pos=(a.price-a.bbLower)/(a.bbUpper-a.bbLower);const pct=Math.round(pos*100);
    if(trend.includes('bullish')){
      if(pos<0.25)return{vote:'buy',confidence:85,reason:'BB '+pct+'% in uptrend — lower band = dynamic support, buy the dip.'};
      if(pos>0.9)return{vote:'hold',confidence:0,reason:'BB '+pct+'% in uptrend — walking upper band is normal. No fresh signal.'};
      return{vote:'buy',confidence:50,reason:'BB '+pct+'% in uptrend — normal.'};
    }
    if(trend.includes('bearish')){
      if(pos>0.75)return{vote:'sell',confidence:85,reason:'BB '+pct+'% in downtrend — upper band = dynamic resistance, sell the rip.'};
      if(pos<0.1)return{vote:'hold',confidence:0,reason:'BB '+pct+'% in downtrend — walking lower band. No fresh signal.'};
      return{vote:'sell',confidence:50,reason:'BB '+pct+'% in downtrend — normal.'};
    }
    if(pos<0.15)return{vote:'buy',confidence:75,reason:'BB '+pct+'% in range — oversold mean reversion.'};
    if(pos>0.85)return{vote:'sell',confidence:75,reason:'BB '+pct+'% in range — overbought mean reversion.'};
    return{vote:'hold',confidence:0,reason:'BB '+pct+'% in range — middle of bands, no edge.'};
  },

  sentiment_analyst(a){
    if(!a.sentiment)return{vote:'hold',confidence:0,reason:'No sentiment data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];const fg=a.sentiment.value;
    if(trend.includes('bullish')){
      if(fg<30){score+=35;reasons.push('Extreme fear ('+fg+') in uptrend — contrarian gold.')}
      else if(fg<45){score+=20;reasons.push('Fear ('+fg+') in uptrend — early buyers benefit.')}
      else if(fg>75){score-=15;reasons.push('Extreme greed ('+fg+') in uptrend — tighten stops.')}
    }else if(trend.includes('bearish')){
      if(fg>70){score-=35;reasons.push('Greed ('+fg+') in downtrend — complacency before more pain.')}
      else if(fg>55){score-=20;reasons.push('Optimism ('+fg+') in downtrend — contrarian sell.')}
      else if(fg<25){score+=15;reasons.push('Capitulation fear ('+fg+') — potential bottom.')}
    }else{
      if(fg<25){score+=25;reasons.push('Extreme fear '+fg+' — contrarian buy.')}
      else if(fg>75){score-=25;reasons.push('Extreme greed '+fg+' — contrarian sell.')}
    }
    if(a.news){const cn=a.news.coin;if(cn&&cn.bias==='bullish'){score+=12;reasons.push('Coin news bullish.')}if(cn&&cn.bias==='bearish'){score-=12;reasons.push('Coin news bearish.')}
    const ov=a.news.overall;if(ov&&ov.macroBias==='bullish'){score+=8;reasons.push('Macro positive.')}if(ov&&ov.macroBias==='bearish'){score-=8;reasons.push('Macro negative.')}}
    if(Math.abs(score)<10)return{vote:'hold',confidence:0,reason:'Sentiment neutral (F&G:'+fg+'). No conviction.'};
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  quant_ai(a){
    if(!a.price||!a.ema21||!a.bbUpper||!a.bbLower)return{vote:'hold',confidence:0,reason:'No data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];
    const bbMid=a.bbSma||(a.bbUpper+a.bbLower)/2;const bbStd=(a.bbUpper-a.bbLower)/4;
    const zScore=bbStd>0?(a.price-bbMid)/bbStd:0;const roc=((a.price-a.ema21)/a.ema21)*100;
    reasons.push('Z:'+zScore.toFixed(2)+' ROC:'+roc.toFixed(2)+'%');
    if(trend.includes('bullish')){
      if(zScore<-1){score+=30;reasons.push('Undervalued in uptrend — high prob buy.')}
      else if(zScore>1.5){score-=10;reasons.push('Extended even for uptrend.')}
    }else if(trend.includes('bearish')){
      if(zScore>1){score-=30;reasons.push('Overvalued in downtrend — high prob short.')}
      else if(zScore<-1.5){score+=10;reasons.push('Deeply depressed — bounce possible.')}
    }else{
      if(zScore<-1)score+=20;else if(zScore>1)score-=20;
      if(roc<-2)score+=12;else if(roc>2)score-=12;
    }
    if(a.rsi&&a.rsi>70&&roc<0){score-=10;reasons.push('Bearish divergence.')}
    if(a.rsi&&a.rsi<30&&roc>0){score+=10;reasons.push('Bullish divergence.')}
    if(Math.abs(score)<10)return{vote:'hold',confidence:0,reason:'Stats show no edge. '+reasons.join(' ')};
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  atr_volatility(a){
    if(!a.atr||!a.price)return{vote:'hold',confidence:0,reason:'No ATR data'};
    const trend=a.condition||'neutral';const atrPct=(a.atr/a.price)*100;
    let score=0,reasons=['ATR '+atrPct.toFixed(2)+'%'];
    const bbWidth=a.bbUpper&&a.bbLower?((a.bbUpper-a.bbLower)/(a.bbSma||a.price))*100:5;
    if(atrPct<1.5&&bbWidth<4){
      if(trend.includes('bullish')){score+=30;reasons.push('Squeeze + uptrend = breakout up.')}
      else if(trend.includes('bearish')){score-=30;reasons.push('Squeeze + downtrend = breakdown.')}
      else{return{vote:'hold',confidence:0,reason:'Volatility squeeze detected but no trend. Wait for direction.'}}
    }else if(atrPct>3){
      const bp=a.bbUpper?(a.price-a.bbLower)/(a.bbUpper-a.bbLower):0.5;
      if(bp>0.8){score-=25;reasons.push('High vol extended up — pullback likely.')}
      else if(bp<0.2){score+=25;reasons.push('High vol depressed — bounce likely.')}
      else{return{vote:'hold',confidence:0,reason:'High volatility, price mid-range — choppy, stay out.'}}
    }else{
      if(trend.includes('bullish')){score+=12;reasons.push('Normal vol + uptrend.')}
      else if(trend.includes('bearish')){score-=12;reasons.push('Normal vol + downtrend.')}
      else return{vote:'hold',confidence:0,reason:'Normal vol but no trend. No edge.'};
    }
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  }
};


// ═══ AGENT TIERS — harder to manipulate = higher weight ═══
const AGENT_TIERS={
  // TIER 1 (weight 3x) — Hardest to manipulate
  // Multi-TF trends, math-based levels, external sentiment — whales can't fake these
  trend_master:    {tier:1,weight:3,why:'Multi-TF EMA alignment is nearly impossible to fake'},
  fibonacci_analyst:{tier:1,weight:3,why:'Math-based price levels from historical structure'},
  atr_volatility:  {tier:1,weight:3,why:'Volatility patterns are structural, not easily spoofed'},
  sentiment_analyst:{tier:1,weight:3,why:'External data (Fear&Greed, world news) outside exchange control'},

  // TIER 2 (weight 2x) — Moderate manipulation risk
  // Lagging indicators derived from price — some buffer against fakes
  macd_specialist:  {tier:2,weight:2,why:'Lagging EMA derivative — harder to fake than raw price'},
  bollinger_trader: {tier:2,weight:2,why:'Statistical bands with 20-period lookback resist short spikes'},
  quant_ai:         {tier:2,weight:2,why:'Z-score and ROC use statistical baselines'},

  // TIER 3 (weight 1x) — Easiest to manipulate
  // Short-term momentum and volume — whales can move these easily
  momentum_hunter:  {tier:3,weight:1,why:'RSI/StochRSI react to short-term pumps and dumps'},
  volume_expert:    {tier:3,weight:1,why:'Volume is the most manipulated metric (wash trading, spoofing)'}
};

// ═══ COUNCIL VOTE (tiered weighted + multi-timeframe) ═══
function councilVote(a,requiredAgree=4){
  const votes={};
  for(const[name,fn]of Object.entries(AGENTS)){
    votes[name]=fn(a);
    const ti=AGENT_TIERS[name]||{tier:2,weight:2};
    votes[name].tier=ti.tier;
    votes[name].weight=ti.weight;
    votes[name].tierWhy=ti.why;
  }

  const buys=Object.entries(votes).filter(([_,v])=>v.vote==='buy');
  const sells=Object.entries(votes).filter(([_,v])=>v.vote==='sell');

  // Weighted confidence: Tier 1 votes count 3x, Tier 2 = 2x, Tier 3 = 1x
  const buyWeightedConf=buys.length?Math.round(buys.reduce((s,[_,v])=>s+v.confidence*v.weight,0)/buys.reduce((s,[_,v])=>s+v.weight,0)):0;
  const sellWeightedConf=sells.length?Math.round(sells.reduce((s,[_,v])=>s+v.confidence*v.weight,0)/sells.reduce((s,[_,v])=>s+v.weight,0)):0;

  // Weighted vote score (max possible = 3+3+3+3+2+2+2+1+1 = 20)
  const buyScore=buys.reduce((s,[_,v])=>s+v.weight,0);
  const sellScore=sells.reduce((s,[_,v])=>s+v.weight,0);
  const maxScore=Object.values(AGENT_TIERS).reduce((s,t)=>s+t.weight,0); // 20

  // Tier 1 agreement count
  const buyT1=buys.filter(([_,v])=>v.tier===1).length;
  const sellT1=sells.filter(([_,v])=>v.tier===1).length;

  // Higher timeframe bias adjustments
  const htf=a.htf||{bias:'neutral'};
  let htfNote='';
  let buyBonus=0,sellBonus=0;

  if(htf.bias==='strong_bullish'){buyBonus=3;sellBonus=-3;htfNote='4H+1H bullish → buys boosted, sells penalized'}
  else if(htf.bias==='bullish'){buyBonus=2;htfNote='4H bullish → buys boosted'}
  else if(htf.bias==='strong_bearish'){sellBonus=3;buyBonus=-3;htfNote='4H+1H bearish → sells boosted, buys penalized'}
  else if(htf.bias==='bearish'){sellBonus=2;htfNote='4H bearish → sells boosted'}
  else if(htf.bias==='mildly_bullish'){buyBonus=1;htfNote='1H mildly bullish'}
  else if(htf.bias==='mildly_bearish'){sellBonus=1;htfNote='1H mildly bearish'}

  const adjBuyScore=buyScore+buyBonus;
  const adjSellScore=sellScore+sellBonus;

  // SIMPLIFIED GATES:
  // Gate 1: Weighted score threshold (lower = more trades)
  const weightThreshold=Math.max(5,Math.floor(requiredAgree*1.5)); // e.g., 4 agents = need 8 pts
  // Gate 2: At least 1 Tier 1 agent must agree (anti-manipulation)
  const t1Required=1;

  let decision='hold',conf=0,agreeing=0;

  // Primary: weighted score meets threshold + at least 1 T1 agrees
  const buyMet=adjBuyScore>=weightThreshold&&buyT1>=t1Required;
  const sellMet=adjSellScore>=weightThreshold&&sellT1>=t1Required;

  if(buyMet&&sellMet){
    if(adjSellScore>adjBuyScore||(adjSellScore===adjBuyScore&&sellWeightedConf>=buyWeightedConf)){decision='sell';conf=sellWeightedConf;agreeing=sells.length}
    else{decision='buy';conf=buyWeightedConf;agreeing=buys.length}
  }else if(buyMet){decision='buy';conf=buyWeightedConf;agreeing=buys.length}
  else if(sellMet){decision='sell';conf=sellWeightedConf;agreeing=sells.length}

  // Bonus for strong agreement
  if(agreeing>=8)conf=Math.min(conf+20,100);
  else if(agreeing>=7)conf=Math.min(conf+15,100);
  else if(agreeing>=6)conf=Math.min(conf+10,100);
  else if(agreeing>=5)conf=Math.min(conf+5,100);

  // Block reason logging
  let blockReason='';
  if(decision==='hold'){
    if((buys.length>=3||sells.length>=3)&&buyT1<t1Required&&sellT1<t1Required)blockReason=`Blocked: no Tier 1 agent agrees (anti-manipulation)`;
    else if(adjBuyScore>=4||adjSellScore>=4)blockReason=`Hold: buy ${adjBuyScore}pts / sell ${adjSellScore}pts (need ${weightThreshold})`;
  }

  return{decision,confidence:conf,agreeing,total:Object.keys(AGENTS).length,votes,
    buyCount:buys.length,sellCount:sells.length,
    buyScore:adjBuyScore,sellScore:adjSellScore,maxScore,weightThreshold,
    buyT1,sellT1,t1Required,
    htf:htf.bias,htfNote,h4:htf.h4||null,h1:htf.h1||null,
    blockReason};
}

// ═══ BOT STATE ═══
const ALL_SYMBOLS=['BTC-USDT','ETH-USDT','SOL-USDT','XRP-USDT','ADA-USDT','DOGE-USDT','LINK-USDT','AVAX-USDT','DOT-USDT','MATIC-USDT','SHIB-USDT','UNI-USDT','ATOM-USDT','LTC-USDT','FIL-USDT','NEAR-USDT','APT-USDT','ARB-USDT','OP-USDT','SUI-USDT','SEI-USDT','INJ-USDT','FET-USDT','RENDER-USDT','PEPE-USDT','WIF-USDT','BONK-USDT','FLOKI-USDT','TIA-USDT','BNB-USDT'];
const SETTINGS_FILE=path.join(__dirname,'.bot-settings.json');
const STATE_FILE=path.join(__dirname,'.bot-state.json');
const bot={
  running:false,mode:'paper',tradingType:'combined',
  symbols:ALL_SYMBOLS,intervalMs:45000,intervalId:null,
  requiredAgents:4,
  riskPct:2,maxDrawdownPct:15,slATR:1.5,tpATR:3.0,trailingStop:true,trailATR:1.0,maxOpenTrades:10,leverage:5,smallBalanceMode:'auto',
  paperUSD:10000,startBal:10000,peakBal:10000,
  openTrades:[],history:[],totalPnL:0,winCount:0,lossCount:0,
  lastAnalysis:{},lastCouncil:{},log:[],cooldown:{},credentials:null
};

// Load saved settings on startup
function loadSettings(){
  try{if(fs.existsSync(SETTINGS_FILE)){const s=JSON.parse(fs.readFileSync(SETTINGS_FILE,'utf8'));
    if(s.mode)bot.mode=s.mode;if(s.tradingType)bot.tradingType=s.tradingType;
    if(s.symbols)bot.symbols=s.symbols;if(s.intervalMs)bot.intervalMs=s.intervalMs;
    if(s.requiredAgents)bot.requiredAgents=s.requiredAgents;
    if(s.riskPct)bot.riskPct=s.riskPct;if(s.maxDrawdownPct)bot.maxDrawdownPct=s.maxDrawdownPct;
    if(s.slATR)bot.slATR=s.slATR;if(s.tpATR)bot.tpATR=s.tpATR;
    if(s.trailingStop!==undefined)bot.trailingStop=s.trailingStop;if(s.trailATR)bot.trailATR=s.trailATR;
    if(s.maxOpenTrades)bot.maxOpenTrades=s.maxOpenTrades;if(s.leverage)bot.leverage=s.leverage;
    if(s.smallBalanceMode)bot.smallBalanceMode=s.smallBalanceMode;
    if(s.credentials)bot.credentials=s.credentials;
    console.log('✅ Settings loaded: mode='+bot.mode+' type='+bot.tradingType+' agents='+bot.requiredAgents+' creds='+(bot.credentials?'yes':'no'));
  }else{console.log('No settings file found, using defaults')}}catch(e){console.log('Settings load err:',e.message)}
  try{if(fs.existsSync(STATE_FILE)){const s=JSON.parse(fs.readFileSync(STATE_FILE,'utf8'));
    if(s.paperUSD!==undefined)bot.paperUSD=s.paperUSD;if(s.startBal)bot.startBal=s.startBal;
    if(s.peakBal)bot.peakBal=s.peakBal;if(s.totalPnL!==undefined)bot.totalPnL=s.totalPnL;
    if(s.winCount!==undefined)bot.winCount=s.winCount;if(s.lossCount!==undefined)bot.lossCount=s.lossCount;
    if(s.history)bot.history=s.history;if(s.openTrades)bot.openTrades=s.openTrades;
    console.log('✅ State loaded: balance=$'+bot.paperUSD+' trades='+bot.history.length+' open='+bot.openTrades.length);
  }else{console.log('No state file found')}}catch(e){console.log('State load err:',e.message)}
}
function saveSettings(){
  try{const data=JSON.stringify({mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents,riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,credentials:bot.credentials});
  fs.writeFileSync(SETTINGS_FILE,data);console.log('Settings saved: mode='+bot.mode)}catch(e){console.log('Save err:',e.message)}
}
function saveState(){
  try{fs.writeFileSync(STATE_FILE,JSON.stringify({paperUSD:bot.paperUSD,startBal:bot.startBal,peakBal:bot.peakBal,totalPnL:bot.totalPnL,winCount:bot.winCount,lossCount:bot.lossCount,history:bot.history.slice(-200),openTrades:bot.openTrades}))}catch(e){console.log('State save err:',e.message)}
}
loadSettings();
// Auto-save BOTH settings and state every 30s (was 60s)
setInterval(()=>{saveSettings();saveState()},30000);
// News refreshes independently of bot state - every 5 min
setInterval(()=>{fetchNews().catch(e=>console.log('News refresh err:',e.message))},300000);
// Also fetch on startup after 5 seconds
setTimeout(()=>{fetchNews().catch(e=>console.log('Initial news err:',e.message));getSentiment().catch(e=>console.log('Initial sentiment err:',e.message))},5000);

function botLog(m){const e={time:new Date().toISOString(),msg:m};bot.log.push(e);if(bot.log.length>500)bot.log.shift();console.log('[BOT]',m)}

// ═══ FETCH CANDLES ═══
async function fetchKlines(sym,type='15min',limit=100){
  const end=Math.floor(Date.now()/1000),mins={'1min':1,'5min':5,'15min':15,'1hour':60,'4hour':240}[type]||15;
  const r=await fetch(`https://api.kucoin.com/api/v1/market/candles?type=${type}&symbol=${sym}&startAt=${end-limit*mins*60}&endAt=${end}`);
  const d=await safeJSON(r);if(d.code!=='200000'||!d.data)throw new Error('Candle fetch failed for '+sym);
  return d.data.reverse().map(c=>({time:+c[0]*1000,open:+c[1],close:+c[2],high:+c[3],low:+c[4],volume:+c[5]}));
}

// ═══ TRADE EXECUTION ═══
function paperBuy(sym,price,usd,sl,tp,conf,council,type='spot',autoLev=1){
  const qty=usd/price,lev=autoLev>1?autoLev:1,margin=lev>1?usd/lev:usd;
  bot.paperUSD-=margin;
  const slPct=((Math.abs(price-sl)/price)*100).toFixed(2);
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'buy',type:lev>1?'futures':'spot',leverage:lev,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,agreeing:council.agreeing,trailingSl:bot.trailingStop?sl:null,highSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`BUY ${sym} @$${price.toFixed(2)} | size:$${usd.toFixed(2)} | lev:${lev}x | SL:${slPct}% ($${sl.toFixed(2)}) | TP:$${tp.toFixed(2)} | ${council.agreeing}/${council.total} agents | conf:${conf}%`);return t;
}
function paperSell(sym,price,usd,sl,tp,conf,council,autoLev=1){
  const lev=autoLev>1?autoLev:bot.leverage;
  const qty=usd/price,margin=usd/lev;bot.paperUSD-=margin;
  const slPct=((Math.abs(sl-price)/price)*100).toFixed(2);
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'sell',type:'futures',leverage:lev,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,agreeing:council.agreeing,trailingSl:bot.trailingStop?sl:null,lowSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`SHORT ${sym} @$${price.toFixed(2)} | size:$${usd.toFixed(2)} | lev:${lev}x | SL:${slPct}% ($${sl.toFixed(2)}) | TP:$${tp.toFixed(2)} | ${council.agreeing}/${council.total} agents | conf:${conf}%`);return t;
}
async function closeTrade(t,price,reason){
  t.status='closed';t.exitPrice=price;t.closeTime=new Date().toISOString();t.reason=reason;

  // If this is a LIVE futures trade, close the position on exchange
  if(t.isLive&&t.type==='futures'){
    try{
      await futuresClosePosition(t.symbol,t.side,t.qty);
      botLog(`Closed futures position on KuCoin: ${t.symbol}`);
    }catch(e){botLog(`Failed to close futures position: ${e.message}`)}
  }else if(t.isLive&&t.type==='spot'&&t.side==='buy'){
    // For spot, need to sell the position
    try{
      await liveOrder('sell',t.symbol,t.usdAmount,price);
      botLog(`Sold spot position on KuCoin: ${t.symbol}`);
    }catch(e){botLog(`Failed to sell spot: ${e.message}`)}
  }

  const dir=t.side==='buy'?1:-1;const raw=(price-t.entryPrice)*t.qty*dir;
  t.pnl=t.type==='futures'?raw*t.leverage:raw;
  t.pnlPct=((t.exitPrice-t.entryPrice)/t.entryPrice*100*dir*(t.type==='futures'?t.leverage:1));
  if(!t.isLive)bot.paperUSD+=t.margin+t.pnl;
  bot.totalPnL+=t.pnl;t.pnl>0?bot.winCount++:bot.lossCount++;
  bot.openTrades=bot.openTrades.filter(x=>x.id!==t.id);bot.history.push(t);if(bot.history.length>500)bot.history.shift();
  botLog(`CLOSE ${t.side} ${t.symbol} @$${price.toFixed(4)} | size:$${(t.usdAmount||0).toFixed(2)} | lev:${t.leverage||1}x | PnL:${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)} (${t.pnlPct.toFixed(1)}%) | ${reason}`);saveState();
}

// Symbol info cache (increments, minimums from KuCoin) — SPOT
let symbolInfoCache={data:{},updated:0};
async function getSymbolInfo(sym){
  if(Date.now()-symbolInfoCache.updated<3600000&&symbolInfoCache.data[sym])return symbolInfoCache.data[sym];
  try{
    const r=await fetch('https://api.kucoin.com/api/v2/symbols');
    const d=await safeJSON(r);
    if(d.code==='200000'&&d.data){
      const info={};
      for(const s of d.data){
        info[s.symbol]={baseIncrement:+s.baseIncrement,quoteIncrement:+s.quoteIncrement,baseMinSize:+s.baseMinSize,quoteMinSize:+s.quoteMinSize,priceIncrement:+s.priceIncrement};
      }
      symbolInfoCache={data:info,updated:Date.now()};
      console.log('Spot symbol info cached:',Object.keys(info).length,'symbols');
    }
  }catch(e){console.log('Spot symbol info err:',e.message)}
  return symbolInfoCache.data[sym]||{baseIncrement:0.001,baseMinSize:0.001,quoteMinSize:1};
}

// FUTURES symbol info cache (different endpoint)
let futuresInfoCache={data:{},symbolMap:{},updated:0};
async function getFuturesInfo(spotSym){
  if(Date.now()-futuresInfoCache.updated<3600000&&Object.keys(futuresInfoCache.data).length)return futuresInfoCache.data[futuresInfoCache.symbolMap[spotSym]];
  try{
    const r=await fetch('https://api-futures.kucoin.com/api/v1/contracts/active');
    const d=await safeJSON(r);
    if(d.code==='200000'&&d.data){
      const info={};const symbolMap={};
      for(const c of d.data){
        // Build map: spot symbol "BTC-USDT" → futures contract "XBTUSDTM"
        const base=c.baseCurrency==='XBT'?'BTC':c.baseCurrency;
        const quote=c.quoteCurrency;
        const spotSymbol=base+'-'+quote;
        symbolMap[spotSymbol]=c.symbol;
        info[c.symbol]={
          contract:c.symbol,
          multiplier:+c.multiplier,    // value of 1 contract in base currency
          lotSize:+c.lotSize,          // minimum contracts per order
          tickSize:+c.tickSize,        // price increment
          maxLeverage:+c.maxLeverage,
          isInverse:c.isInverse,       // inverse vs linear
          markPrice:+c.markPrice
        };
      }
      futuresInfoCache={data:info,symbolMap,updated:Date.now()};
      console.log('Futures contracts cached:',Object.keys(info).length,'contracts');
    }
  }catch(e){console.log('Futures info err:',e.message)}
  const contract=futuresInfoCache.symbolMap[spotSym];
  return contract?futuresInfoCache.data[contract]:null;
}

function roundToIncrement(qty,increment){
  if(!increment||increment===0)return qty;
  return Math.floor(qty/increment)*increment;
}

// SPOT market order
async function liveOrder(side,sym,usdAmount,price){
  if(!bot.credentials)throw new Error('No credentials');
  const info=await getSymbolInfo(sym);
  let qty=usdAmount/price;
  qty=roundToIncrement(qty,info.baseIncrement);
  if(qty<info.baseMinSize)throw new Error(`qty ${qty} < min ${info.baseMinSize}`);
  if(qty*price<info.quoteMinSize)throw new Error(`value $${(qty*price).toFixed(2)} < min $${info.quoteMinSize}`);
  const qtyStr=qty.toFixed(Math.max(0,-Math.floor(Math.log10(info.baseIncrement||0.001))));
  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep='/api/v1/orders',body={clientOid:crypto.randomUUID(),side,symbol:sym,type:'market',size:qtyStr};
  const r=await fetch('https://api.kucoin.com'+ep,{method:'POST',headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),body:JSON.stringify(body)});
  const d=await safeJSON(r);
  if(d.code!=='200000')throw new Error(d.msg||'Order failed');
  return{...d.data,qty,price};
}

// FUTURES market order (with leverage, supports both long and short)
async function futuresOrder(side,spotSym,usdAmount,price,leverage){
  if(!bot.credentials)throw new Error('No credentials');
  const info=await getFuturesInfo(spotSym);
  if(!info)throw new Error(`No futures contract for ${spotSym}`);

  // Calculate contracts. Linear contracts: size = (usdAmount × leverage) / (price × multiplier)
  const contracts=Math.floor((usdAmount*leverage)/(price*info.multiplier));
  if(contracts<info.lotSize)throw new Error(`contracts ${contracts} < min lot ${info.lotSize}`);

  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep='/api/v1/orders';
  const body={
    clientOid:crypto.randomUUID(),
    side,  // 'buy' or 'sell'
    symbol:info.contract,
    type:'market',
    size:contracts,
    leverage:String(leverage)
  };
  const r=await fetch('https://api-futures.kucoin.com'+ep,{
    method:'POST',
    headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),
    body:JSON.stringify(body)
  });
  const d=await safeJSON(r);
  if(d.code!=='200000')throw new Error('Futures: '+(d.msg||'Order failed'));
  return{orderId:d.data.orderId,qty:contracts*info.multiplier,price,contracts};
}

// Close futures position (opposite side)
async function futuresClosePosition(spotSym,side,size){
  if(!bot.credentials)throw new Error('No credentials');
  const info=await getFuturesInfo(spotSym);
  if(!info)throw new Error(`No futures contract for ${spotSym}`);
  const oppositeSide=side==='buy'?'sell':'buy';
  const contracts=Math.floor(size/info.multiplier);
  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep='/api/v1/orders';
  const body={
    clientOid:crypto.randomUUID(),
    side:oppositeSide,
    symbol:info.contract,
    type:'market',
    size:contracts,
    reduceOnly:true  // only reduce position, don't open opposite
  };
  const r=await fetch('https://api-futures.kucoin.com'+ep,{method:'POST',headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),body:JSON.stringify(body)});
  const d=await safeJSON(r);
  if(d.code!=='200000')throw new Error('Futures close: '+(d.msg||'Failed'));
  return d.data;
}

// ═══ MULTI-TIMEFRAME ANALYSIS ═══
async function multiTimeframeAnalysis(sym){
  // Fetch 15m first (required), then try higher TFs (optional)
  const c15=await fetchKlines(sym,'15min',100);
  const a15=await analyze(c15,sym);

  // Higher timeframes are OPTIONAL — don't let them block trading
  let htfBias='neutral',h4Data=null,h1Data=null;
  try{
    await new Promise(r=>setTimeout(r,500)); // small delay to avoid rate limit
    const c1h=await fetchKlines(sym,'1hour',60);
    h1Data=await analyze(c1h,sym);
  }catch(e){/* 1h failed — ok, use 15m only */}

  try{
    await new Promise(r=>setTimeout(r,500));
    const c4h=await fetchKlines(sym,'4hour',50);
    h4Data=await analyze(c4h,sym);
  }catch(e){/* 4h failed — ok */}

  // Determine bias from whatever TFs we got
  if(h4Data&&h1Data){
    if(h4Data.condition.includes('bullish')&&h1Data.condition.includes('bullish'))htfBias='strong_bullish';
    else if(h4Data.condition.includes('bearish')&&h1Data.condition.includes('bearish'))htfBias='strong_bearish';
    else if(h4Data.condition.includes('bullish'))htfBias='bullish';
    else if(h4Data.condition.includes('bearish'))htfBias='bearish';
    else if(h1Data.condition.includes('bullish'))htfBias='mildly_bullish';
    else if(h1Data.condition.includes('bearish'))htfBias='mildly_bearish';
  }else if(h1Data){
    if(h1Data.condition.includes('bullish'))htfBias='mildly_bullish';
    else if(h1Data.condition.includes('bearish'))htfBias='mildly_bearish';
  }
  // Even without higher TFs, the 15m analysis + agents still work

  a15.htf={
    bias:htfBias,
    h4:h4Data?{condition:h4Data.condition,rsi:h4Data.rsi,ema9:h4Data.ema9,ema21:h4Data.ema21,ema50:h4Data.ema50,macdHist:h4Data.macdHist,atr:h4Data.atr}:null,
    h1:h1Data?{condition:h1Data.condition,rsi:h1Data.rsi,ema9:h1Data.ema9,ema21:h1Data.ema21,ema50:h1Data.ema50,macdHist:h1Data.macdHist,atr:h1Data.atr}:null
  };
  return a15;
}

// ═══ BOT TICK ═══
let tickIndex=0;
let tickCount=0;
async function tick(){
  tickCount++;
  try{
    fetchNews().catch(()=>{});
    getSentiment().catch(()=>{});
    // In live mode, refresh real balance before trading decisions
    if(bot.mode==='live'&&bot.credentials){try{await fetchLiveBalance()}catch(e){botLog('Balance fetch err: '+e.message)}}

    const batchSize=5;
    const batch=[];
    for(let i=0;i<batchSize&&i<bot.symbols.length;i++){
      batch.push(bot.symbols[(tickIndex+i)%bot.symbols.length]);
    }
    tickIndex=(tickIndex+batchSize)%bot.symbols.length;
    botLog(`Scanning: ${batch.map(s=>s.replace('-USDT','')).join(', ')} (batch ${Math.ceil(tickIndex/batchSize)}/${Math.ceil(bot.symbols.length/batchSize)})`);

    for(const sym of batch){
      try{
        const a=await multiTimeframeAnalysis(sym);
        bot.lastAnalysis[sym]=a;
        const{price,atr}=a;if(!price||!atr)continue;

        // Check open trades (check ALL open trades, not just this batch)
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

        // Drawdown
        const bal=getCurBal();if(bal>bot.peakBal)bot.peakBal=bal;
        const dd=((bot.peakBal-bal)/bot.peakBal)*100;
        const coin=sym.replace('-USDT','');
        if(dd>=bot.maxDrawdownPct){botLog(`${coin} SKIP: drawdown ${dd.toFixed(1)}% >= max ${bot.maxDrawdownPct}%`);continue}

        // Limits — reduced cooldown to 5 min
        if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<300000){continue} // cooldown — don't spam log
        if(bot.openTrades.length>=bot.maxOpenTrades){botLog(`${coin} SKIP: max open trades ${bot.openTrades.length}/${bot.maxOpenTrades}`);continue}
        if(bot.openTrades.filter(t=>t.symbol===sym).length>=2){botLog(`${coin} SKIP: already 2 open trades for this coin`);continue}

        // ═══ COUNCIL VOTE ═══
        const council=councilVote(a,bot.requiredAgents);
        bot.lastCouncil[sym]=council;

        // Always log the result so user can see bot is working
        if(council.decision!=='hold'){
          botLog(`${coin} → ${council.decision.toUpperCase()} | ${council.buyCount}buy(${council.buyScore||0}pts)/${council.sellCount}sell(${council.sellScore||0}pts) | conf:${council.confidence}% | HTF:${council.htf||'?'}`);
        }else if(council.blockReason){
          botLog(`${coin} ${council.blockReason}`);
        }else if(Math.max(council.buyScore||0,council.sellScore||0)>=4){
          // Log when there's a notable signal building
          botLog(`${coin} ${council.buyCount}b(${council.buyScore||0}pts)/${council.sellCount}s(${council.sellScore||0}pts) T1:${council.buyT1||0}b/${council.sellT1||0}s — need ${council.weightThreshold||8}pts`);
        }

        if(council.decision==='hold')continue;
        if(council.confidence<40){botLog(`${coin} ${council.decision} conf too low: ${council.confidence}%`);continue}

        // Auto-leverage: tighter SL = higher leverage for same risk
        const slDistPct=(atr*bot.slATR)/price*100;
        let autoLev=1;
        if(bot.tradingType!=='spot'){
          autoLev=Math.max(1,Math.min(bot.leverage,Math.round(bot.riskPct/slDistPct)));
          autoLev=Math.min(autoLev,bot.leverage);
        }

        // Position sizing — for small balances, use fixed % of balance instead of risk-based
        const riskUSD=bal*(bot.riskPct/100);const slDist=atr*bot.slATR;
        let posUSD=Math.min(riskUSD/(slDist/price)*autoLev,bal*0.15);

        // KuCoin minimums
        const minSize=bot.tradingType==='spot'?1:5;

        const useSmall=bot.smallBalanceMode==='on'||(bot.smallBalanceMode==='auto'&&bal<100);

        if(bot.tradingType==='spot'){
          if(useSmall){
            posUSD=bal*0.9; // Use 90% of balance for spot trades in small balance mode
          }else{
            posUSD=Math.min(bal*0.9,posUSD);
          }
          autoLev=1;
        }else{
          // Futures
          if(useSmall){
            // OVERRIDE: use 50% of balance × max leverage for position size
            posUSD=bal*0.5*bot.leverage;
            autoLev=bot.leverage;
          }else{
            // Normal mode: cap by available margin
            const maxPosByMargin=bal*0.8*bot.leverage;
            posUSD=Math.min(posUSD,maxPosByMargin);
          }
        }

        const marginRequired=bot.tradingType==='spot'?posUSD:posUSD/autoLev;
        if(marginRequired>bal*0.9){
          botLog(`${coin} SKIP: margin $${marginRequired.toFixed(2)} exceeds available $${bal.toFixed(2)}`);
          continue;
        }

        if(posUSD<minSize){
          botLog(`${coin} SKIP: pos $${posUSD.toFixed(2)} < min $${minSize} (balance:$${bal.toFixed(2)} lev:${autoLev}x smallMode:${bot.smallBalanceMode} useSmall:${useSmall})`);
          continue;
        }

        const sl=council.decision==='buy'?price-slDist:price+slDist;
        const tp=council.decision==='buy'?price+atr*bot.tpATR:price-atr*bot.tpATR;
        const slPct=((slDist/price)*100).toFixed(2);

        // Execute
        if(bot.mode==='paper'){
          if(council.decision==='buy')paperBuy(sym,price,posUSD,sl,tp,council.confidence,council,'spot',autoLev);
          else if(council.decision==='sell')paperSell(sym,price,posUSD,sl,tp,council.confidence,council,autoLev);
        }else{
          // LIVE MODE
          const useFutures=bot.tradingType==='futures'||bot.tradingType==='combined';
          try{
            let orderResult,fillPrice=price,fillQty,realUSD,lev=autoLev;

            if(useFutures){
              // FUTURES — supports both long and short with leverage
              lev=bot.leverage;  // use configured leverage
              orderResult=await futuresOrder(council.decision,sym,posUSD,price,lev);
              fillQty=orderResult.qty;
              realUSD=posUSD;  // notional position value
              botLog(`LIVE FUTURES ${council.decision.toUpperCase()} ${sym} @$${fillPrice.toFixed(4)} | notional:$${realUSD.toFixed(2)} | lev:${lev}x | contracts:${orderResult.contracts} | margin:$${(realUSD/lev).toFixed(2)}`);
            }else{
              // SPOT — only long
              if(council.decision==='sell'){
                botLog(`${coin} SKIP: cannot short on spot. Switch to Futures/Combined mode.`);
                continue;
              }
              orderResult=await liveOrder(council.decision,sym,posUSD,price);
              fillQty=orderResult.qty||(posUSD/price);
              realUSD=fillPrice*fillQty;
              lev=1;
              botLog(`LIVE SPOT BUY ${sym} @$${fillPrice.toFixed(4)} | size:$${realUSD.toFixed(2)} | qty:${fillQty.toFixed(6)}`);
            }

            bot.openTrades.push({
              id:crypto.randomUUID().slice(0,8),
              orderId:orderResult.orderId,
              symbol:sym,
              side:council.decision,
              type:useFutures?'futures':'spot',
              leverage:lev,
              entryPrice:fillPrice,
              qty:fillQty,
              contracts:orderResult.contracts||null,
              usdAmount:realUSD,
              margin:useFutures?realUSD/lev:realUSD,
              sl,tp,
              confidence:council.confidence,
              agreeing:council.agreeing,
              openTime:new Date().toISOString(),
              status:'open',
              highSince:fillPrice,
              lowSince:fillPrice,
              trailingSl:bot.trailingStop?sl:null,
              isLive:true
            });
            saveState();
          }catch(e){botLog(`ORDER ERR ${sym}: ${e.message}`)}
        }
        bot.cooldown[sym]=Date.now();
      }catch(e){botLog(`${sym.replace('-USDT','')} error: ${e.message}`)}
      // Small delay between coins to avoid rate limits
      await new Promise(r=>setTimeout(r,1500));
    }
  }catch(e){botLog(`TICK ERROR: ${e.message}`)}
}

// Fetch real order fill details from KuCoin
async function fetchOrderFill(orderId){
  if(!bot.credentials)return null;
  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep=`/api/v1/orders/${orderId}`;
  const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
  const d=await safeJSON(r);
  if(d.code==='200000'&&d.data){
    return{price:+d.data.dealFunds/(+d.data.dealSize||1),qty:+d.data.dealSize,fee:+d.data.fee||0,filled:d.data.dealSize>0};
  }
  return null;
}

// Fetch real wallet balance for live mode
let liveBalanceCache={totalUSD:0,updated:0};
async function fetchLiveBalance(){
  if(!bot.credentials)return 0;
  if(Date.now()-liveBalanceCache.updated<15000)return liveBalanceCache.totalUSD;
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    let spotTotal=0,futuresTotal=0;
    const bals={};

    // Spot balance
    try{
      const ep='/api/v1/accounts?type=trade';
      const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
      const d=await safeJSON(r);
      if(d.code==='200000'){
        for(const a of d.data){const v=parseFloat(a.available);if(v>0)bals[a.currency]=(bals[a.currency]||0)+v}
      }
    }catch(e){console.log('Spot bal err:',e.message)}

    // Price map
    let pm={USDT:1,USDC:1};
    try{
      const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);
      if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;
    }catch{}
    for(const[c,a]of Object.entries(bals))spotTotal+=(pm[c]||0)*a;

    // Futures balance (separate API)
    try{
      const fep='/api/v1/account-overview?currency=USDT';
      const fr=await fetch('https://api-futures.kucoin.com'+fep,{headers:kcH('GET',fep,null,apiKey,apiSecret,passphrase)});
      const fd=await safeJSON(fr);
      if(fd.code==='200000'&&fd.data){
        futuresTotal=+fd.data.accountEquity||+fd.data.availableBalance||0;
      }
    }catch(e){console.log('Futures bal err:',e.message)}

    const total=spotTotal+futuresTotal;
    liveBalanceCache={totalUSD:Math.round(total*100)/100,spotUSD:Math.round(spotTotal*100)/100,futuresUSD:Math.round(futuresTotal*100)/100,balances:bals,updated:Date.now()};
    return total;
  }catch{return liveBalanceCache.totalUSD}
}

// Track initial live balance for PnL calculation
function getCurBal(){
  if(bot.mode==='live'){
    const liveBal=liveBalanceCache.totalUSD;
    // If we have a valid live balance, use it and auto-init startBal/peakBal
    if(liveBal&&liveBal>0){
      if(!bot.liveInitialized||bot.startBal===10000){
        bot.startBal=liveBal;
        bot.peakBal=liveBal;
        bot.liveInitialized=true;
        console.log('Live mode initialized: startBal=$'+liveBal);
      }
      return liveBal;
    }
    // No live balance yet — return peakBal to avoid fake drawdown
    return bot.peakBal||bot.startBal||10000;
  }
  let b=bot.paperUSD;
  for(const t of bot.openTrades){const a=bot.lastAnalysis[t.symbol];if(!a){b+=t.margin;continue}const dir=t.side==='buy'?1:-1;b+=t.margin+(a.price-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)}
  return b;
}

// ═══ BACKTEST ═══
async function backtest(sym,reqAgents=4,periods=500){
  const candles=await fetchKlines(sym,'15min',periods);if(candles.length<60)throw new Error('Not enough data');
  let bal=10000,peak=10000,maxDD=0,open=null;const trades=[];
  for(let i=55;i<candles.length;i++){
    const sl=candles.slice(0,i+1);const a=await analyze(sl,sym);const{price,atr}=a;if(!price||!atr)continue;
    if(open){
      if(open.side==='buy'){if(price<=open.sl||price>=open.tp){const pnl=(price-open.entry)*open.qty;bal+=open.cost+pnl;trades.push({...open,exit:price,pnl,pnlPct:(pnl/open.cost)*100,reason:price<=open.sl?'sl':'tp'});open=null}}
      else{if(price>=open.sl||price<=open.tp){const pnl=(open.entry-price)*open.qty;bal+=open.cost+pnl;trades.push({...open,exit:price,pnl,pnlPct:(pnl/open.cost)*100,reason:price>=open.sl?'sl':'tp'});open=null}}
    }
    if(bal>peak)peak=bal;const dd=((peak-bal)/peak)*100;if(dd>maxDD)maxDD=dd;
    if(open)continue;
    const council=councilVote(a,reqAgents);
    if(council.decision==='hold'||council.confidence<40)continue;
    const rUSD=bal*0.02,slD=atr*1.5,cost=Math.min(rUSD/(slD/price),bal*0.25);if(cost<10)continue;
    const qty=cost/price;
    bal-=cost;open={side:council.decision,symbol:sym,entry:price,qty,cost,sl:council.decision==='buy'?price-slD:price+slD,tp:council.decision==='buy'?price+atr*3:price-atr*3,conf:council.confidence,agreeing:council.agreeing};
  }
  if(open){const lp=candles[candles.length-1].close;const dir=open.side==='buy'?1:-1;const pnl=(lp-open.entry)*open.qty*dir;bal+=open.cost+pnl;trades.push({...open,exit:lp,pnl,pnlPct:(pnl/open.cost)*100,reason:'end'})}
  const wins=trades.filter(t=>t.pnl>0),losses=trades.filter(t=>t.pnl<=0);
  const gp=wins.reduce((a,t)=>a+t.pnl,0),gl=Math.abs(losses.reduce((a,t)=>a+t.pnl,0));
  return{symbol:sym,requiredAgents:reqAgents,periods:candles.length,startBal:10000,endBal:Math.round(bal*100)/100,totalTrades:trades.length,wins:wins.length,losses:losses.length,winRate:trades.length?Math.round(wins.length/trades.length*10000)/100:0,profitFactor:gl>0?Math.round(gp/gl*100)/100:gp>0?999:0,avgWin:wins.length?Math.round(gp/wins.length*100)/100:0,avgLoss:losses.length?Math.round(gl/losses.length*100)/100:0,maxDrawdown:Math.round(maxDD*100)/100,trades:trades.slice(-50)};
}

// ═══ ROUTES ═══
app.post('/api/bot/connect',mw,(req,res)=>{const{apiKey,apiSecret,passphrase}=req.body||{};if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All fields required'});bot.credentials={apiKey,apiSecret,passphrase};botLog('Exchange connected');saveSettings();res.json({success:true})});
app.post('/api/bot/start',mw,(req,res)=>{if(bot.running)return res.json({success:true});bot.running=true;botLog(`STARTED — ${bot.mode} | ${bot.symbols.length} coins | ${bot.requiredAgents}/${Object.keys(AGENTS).length} agents needed`);tick();bot.intervalId=setInterval(tick,bot.intervalMs);res.json({success:true})});
app.post('/api/bot/stop',mw,(req,res)=>{bot.running=false;if(bot.intervalId){clearInterval(bot.intervalId);bot.intervalId=null}botLog('STOPPED');res.json({success:true})});

app.get('/api/bot/status',mw,async(req,res)=>{
  // In live mode, fetch real balance
  if(bot.mode==='live'&&bot.credentials){try{await fetchLiveBalance()}catch{}}
  const bal=getCurBal(),dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0,tot=bot.winCount+bot.lossCount;
  const liveBal=bot.mode==='live'?liveBalanceCache:{};
  res.json({running:bot.running,mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,leverage:bot.leverage,
    tickCount,newsAge:newsCache.updated?Math.round((Date.now()-newsCache.updated)/1000):null,newsArticles:(newsCache.articles||[]).length,
    balance:Math.round(bal*100)/100,startBal:bot.startBal,totalPnL:Math.round(bot.totalPnL*100)/100,
    totalPnLPct:bot.startBal>0?Math.round((bal-bot.startBal)/bot.startBal*10000)/100:0,
    // Real portfolio data (live mode only)
    liveBalance:liveBal.totalUSD||null,liveBalances:liveBal.balances||null,
    isLive:bot.mode==='live',
    winCount:bot.winCount,lossCount:bot.lossCount,winRate:tot>0?Math.round(bot.winCount/tot*10000)/100:0,
    drawdown:Math.round(dd*100)/100,requiredAgents:bot.requiredAgents,totalAgents:Object.keys(AGENTS).length,
    openTrades:bot.openTrades.map(t=>{const cp=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;const dir=t.side==='buy'?1:-1;const upnl=Math.round((cp-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)*100)/100;return{...t,currentPrice:cp,unrealizedPnl:upnl,slPct:t.sl?((Math.abs(t.entryPrice-t.sl)/t.entryPrice)*100).toFixed(2)+'%':'—'}}),
    recentHistory:bot.history.slice(-30).reverse(),council:bot.lastCouncil,log:bot.log.slice(-50).reverse(),
    hasCredentials:!!bot.credentials,sentiment:sentimentCache,newsOverall:newsCache.overall,newsSentiment:newsCache.sentiment,recentNews:(newsCache.articles||[]).slice(0,15),
    settings:{riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents}
  });
});

app.post('/api/bot/settings',mw,async(req,res)=>{
  const s=req.body||{};
  if(s.mode==='live'&&bot.mode!=='live')botLog('⚠ SWITCHED TO LIVE');
  if(s.mode)bot.mode=s.mode;if(s.tradingType)bot.tradingType=s.tradingType;
  if(s.symbols&&Array.isArray(s.symbols))bot.symbols=s.symbols;
  if(s.riskPct!==undefined)bot.riskPct=Math.max(0.5,Math.min(5,+s.riskPct));
  if(s.maxDrawdownPct!==undefined)bot.maxDrawdownPct=Math.max(5,Math.min(30,+s.maxDrawdownPct));
  if(s.slATR!==undefined)bot.slATR=Math.max(0.5,Math.min(5,+s.slATR));
  if(s.tpATR!==undefined)bot.tpATR=Math.max(1,Math.min(10,+s.tpATR));
  if(s.trailingStop!==undefined)bot.trailingStop=!!s.trailingStop;
  if(s.maxOpenTrades!==undefined)bot.maxOpenTrades=Math.max(1,Math.min(15,+s.maxOpenTrades));
  if(s.leverage!==undefined)bot.leverage=Math.max(1,Math.min(20,+s.leverage));
  if(s.intervalMs!==undefined){bot.intervalMs=Math.max(30000,Math.min(300000,+s.intervalMs));if(bot.running&&bot.intervalId){clearInterval(bot.intervalId);bot.intervalId=setInterval(tick,bot.intervalMs)}}
  if(s.requiredAgents!==undefined)bot.requiredAgents=Math.max(2,Math.min(9,+s.requiredAgents));
  if(s.smallBalanceMode)bot.smallBalanceMode=s.smallBalanceMode;
  if(s.resetPaper){bot.paperUSD=10000;bot.startBal=10000;bot.peakBal=10000;bot.openTrades=[];bot.history=[];bot.totalPnL=0;bot.winCount=0;bot.lossCount=0;botLog('Paper reset')}
  if(s.resetDrawdown){
    // Re-initialize live baseline to current balance
    if(bot.mode==='live'){
      try{await fetchLiveBalance()}catch{}
      const liveBal=liveBalanceCache.totalUSD||bot.startBal;
      bot.startBal=liveBal;bot.peakBal=liveBal;bot.liveInitialized=true;
      botLog('Live drawdown reset — new baseline $'+liveBal.toFixed(2));
    }else{
      bot.peakBal=bot.paperUSD;botLog('Paper peak balance reset to current');
    }
  }
  botLog('Settings updated');saveSettings();saveState();res.json({success:true});
});

app.get('/api/bot/analysis/:sym',mw,async(req,res)=>{
  try{const a=await multiTimeframeAnalysis(req.params.sym);const council=councilVote(a,bot.requiredAgents);res.json({success:true,analysis:a,council})}catch(e){res.status(500).json({error:e.message})}
});
app.get('/api/bot/news',mw,async(req,res)=>{try{const n=await fetchNews();const s=await getSentiment();res.json({success:true,articles:n.articles,coinSentiment:n.sentiment,overall:n.overall,fearGreed:s})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/bot/backtest',mw,async(req,res)=>{try{const{symbol='BTC-USDT',requiredAgents=4,periods=500}=req.body||{};res.json({success:true,result:await backtest(symbol,requiredAgents,periods)})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/bot/close/:id',mw,(req,res)=>{const t=bot.openTrades.find(x=>x.id===req.params.id);if(!t)return res.status(404).json({error:'Not found'});closeTrade(t,bot.lastAnalysis[t.symbol]?.price||t.entryPrice,'manual');res.json({success:true})});

// Diagnostic: test full pipeline for one coin (with timeout)
app.get('/api/bot/diagnose/:sym',mw,async(req,res)=>{
  const sym=req.params.sym;const steps=[];
  let done=false;
  // 15 second hard timeout
  const timeout=setTimeout(()=>{
    if(done)return;done=true;
    steps.push({step:'TIMEOUT',error:'Request took >15s — KuCoin may be slow or rate-limited'});
    res.json({success:false,symbol:sym,steps,error:'timeout'});
  },15000);

  try{
    // Try cached data first
    if(bot.lastAnalysis[sym]&&bot.lastCouncil[sym]){
      const a=bot.lastAnalysis[sym];const council=bot.lastCouncil[sym];
      steps.push({step:'source',data:'Using cached data from last bot scan'});
      steps.push({step:'analyze',status:'ok',price:a.price,rsi:a.rsi?.toFixed(1),condition:a.condition,atr:a.atr?.toFixed(2)});
      steps.push({step:'council',status:'ok',decision:council.decision,confidence:council.confidence,
        buyCount:council.buyCount,sellCount:council.sellCount,
        buyScore:council.buyScore,sellScore:council.sellScore,
        threshold:council.weightThreshold,
        buyT1:council.buyT1,sellT1:council.sellT1,
        blockReason:council.blockReason||'none',
        votes:Object.fromEntries(Object.entries(council.votes||{}).map(([k,v])=>[k,v.vote+'('+v.confidence+'%)']))
      });
      const bal=getCurBal();
      const dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0;
      const cooldownLeft=bot.cooldown[sym]?Math.max(0,300000-(Date.now()-bot.cooldown[sym])):0;
      const openForSym=bot.openTrades.filter(t=>t.symbol===sym).length;
      steps.push({step:'gates',balance:Math.round(bal*100)/100,drawdown:dd.toFixed(1)+'%',maxDD:bot.maxDrawdownPct+'%',ddBlocked:dd>=bot.maxDrawdownPct,cooldownLeft:Math.round(cooldownLeft/1000)+'s',cooldownBlocked:cooldownLeft>0,openTrades:bot.openTrades.length,maxTrades:bot.maxOpenTrades,maxBlocked:bot.openTrades.length>=bot.maxOpenTrades,openForThisCoin:openForSym,maxPerCoin:2,coinBlocked:openForSym>=2,confidenceOk:council.confidence>=40,mode:bot.mode,running:bot.running});
      const wouldTrade=council.decision!=='hold'&&council.confidence>=40&&dd<bot.maxDrawdownPct&&cooldownLeft<=0&&bot.openTrades.length<bot.maxOpenTrades&&openForSym<2&&bot.running;
      steps.push({step:'result',wouldTrade,decision:council.decision,reason:wouldTrade?'ALL GATES PASSED':'Blocked — bot.running='+bot.running+' decision='+council.decision+' conf='+council.confidence});
      if(done)return;done=true;clearTimeout(timeout);
      return res.json({success:true,symbol:sym,steps,cached:true});
    }

    // No cache — fetch fresh (with timeout)
    steps.push({step:'source',data:'No cached data for this coin, fetching fresh'});
    const c15=await fetchKlines(sym,'15min',100);
    if(done)return;
    steps.push({step:'fetch_15m',status:'ok',candles:c15.length});

    const a=await analyze(c15,sym);
    steps.push({step:'analyze',status:'ok',price:a.price,rsi:a.rsi?.toFixed(1),condition:a.condition,atr:a.atr?.toFixed(2)});

    const council=councilVote(a,bot.requiredAgents);
    steps.push({step:'council',status:'ok',decision:council.decision,confidence:council.confidence,buyCount:council.buyCount,sellCount:council.sellCount,buyScore:council.buyScore,sellScore:council.sellScore,threshold:council.weightThreshold,buyT1:council.buyT1,sellT1:council.sellT1,blockReason:council.blockReason||'none',votes:Object.fromEntries(Object.entries(council.votes).map(([k,v])=>[k,v.vote+'('+v.confidence+'%)']))});

    const bal=getCurBal();
    const dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0;
    const cooldownLeft=bot.cooldown[sym]?Math.max(0,300000-(Date.now()-bot.cooldown[sym])):0;
    const openForSym=bot.openTrades.filter(t=>t.symbol===sym).length;
    steps.push({step:'gates',balance:Math.round(bal*100)/100,drawdown:dd.toFixed(1)+'%',maxDD:bot.maxDrawdownPct+'%',ddBlocked:dd>=bot.maxDrawdownPct,cooldownLeft:Math.round(cooldownLeft/1000)+'s',cooldownBlocked:cooldownLeft>0,openTrades:bot.openTrades.length,maxTrades:bot.maxOpenTrades,maxBlocked:bot.openTrades.length>=bot.maxOpenTrades,openForThisCoin:openForSym,maxPerCoin:2,coinBlocked:openForSym>=2,confidenceOk:council.confidence>=40,mode:bot.mode,running:bot.running});

    const wouldTrade=council.decision!=='hold'&&council.confidence>=40&&dd<bot.maxDrawdownPct&&cooldownLeft<=0&&bot.openTrades.length<bot.maxOpenTrades&&openForSym<2&&bot.running;
    steps.push({step:'result',wouldTrade,decision:council.decision,reason:wouldTrade?'ALL GATES PASSED':'Blocked — bot.running='+bot.running});

    if(done)return;done=true;clearTimeout(timeout);
    res.json({success:true,symbol:sym,steps});
  }catch(e){
    if(done)return;done=true;clearTimeout(timeout);
    steps.push({step:'ERROR',error:e.message});
    res.json({success:false,symbol:sym,steps,error:e.message});
  }
});

// PUBLIC debug page — no auth, view in browser
app.get('/debug',(req,res)=>{
  res.setHeader('Content-Type','text/html');
  let h='<html><head><meta http-equiv="refresh" content="10"><title>Debug</title><style>body{font-family:monospace;background:#000;color:#0f0;padding:20px;font-size:12px;line-height:1.5}h2{color:#ff0;border-bottom:1px solid #0f0;margin-top:20px}pre{background:#111;padding:10px;overflow-x:auto}.ok{color:#0f0}.bad{color:#f00}.warn{color:#fa0}</style></head><body>';
  h+='<h1>TradeMatrix Debug (refreshes every 10s)</h1>';
  h+='<h2>BOT STATUS</h2><pre>';
  h+='running: '+(bot.running?'<span class="ok">YES</span>':'<span class="bad">NO — not trading!</span>')+'\n';
  h+='mode: '+bot.mode+' | type: '+bot.tradingType+'\n';
  h+='tickCount: '+tickCount+' '+(tickCount===0?'<span class="bad">(BOT NEVER RAN)</span>':tickCount<5?'<span class="warn">(just started)</span>':'<span class="ok">(healthy)</span>')+'\n';
  h+='requiredAgents: '+bot.requiredAgents+' of '+Object.keys(AGENTS).length+'\n';
  h+='credentials: '+(bot.credentials?'<span class="ok">yes</span>':'<span class="bad">no</span>')+'\n';
  h+='openTrades: '+bot.openTrades.length+' | historyCount: '+bot.history.length+'\n';
  h+='</pre>';
  h+='<h2>NEWS CACHE</h2><pre>';
  h+='articles: '+(newsCache.articles?.length||0)+'\n';
  h+='lastUpdate: '+(newsCache.updated?Math.round((Date.now()-newsCache.updated)/60000)+' min ago':'<span class="bad">NEVER</span>')+'\n';
  h+='</pre>';
  h+='<h2>LAST 30 LOG ENTRIES</h2><pre>';
  if(bot.log.length===0)h+='<span class="bad">NO LOG ENTRIES — bot has never run</span>';
  else h+=bot.log.slice(-30).map(l=>new Date(l.time).toLocaleTimeString()+' '+l.msg).join('\n');
  h+='</pre>';
  h+='<h2>COUNCIL RESULTS (last scan of each coin)</h2><pre>';
  const ck=Object.keys(bot.lastCouncil);
  if(ck.length===0)h+='<span class="bad">NO COUNCIL DATA — bot has not analyzed any coins yet</span>';
  else{
    for(const s of ck){const c=bot.lastCouncil[s];
    const col=c.decision==='buy'?'ok':c.decision==='sell'?'bad':'warn';
    h+=s.padEnd(12)+' <span class="'+col+'">'+c.decision.toUpperCase().padEnd(4)+'</span> conf:'+String(c.confidence).padStart(3)+'% | B:'+c.buyCount+'('+c.buyScore+'pts) S:'+c.sellCount+'('+c.sellScore+'pts) | need '+c.weightThreshold+'pts | T1:'+c.buyT1+'/'+c.sellT1+' | '+(c.blockReason||'')+'\n'}
  }
  h+='</pre></body></html>';
  res.send(h);
});
app.get('/api/bot/wallet',mw,async(req,res)=>{
  if(!bot.credentials)return res.json({connected:false});
  try{const{apiKey,apiSecret,passphrase}=bot.credentials;const ep='/api/v1/accounts?type=trade';const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});const d=await safeJSON(r);if(d.code!=='200000')return res.json({connected:false,error:d.msg});
  const bals={};for(const a of d.data){const v=parseFloat(a.available);if(v>0)bals[a.currency]=(bals[a.currency]||0)+v}
  let total=0;try{const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);const pm={USDT:1,USDC:1};if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;for(const[c,a]of Object.entries(bals))total+=(pm[c]||0)*a}catch{}
  res.json({connected:true,balances:bals,totalUSD:Math.round(total*100)/100})}catch(e){res.json({connected:false,error:e.message})}
});
// AI Advisor
app.post('/api/bot/ai-advice',mw,async(req,res)=>{
  const{symbol='BTC-USDT',anthropicKey}=req.body||{};if(!anthropicKey)return res.status(400).json({error:'API key required'});
  try{const candles=await fetchKlines(symbol,'15min',100);const a=await analyze(candles,symbol);const council=councilVote(a,bot.requiredAgents);
  const prompt=`Expert crypto trader analysis for ${symbol}:\nPrice:$${a.price?.toFixed(2)} Condition:${a.condition} RSI:${a.rsi?.toFixed(1)} MACD:${a.macdHist?.toFixed(4)} ADX:${a.adx?.toFixed(1)}\nFib Support:$${a.support?.toFixed(2)} Resistance:$${a.resistance?.toFixed(2)} Golden Pocket:${a.inGoldenPocket}\nVWAP:$${a.vwap?.toFixed(2)} OBV:${a.obvTrend} Volume:${a.volTrend}\nFear&Greed:${a.sentiment.value}(${a.sentiment.label}) News:${a.news.coin.bias}(${a.news.coin.n} articles)\nCouncil:${council.buyCount} buy/${council.sellCount} sell → ${council.decision} (${council.confidence}%)\n\nGive: RECOMMENDATION, CONFIDENCE(1-10), ENTRY, SL, TP, REASONING(2-3 sentences), RISK`;
  const r=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json','x-api-key':anthropicKey,'anthropic-version':'2023-06-01'},body:JSON.stringify({model:'claude-sonnet-4-20250514',max_tokens:500,messages:[{role:'user',content:prompt}]})});
  const d=await safeJSON(r);res.json({success:true,advice:d.content?.map(x=>x.text||'').join('\n')||'No response',council})}catch(e){res.status(500).json({error:e.message})}
});

app.get('/api/prices',async(req,res)=>{try{const r=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const d=await safeJSON(r);if(d.code!=='200000')return res.status(502).json({error:'Feed error'});const prices={};for(const t of d.data.ticker)if(ALL_SYMBOLS.includes(t.symbol))prices[t.symbol]={price:+t.last,change:+t.changeRate*100,vol:+t.volValue};res.json({success:true,prices})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/kucoin/balance',async(req,res)=>{const{apiKey,apiSecret,passphrase}=req.body||{};if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All required'});try{const ep='/api/v1/accounts?type=trade';const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});const d=await safeJSON(r);if(d.code!=='200000')return res.status(400).json({error:d.msg||'Error'});const b={};for(const a of d.data){const v=+a.available;if(v>0)b[a.currency]=(b[a.currency]||0)+v}let t=0;try{const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);const pm={USDT:1,USDC:1};if(pd.code==='200000')for(const x of pd.data.ticker)if(x.symbol.endsWith('-USDT'))pm[x.symbol.replace('-USDT','')]=+x.last||0;for(const[c,a]of Object.entries(b))t+=(pm[c]||0)*a}catch{}res.json({success:true,balances:b,totalUSD:t})}catch(e){res.status(500).json({error:e.message})}});

app.get('/health',(_,res)=>res.json({status:'ok'}));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(_,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const PORT=process.env.PORT||3000;
app.listen(PORT,'0.0.0.0',()=>console.log(`TradeMatrix Pro v4 Council → http://localhost:${PORT}`));

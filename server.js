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

    // CryptoCompare only — free unlimited, no rate limits
    const cats=['','&categories=regulation,fiat,exchange','&categories=mining,trading,technology','&categories=blockchain,business,government'];
    for(const cat of cats){
      try{
        const controller=new AbortController();
        const timeout=setTimeout(()=>controller.abort(),8000);
        const r=await fetch('https://min-api.cryptocompare.com/data/v2/news/?lang=EN&sortOrder=latest'+cat,{signal:controller.signal});
        clearTimeout(timeout);
        const d=await safeJSON(r);
        if(d.Data)for(const a of d.Data.slice(0,15)){const x=classify(a.title,a.body,a.source,a.url,a.published_on*1000);if(x)articles.push(x)}
      }catch(e){console.log('News cat err:',e.message)}
    }

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
  // Every agent reads the CONTEXT first, then interprets its indicator accordingly.
  // bull = condition includes 'bullish', bear = includes 'bearish'

  trend_master(a){
    if(!a.ema9||!a.ema21)return{vote:'hold',confidence:0,reason:'Missing EMA data'};
    const bull=a.ema9>a.ema21, aligned=a.ema50&&((bull&&a.ema21>a.ema50)||(!bull&&a.ema21<a.ema50));
    const strong=a.adx&&a.adx>25, adx=a.adx?a.adx.toFixed(0):'?';
    // Context: EMAs tell the story of trend direction AND strength
    if(bull&&aligned&&strong)return{vote:'buy',confidence:90,reason:'Perfect uptrend setup: all EMAs stacked bullish (9>21>50) with strong trend momentum (ADX:'+adx+'). This is a textbook "don\'t fight the trend" situation — stay long.'};
    if(bull&&aligned)return{vote:'buy',confidence:70,reason:'Uptrend intact: EMAs aligned bullish but trend strength is moderate (ADX:'+adx+'). Good for buying dips but don\'t chase.'};
    if(!bull&&aligned&&strong)return{vote:'sell',confidence:90,reason:'Strong downtrend: all EMAs stacked bearish (9<21<50) with powerful selling pressure (ADX:'+adx+'). Shorting into strength is the play here.'};
    if(!bull&&aligned)return{vote:'sell',confidence:70,reason:'Downtrend in progress: EMAs aligned bearish (ADX:'+adx+'). Rallies are sell opportunities until EMAs flip.'};
    if(bull)return{vote:'buy',confidence:50,reason:'Short-term bullish bias: EMA9 above EMA21 but longer-term EMAs not yet aligned (ADX:'+adx+'). Could be an early trend change or just a bounce — cautiously bullish.'};
    return{vote:'sell',confidence:50,reason:'Short-term bearish bias: EMA9 below EMA21 (ADX:'+adx+'). Could be early downtrend or a dip — watching for confirmation.'};
  },

  momentum_hunter(a){
    if(a.rsi===null)return{vote:'hold',confidence:0,reason:'No RSI data'};
    const trend=a.condition||'neutral';const r=a.rsi;const rising=a.prevRsi&&r>a.prevRsi;
    // CONTEXT: RSI means different things in different trends
    if(trend.includes('bullish')){
      // In uptrend: RSI 40-50 is a DIP to buy, 60-70 is normal, >75 is extended
      if(r<35)return{vote:'buy',confidence:90,reason:'RSI at '+r.toFixed(0)+' in an uptrend — this is a deep oversold dip. In strong uptrends, these are the best buy opportunities. Smart money buys fear.'};
      if(r<45)return{vote:'buy',confidence:80,reason:'RSI at '+r.toFixed(0)+' pulling back in an uptrend — classic "buy the dip" setup. Healthy correction before the next leg up.'};
      if(r<60)return{vote:'buy',confidence:60,reason:'RSI at '+r.toFixed(0)+' — normal healthy range for an uptrend. Momentum is with the buyers.'};
      if(r<75)return{vote:'buy',confidence:45,reason:'RSI at '+r.toFixed(0)+' — getting extended but uptrends can stay overbought for a long time. Still bullish but tighten stops.'};
      return{vote:'sell',confidence:70,reason:'RSI at '+r.toFixed(0)+' in uptrend — extremely overbought even for a bull market. Short-term pullback very likely. Taking profits here is wise.'};
    }
    if(trend.includes('bearish')){
      // In downtrend: RSI 50-60 is a dead cat bounce = sell, <30 might bounce but trend is down
      if(r>65)return{vote:'sell',confidence:90,reason:'RSI at '+r.toFixed(0)+' in a downtrend — this is a bear market rally / dead cat bounce. Overbought in a downtrend = prime short entry.'};
      if(r>55)return{vote:'sell',confidence:80,reason:'RSI at '+r.toFixed(0)+' bouncing in a downtrend — the bounce is losing steam. Sellers will likely push it back down.'};
      if(r>45)return{vote:'sell',confidence:60,reason:'RSI at '+r.toFixed(0)+' — weak momentum in a downtrend. Bears are in control.'};
      if(r>30)return{vote:'sell',confidence:45,reason:'RSI at '+r.toFixed(0)+' — oversold but downtrends can stay oversold for weeks. Don\'t try to catch falling knives.'};
      return{vote:'buy',confidence:55,reason:'RSI at '+r.toFixed(0)+' — extremely oversold even for a downtrend. Dead cat bounce likely but be quick — the trend is still down.'};
    }
    // Sideways/neutral: RSI extremes matter more
    if(r<30)return{vote:'buy',confidence:80,reason:'RSI at '+r.toFixed(0)+' in ranging market — oversold, mean reversion bounce expected.'};
    if(r<45)return{vote:'buy',confidence:50,reason:'RSI at '+r.toFixed(0)+' — below midline, slight buy lean.'};
    if(r>70)return{vote:'sell',confidence:80,reason:'RSI at '+r.toFixed(0)+' in ranging market — overbought, pullback expected.'};
    if(r>55)return{vote:'sell',confidence:50,reason:'RSI at '+r.toFixed(0)+' — above midline, slight sell lean.'};
    return{vote:rising?'buy':'sell',confidence:40,reason:'RSI neutral at '+r.toFixed(0)+', leaning with micro-momentum: '+(rising?'rising':'falling')+'.'};
  },

  macd_specialist(a){
    if(a.macdHist===null)return{vote:'hold',confidence:0,reason:'No MACD data'};
    const trend=a.condition||'neutral';const h=a.macdHist;
    const growing=a.prevMacdHist!==null&&Math.abs(h)>Math.abs(a.prevMacdHist);
    const crossUp=a.prevMacdHist!==null&&h>0&&a.prevMacdHist<=0;
    const crossDn=a.prevMacdHist!==null&&h<0&&a.prevMacdHist>=0;
    // Fresh crosses are always significant
    if(crossUp)return{vote:'buy',confidence:85,reason:'MACD just crossed bullish — fresh momentum shift. This is one of the strongest buy signals in technical analysis, especially when it aligns with the trend.'};
    if(crossDn)return{vote:'sell',confidence:85,reason:'MACD just crossed bearish — momentum has shifted to sellers. This often marks the start of a significant move down.'};
    // CONTEXT: MACD in trend
    if(trend.includes('bullish')){
      if(h>0&&growing)return{vote:'buy',confidence:75,reason:'MACD positive AND accelerating in an uptrend — bullish momentum is building. The trend is getting stronger, not weaker.'};
      if(h>0)return{vote:'buy',confidence:55,reason:'MACD positive but slowing in uptrend — momentum fading slightly but still bullish. Normal during consolidation before next push.'};
      if(h<0&&!growing)return{vote:'buy',confidence:65,reason:'MACD negative but recovering in uptrend — the pullback is losing steam. This is often the BEST buy signal: dip in an uptrend with MACD turning.'};
      return{vote:'sell',confidence:50,reason:'MACD negative and falling in uptrend — concerning. The pullback might go deeper. Wait for MACD to turn before buying.'};
    }
    if(trend.includes('bearish')){
      if(h<0&&growing)return{vote:'sell',confidence:75,reason:'MACD negative AND accelerating in downtrend — selling pressure intensifying. Don\'t try to catch this knife.'};
      if(h<0)return{vote:'sell',confidence:55,reason:'MACD negative in downtrend — bears in control. Bounces are for selling.'};
      if(h>0&&!growing)return{vote:'sell',confidence:65,reason:'MACD positive but fading in downtrend — the bounce is dying. This is a prime short entry: rally in a downtrend with MACD rolling over.'};
      return{vote:'buy',confidence:50,reason:'MACD positive and growing in downtrend — possible trend reversal starting, but need more confirmation.'};
    }
    if(h>0)return{vote:'buy',confidence:growing?65:50,reason:'MACD positive ('+h.toFixed(4)+') — '+(growing?'momentum building':'holding steady')+'. Bullish lean.'};
    return{vote:'sell',confidence:growing?65:50,reason:'MACD negative ('+h.toFixed(4)+') — '+(growing?'selling pressure building':'holding steady')+'. Bearish lean.'};
  },

  fibonacci_analyst(a){
    if(!a.fib||!a.price)return{vote:'hold',confidence:0,reason:'No fib data'};
    const trend=a.condition||'neutral';
    const distSup=Math.abs(a.price-a.support)/a.price*100;
    const distRes=Math.abs(a.resistance-a.price)/a.price*100;
    // Golden pocket is always significant
    if(a.inGoldenPocket)return{vote:'buy',confidence:85,reason:'Price is in the golden pocket zone (0.618 fib retracement) — this is the single most reliable buy zone in Fibonacci analysis. Institutional traders place limit orders here. High probability bounce zone.'};
    // CONTEXT: fib levels in trend
    if(trend.includes('bullish')){
      if(distSup<1)return{vote:'buy',confidence:80,reason:'Price at fib support $'+a.support.toFixed(2)+' in an uptrend — textbook "buy the dip at support" setup. Support levels hold more often in uptrends.'};
      if(distRes<0.5)return{vote:'buy',confidence:45,reason:'Price near fib resistance $'+a.resistance.toFixed(2)+' in uptrend — resistance often breaks in strong uptrends. Lean buy but watch for rejection.'};
      return{vote:'buy',confidence:55,reason:'In uptrend, closer to support ($'+a.support.toFixed(2)+') than resistance. Fib structure supports continuation higher.'};
    }
    if(trend.includes('bearish')){
      if(distRes<1)return{vote:'sell',confidence:80,reason:'Price at fib resistance $'+a.resistance.toFixed(2)+' in downtrend — textbook "sell the rip" setup. Resistance holds more often in downtrends.'};
      if(distSup<0.5)return{vote:'sell',confidence:45,reason:'Price at fib support $'+a.support.toFixed(2)+' in downtrend — support breaks more often in downtrends. Lean sell but watch for bounce.'};
      return{vote:'sell',confidence:55,reason:'In downtrend, closer to resistance ($'+a.resistance.toFixed(2)+'). Fib structure supports continuation lower.'};
    }
    if(distSup<distRes)return{vote:'buy',confidence:55,reason:'Closer to fib support ($'+a.support.toFixed(2)+') — mean reversion says buy near support.'};
    return{vote:'sell',confidence:55,reason:'Closer to fib resistance ($'+a.resistance.toFixed(2)+') — mean reversion says sell near resistance.'};
  },

  volume_expert(a){
    if(!a.price)return{vote:'hold',confidence:0,reason:'No data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];
    // CONTEXT: volume confirms or denies the trend
    if(trend.includes('bullish')){
      if(a.obvTrend==='bullish'){score+=35;reasons.push('Money flowing IN during uptrend — volume confirms the move up. Smart money is buying.')}
      else{score-=10;reasons.push('Warning: uptrend but money flowing OUT — the rally may be losing institutional support.')}
    }else if(trend.includes('bearish')){
      if(a.obvTrend==='bearish'){score-=35;reasons.push('Money flowing OUT during downtrend — volume confirms the selling. Institutions are dumping.')}
      else{score+=10;reasons.push('Interesting: downtrend but money flowing IN — possible accumulation by smart money before reversal.')}
    }else{
      if(a.obvTrend==='bullish'){score+=25;reasons.push('OBV bullish')}else{score-=25;reasons.push('OBV bearish')}
    }
    if(a.vwap){if(a.price>a.vwap){score+=15;reasons.push('Above VWAP $'+a.vwap.toFixed(2)+' — intraday buyers winning.')}else{score-=15;reasons.push('Below VWAP $'+a.vwap.toFixed(2)+' — intraday sellers winning.')}}
    if(a.volTrend==='high')reasons.push('Volume is elevated — move is significant.');
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  bollinger_trader(a){
    if(!a.bbUpper||!a.bbLower||!a.price)return{vote:'hold',confidence:0,reason:'No BB data'};
    const trend=a.condition||'neutral';const pos=(a.price-a.bbLower)/(a.bbUpper-a.bbLower);const pct=Math.round(pos*100);
    // CONTEXT: BB position means different things in trends vs ranges
    if(trend.includes('bullish')){
      if(pos<0.2)return{vote:'buy',confidence:85,reason:'Price at bottom of BB ('+pct+'%) during uptrend — this is a gift. In uptrends, lower BB touches are prime buy-the-dip entries. The band acts as dynamic support.'};
      if(pos<0.4)return{vote:'buy',confidence:65,reason:'Price in lower BB zone ('+pct+'%) during uptrend — healthy pullback. Expect bounce back toward upper band.'};
      if(pos>0.9)return{vote:'buy',confidence:40,reason:'Price at upper BB ('+pct+'%) in uptrend — extended but "walking the upper band" is normal in strong trends. Cautious buy, tighten stops.'};
      return{vote:'buy',confidence:55,reason:'BB position '+pct+'% in uptrend — normal range. Trend supports buying.'};
    }
    if(trend.includes('bearish')){
      if(pos>0.8)return{vote:'sell',confidence:85,reason:'Price at top of BB ('+pct+'%) during downtrend — classic sell-the-rip setup. Upper BB acts as dynamic resistance in downtrends.'};
      if(pos>0.6)return{vote:'sell',confidence:65,reason:'Price in upper BB zone ('+pct+'%) during downtrend — dead cat bounce hitting resistance.'};
      if(pos<0.1)return{vote:'sell',confidence:40,reason:'Price at lower BB ('+pct+'%) in downtrend — "walking the lower band" happens in crashes. Don\'t catch knives.'};
      return{vote:'sell',confidence:55,reason:'BB position '+pct+'% in downtrend — trend supports selling.'};
    }
    // Sideways: BB works best for mean reversion
    if(pos<0.15)return{vote:'buy',confidence:80,reason:'BB position '+pct+'% in range — oversold, strong mean reversion buy.'};
    if(pos<0.4)return{vote:'buy',confidence:55,reason:'BB below midline ('+pct+'%) — lean buy.'};
    if(pos>0.85)return{vote:'sell',confidence:80,reason:'BB position '+pct+'% in range — overbought, strong mean reversion sell.'};
    if(pos>0.6)return{vote:'sell',confidence:55,reason:'BB above midline ('+pct+'%) — lean sell.'};
    return{vote:pos<0.5?'buy':'sell',confidence:40,reason:'BB mid-range ('+pct+'%) — slight lean.'};
  },

  sentiment_analyst(a){
    if(!a.sentiment)return{vote:'hold',confidence:0,reason:'No sentiment data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];const fg=a.sentiment.value;
    // CONTEXT: sentiment is contrarian — fear in uptrend = buy more, greed in downtrend = short more
    if(trend.includes('bullish')){
      if(fg<30){score+=35;reasons.push('Extreme fear ('+fg+') in an uptrend — the crowd is scared but the trend is up. This is when Warren Buffett says "be greedy when others are fearful." Strongest buy signal.')}
      else if(fg<45){score+=20;reasons.push('Fear ('+fg+') despite uptrend — market hasn\'t caught up to the trend yet. Early buyers profit most.')}
      else if(fg>75){score-=15;reasons.push('Extreme greed ('+fg+') in uptrend — everyone is bullish which means the easy money is made. Tighten stops but don\'t fight the trend.')}
      else{score+=10;reasons.push('F&G '+fg+' — neutral sentiment in uptrend, room to run.')}
    }else if(trend.includes('bearish')){
      if(fg>70){score-=35;reasons.push('Extreme greed ('+fg+') in a downtrend — the crowd is delusional. They\'re buying the dip but the trend is down. Prime short setup.')}
      else if(fg>55){score-=20;reasons.push('Greed ('+fg+') despite downtrend — complacency before more pain.')}
      else if(fg<25){score+=15;reasons.push('Extreme fear ('+fg+') in downtrend — maximum pessimism might mean capitulation. Potential bottom but risky.')}
      else{score-=10;reasons.push('F&G '+fg+' in downtrend — sentiment confirms bearishness.')}
    }else{
      if(fg<30){score+=25;reasons.push('Extreme fear ('+fg+') — contrarian buy')}
      else if(fg>70){score-=25;reasons.push('Extreme greed ('+fg+') — contrarian sell')}
      else{score+=fg<50?5:-5;reasons.push('F&G neutral at '+fg)}
    }
    if(a.news){const cn=a.news.coin;if(cn&&cn.bias==='bullish'){score+=12;reasons.push('Coin news bullish')}if(cn&&cn.bias==='bearish'){score-=12;reasons.push('Coin news bearish')}
    const ov=a.news.overall;if(ov&&ov.macroBias==='bullish'){score+=8;reasons.push('World macro positive')}if(ov&&ov.macroBias==='bearish'){score-=8;reasons.push('World macro negative')}}
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  quant_ai(a){
    if(!a.price||!a.ema21||!a.bbUpper||!a.bbLower)return{vote:'hold',confidence:0,reason:'No data'};
    const trend=a.condition||'neutral';let score=0,reasons=[];
    const bbMid=a.bbSma||(a.bbUpper+a.bbLower)/2;const bbStd=(a.bbUpper-a.bbLower)/4;
    const zScore=bbStd>0?(a.price-bbMid)/bbStd:0;const roc=((a.price-a.ema21)/a.ema21)*100;
    reasons.push('Z-score:'+zScore.toFixed(2)+' ROC:'+roc.toFixed(2)+'%');
    // CONTEXT: z-score means different things in trending vs ranging
    if(trend.includes('bullish')){
      if(zScore<-1){score+=30;reasons.push('Statistically undervalued in uptrend — mean reversion + trend = high probability buy.')}
      else if(zScore>1.5){score-=10;reasons.push('Extended even for an uptrend — minor pullback likely but trend intact.')}
      else{score+=10;reasons.push('Normal range for uptrend.')}
    }else if(trend.includes('bearish')){
      if(zScore>1){score-=30;reasons.push('Statistically overvalued in downtrend — mean reversion + trend = high probability short.')}
      else if(zScore<-1.5){score+=10;reasons.push('Deeply depressed even for downtrend — dead cat bounce possible.')}
      else{score-=10;reasons.push('Normal range for downtrend.')}
    }else{
      if(zScore<-0.5)score+=15;else if(zScore>0.5)score-=15;
      if(roc<-1)score+=12;else if(roc>1)score-=12;
    }
    if(a.rsi&&a.rsi>70&&roc<0){score-=10;reasons.push('Bearish divergence detected.')}
    if(a.rsi&&a.rsi<30&&roc>0){score+=10;reasons.push('Bullish divergence detected.')}
    if(score>0)return{vote:'buy',confidence:Math.min(40+score,85),reason:reasons.join(' ')};
    return{vote:'sell',confidence:Math.min(40+Math.abs(score),85),reason:reasons.join(' ')};
  },

  atr_volatility(a){
    if(!a.atr||!a.price)return{vote:'hold',confidence:0,reason:'No ATR data'};
    const trend=a.condition||'neutral';const atrPct=(a.atr/a.price)*100;
    let score=0,reasons=['ATR: '+atrPct.toFixed(2)+'% of price.'];
    const bbWidth=a.bbUpper&&a.bbLower?((a.bbUpper-a.bbLower)/(a.bbSma||a.price))*100:5;
    // CONTEXT: volatility tells us HOW to trade, not just WHAT direction
    if(atrPct<1.5&&bbWidth<4){
      reasons.push('VOLATILITY SQUEEZE detected — bands are tight, big move incoming.');
      if(trend.includes('bullish')){score+=30;reasons.push('Squeeze in uptrend = expect explosive breakout UPWARD. Coiled spring ready to launch.')}
      else if(trend.includes('bearish')){score-=30;reasons.push('Squeeze in downtrend = expect breakdown. The calm before the storm — to the downside.')}
      else if(a.ema9>a.ema21){score+=20;reasons.push('Squeeze with bullish lean.')}
      else{score-=20;reasons.push('Squeeze with bearish lean.')}
    }else if(atrPct>3){
      const bbPos=a.bbUpper?(a.price-a.bbLower)/(a.bbUpper-a.bbLower):0.5;
      reasons.push('HIGH VOLATILITY — market is wild.');
      if(bbPos>0.8){score-=25;reasons.push('Extended to upside in high vol — profit-taking and mean reversion pullback likely.')}
      else if(bbPos<0.2){score+=25;reasons.push('Depressed in high vol — panic selling overdone, snap-back rally likely.')}
    }else{
      reasons.push('Normal volatility — good environment for trading.');
      if(trend.includes('bullish')){score+=12;reasons.push('Normal vol + uptrend = clean trending environment. Follow the trend.')}
      else if(trend.includes('bearish')){score-=12;reasons.push('Normal vol + downtrend = clean sell setup.')}
      else if(a.ema9>a.ema21){score+=8}else{score-=8}
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
  const weightThreshold=Math.max(6,requiredAgree*2); // e.g., 4 agents = need 8 pts
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
  riskPct:2,maxDrawdownPct:15,slATR:1.5,tpATR:3.0,trailingStop:true,trailATR:1.0,maxOpenTrades:10,leverage:5,
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
  try{const data=JSON.stringify({mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents,riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,credentials:bot.credentials});
  fs.writeFileSync(SETTINGS_FILE,data);console.log('Settings saved: mode='+bot.mode)}catch(e){console.log('Save err:',e.message)}
}
function saveState(){
  try{fs.writeFileSync(STATE_FILE,JSON.stringify({paperUSD:bot.paperUSD,startBal:bot.startBal,peakBal:bot.peakBal,totalPnL:bot.totalPnL,winCount:bot.winCount,lossCount:bot.lossCount,history:bot.history.slice(-200),openTrades:bot.openTrades}))}catch(e){console.log('State save err:',e.message)}
}
loadSettings();
// Auto-save BOTH settings and state every 30s (was 60s)
setInterval(()=>{saveSettings();saveState()},30000);

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
function closeTrade(t,price,reason){
  t.status='closed';t.exitPrice=price;t.closeTime=new Date().toISOString();t.reason=reason;
  const dir=t.side==='buy'?1:-1;const raw=(price-t.entryPrice)*t.qty*dir;
  t.pnl=t.type==='futures'?raw*t.leverage:raw;t.pnlPct=((t.exitPrice-t.entryPrice)/t.entryPrice*100*dir*(t.type==='futures'?t.leverage:1));
  bot.paperUSD+=t.margin+t.pnl;bot.totalPnL+=t.pnl;t.pnl>0?bot.winCount++:bot.lossCount++;
  bot.openTrades=bot.openTrades.filter(x=>x.id!==t.id);bot.history.push(t);if(bot.history.length>500)bot.history.shift();
  botLog(`CLOSE ${t.side} ${t.symbol} @$${price.toFixed(2)} | size:$${(t.usdAmount||0).toFixed(2)} | lev:${t.leverage||1}x | PnL:${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)} (${t.pnlPct.toFixed(1)}%) | ${reason}`);saveState();
}

async function liveOrder(side,sym,qty){
  if(!bot.credentials)throw new Error('No credentials');
  const{apiKey,apiSecret,passphrase}=bot.credentials;
  const ep='/api/v1/orders',body={clientOid:crypto.randomUUID(),side,symbol:sym,type:'market',size:String(qty)};
  const r=await fetch('https://api.kucoin.com'+ep,{method:'POST',headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),body:JSON.stringify(body)});
  const d=await safeJSON(r);if(d.code!=='200000')throw new Error(d.msg||'Order failed');return d.data;
}

// ═══ MULTI-TIMEFRAME ANALYSIS ═══
async function multiTimeframeAnalysis(sym){
  const [c15, c1h, c4h] = await Promise.all([
    fetchKlines(sym,'15min',100),
    fetchKlines(sym,'1hour',100),
    fetchKlines(sym,'4hour',100)
  ]);
  const a15=await analyze(c15,sym);
  const a1h=await analyze(c1h,sym);
  const a4h=await analyze(c4h,sym);
  // Determine higher timeframe bias
  let htfBias='neutral';
  if(a4h.condition.includes('bullish')&&a1h.condition.includes('bullish'))htfBias='strong_bullish';
  else if(a4h.condition.includes('bullish'))htfBias='bullish';
  else if(a4h.condition.includes('bearish')&&a1h.condition.includes('bearish'))htfBias='strong_bearish';
  else if(a4h.condition.includes('bearish'))htfBias='bearish';
  else if(a1h.condition.includes('bullish'))htfBias='mildly_bullish';
  else if(a1h.condition.includes('bearish'))htfBias='mildly_bearish';
  // Attach higher timeframe data to 15m analysis
  a15.htf={
    bias:htfBias,
    h4:{condition:a4h.condition,rsi:a4h.rsi,ema9:a4h.ema9,ema21:a4h.ema21,ema50:a4h.ema50,macdHist:a4h.macdHist,atr:a4h.atr},
    h1:{condition:a1h.condition,rsi:a1h.rsi,ema9:a1h.ema9,ema21:a1h.ema21,ema50:a1h.ema50,macdHist:a1h.macdHist,atr:a1h.atr}
  };
  return a15;
}

// ═══ BOT TICK ═══
let tickIndex=0; // rotate through symbols to avoid rate limits
async function tick(){
  try{
    await fetchNews();
    // Only scan 8 coins per tick to avoid KuCoin rate limits (30 coins / 8 = ~4 ticks to scan all)
    const batchSize=8;
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
        if(dd>=bot.maxDrawdownPct)continue;

        // Limits — reduced cooldown to 5 min
        if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<300000)continue;
        if(bot.openTrades.length>=bot.maxOpenTrades)continue;
        if(bot.openTrades.filter(t=>t.symbol===sym).length>=2)continue;

        // ═══ COUNCIL VOTE ═══
        const council=councilVote(a,bot.requiredAgents);
        bot.lastCouncil[sym]=council;
        const coin=sym.replace('-USDT','');

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

        // Auto-leverage calculation: tighter SL = higher leverage for same risk
        const slDistPct=(atr*bot.slATR)/price*100; // SL distance as % of price
        let autoLev=1;
        if(bot.tradingType!=='spot'){
          // Optimal leverage = target risk% / SL distance%
          // e.g., if risk is 2% and SL is 0.5% away, use 4x leverage
          autoLev=Math.max(1,Math.min(bot.leverage,Math.round(bot.riskPct/slDistPct)));
          // Cap at user's max leverage setting
          autoLev=Math.min(autoLev,bot.leverage);
        }

        // Position sizing with auto-leverage
        const riskUSD=bal*(bot.riskPct/100);const slDist=atr*bot.slATR;
        const posUSD=Math.min(riskUSD/(slDist/price)*autoLev,bal*0.15);
        if(posUSD<10)continue;
        const sl=council.decision==='buy'?price-slDist:price+slDist;
        const tp=council.decision==='buy'?price+atr*bot.tpATR:price-atr*bot.tpATR;
        const slPct=((slDist/price)*100).toFixed(2);

        // Execute
        if(bot.mode==='paper'){
          if(council.decision==='buy')paperBuy(sym,price,posUSD,sl,tp,council.confidence,council,'spot',autoLev);
          else if(council.decision==='sell')paperSell(sym,price,posUSD,sl,tp,council.confidence,council,autoLev);
        }else{
          // LIVE MODE — real orders with fill tracking
          try{
            const qty=(posUSD/price).toFixed(6);
            const orderResult=await liveOrder(council.decision,sym,qty);
            const orderId=orderResult.orderId;
            // Fetch actual fill details
            let fillPrice=price,fillQty=posUSD/price,fillFee=0;
            try{
              await new Promise(r=>setTimeout(r,2000)); // wait for fill
              const fillData=await fetchOrderFill(orderId);
              if(fillData){fillPrice=fillData.price;fillQty=fillData.qty;fillFee=fillData.fee}
            }catch{}
            const realUSD=fillPrice*fillQty;
            bot.openTrades.push({id:crypto.randomUUID().slice(0,8),orderId,symbol:sym,side:council.decision,type:bot.tradingType,leverage:autoLev,entryPrice:fillPrice,qty:fillQty,usdAmount:realUSD,margin:realUSD/(autoLev>1?autoLev:1),sl,tp,confidence:council.confidence,agreeing:council.agreeing,fee:fillFee,openTime:new Date().toISOString(),status:'open',highSince:fillPrice,trailingSl:bot.trailingStop?sl:null,isLive:true});
            botLog(`LIVE ${council.decision.toUpperCase()} ${sym} @$${fillPrice.toFixed(2)} | size:$${realUSD.toFixed(2)} | lev:${autoLev}x | SL:${slPct}% | ${council.agreeing}/${council.total} agents | fee:$${fillFee.toFixed(4)}`);
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
  if(Date.now()-liveBalanceCache.updated<15000)return liveBalanceCache.totalUSD; // cache 15s
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const ep='/api/v1/accounts?type=trade';
    const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
    const d=await safeJSON(r);
    if(d.code!=='200000')return liveBalanceCache.totalUSD;
    const bals={};
    for(const a of d.data){const v=parseFloat(a.available);if(v>0)bals[a.currency]=(bals[a.currency]||0)+v}
    let total=0;
    const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);
    const pm={USDT:1,USDC:1};
    if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;
    for(const[c,a]of Object.entries(bals))total+=(pm[c]||0)*a;
    liveBalanceCache={totalUSD:Math.round(total*100)/100,balances:bals,updated:Date.now()};
    return total;
  }catch{return liveBalanceCache.totalUSD}
}

// Track initial live balance for PnL calculation
function getCurBal(){
  if(bot.mode==='live')return liveBalanceCache.totalUSD||bot.startBal;
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
    settings:{riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents}
  });
});

app.post('/api/bot/settings',mw,(req,res)=>{
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
  if(s.resetPaper){bot.paperUSD=10000;bot.startBal=10000;bot.peakBal=10000;bot.openTrades=[];bot.history=[];bot.totalPnL=0;bot.winCount=0;bot.lossCount=0;botLog('Paper reset')}
  botLog('Settings updated');saveSettings();saveState();res.json({success:true});
});

app.get('/api/bot/analysis/:sym',mw,async(req,res)=>{
  try{const a=await multiTimeframeAnalysis(req.params.sym);const council=councilVote(a,bot.requiredAgents);res.json({success:true,analysis:a,council})}catch(e){res.status(500).json({error:e.message})}
});
app.get('/api/bot/news',mw,async(req,res)=>{try{const n=await fetchNews();const s=await getSentiment();res.json({success:true,articles:n.articles,coinSentiment:n.sentiment,overall:n.overall,fearGreed:s})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/bot/backtest',mw,async(req,res)=>{try{const{symbol='BTC-USDT',requiredAgents=4,periods=500}=req.body||{};res.json({success:true,result:await backtest(symbol,requiredAgents,periods)})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/bot/close/:id',mw,(req,res)=>{const t=bot.openTrades.find(x=>x.id===req.params.id);if(!t)return res.status(404).json({error:'Not found'});closeTrade(t,bot.lastAnalysis[t.symbol]?.price||t.entryPrice,'manual');res.json({success:true})});
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

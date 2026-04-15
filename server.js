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
  if(Date.now()-newsCache.updated<60000&&newsCache.updated>0)return newsCache;
  try{
    let articles=[];const seen=new Set();
    const MB=['rate cut','dovish','stimulus','qe','inflation cool','soft landing','peace','ceasefire','trade deal','dollar weak','dxy down','fed pause','liquidity','risk on','recovery','growth','surplus','jobs added','strong earnings','bull market','rally','tech boom','green energy','oil drop','de-escalation','diplomatic','agreement'];
    const MR=['rate hike','hawkish','taper','qt','recession','inflation hot','hard landing','war','attack','missile','invasion','nuclear','sanction','tariff','dollar strong','dxy up','fed tighten','risk off','default','debt ceiling','shutdown','embargo','crisis','collapse','crash','layoff','unemployment','bankruptcy','downgrade','bear market','pandemic','outbreak','conflict','escalation','strike','coup','protest','unrest','famine','drought'];

    function classify(title,body,source,url,time){
      if(!title||seen.has(title))return null;seen.add(title);
      const txt=(title+' '+(body||'')).toLowerCase();
      let s=scoreText(title+' '+(body||'').slice(0,300)),ms=0;
      for(const w of MB)if(txt.includes(w))ms+=2;
      for(const w of MR)if(txt.includes(w))ms-=2;
      const worldKeys=['fed','federal reserve','central bank','interest rate','inflation','gdp','economy','geopolit','war','iran','israel','china','russia','ukraine','trump','biden','congress','senate','tariff','sanction','opec','oil','gold','dollar','treasury','bond','imf','world bank','nato','military','attack','election','trade war','debt','deficit','employment','jobs','cpi','ppi','fomc','g7','g20','brics','eu ','european','japan','korea','india','pakistan','middle east','gaza','taiwan','syria','yemen','africa','climate','energy','commodity','wheat','food','shipping','suez','semiconductor','chip','ai regulation'];
      const isWorld=worldKeys.some(w=>txt.includes(w));
      s+=ms;
      return{title,source,url,time,body:(body||'').slice(0,200),score:s,macroScore:ms,type:isWorld||ms!==0?'world':'crypto'};
    }

    // 1. Crypto news
    try{const r=await fetch('https://min-api.cryptocompare.com/data/v2/news/?lang=EN&sortOrder=latest');const d=await safeJSON(r);if(d.Data)for(const a of d.Data.slice(0,25)){const x=classify(a.title,a.body,a.source,a.url,a.published_on*1000);if(x)articles.push(x)}}catch{}

    // 2. Regulation/Fiat news
    try{const r=await fetch('https://min-api.cryptocompare.com/data/v2/news/?lang=EN&categories=regulation,fiat,exchange,mining&sortOrder=latest');const d=await safeJSON(r);if(d.Data)for(const a of d.Data.slice(0,15)){const x=classify(a.title,a.body,a.source,a.url,a.published_on*1000);if(x)articles.push(x)}}catch{}

    // 3. World news from RSS feeds
    const feeds=[
      'https://feeds.bbci.co.uk/news/business/rss.xml',
      'https://feeds.bbci.co.uk/news/world/rss.xml',
      'https://www.cnbc.com/id/100003114/device/rss/rss.html',
      'https://rss.nytimes.com/services/xml/rss/nyt/Business.xml',
      'https://rss.nytimes.com/services/xml/rss/nyt/World.xml',
      'https://feeds.reuters.com/reuters/businessNews',
      'https://feeds.reuters.com/reuters/worldNews',
      'https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx6TVdZU0FtVnVHZ0pWVXlnQVAB'
    ];
    for(const feed of feeds){try{const r=await fetch('https://api.rss2json.com/v1/api.json?rss_url='+encodeURIComponent(feed));const d=await safeJSON(r);if(d.items)for(const i of d.items.slice(0,6)){const t=i.pubDate?new Date(i.pubDate).getTime():Date.now();const x=classify(i.title,i.description||'',d.feed?.title||'News',i.link,t);if(x)articles.push(x)}}catch{}}

    articles.sort((a,b)=>b.time-a.time);

    // Coin sentiment
    const cs={};
    for(const[sym,name]of Object.entries(COINS_MAP)){const rel=articles.filter(a=>(a.title+' '+a.body).toLowerCase().includes(name)||a.title.toLowerCase().includes(sym.toLowerCase()));if(rel.length)cs[sym]={score:Math.round(rel.reduce((s,a)=>s+a.score,0)/rel.length*100)/100,n:rel.length,bias:rel.reduce((s,a)=>s+a.score,0)/rel.length>0.5?'bullish':rel.reduce((s,a)=>s+a.score,0)/rel.length<-0.5?'bearish':'neutral'}}

    const worldA=articles.filter(a=>a.type==='world'),cryptoA=articles.filter(a=>a.type==='crypto');
    const as=articles.reduce((s,a)=>s+a.score,0)/Math.max(articles.length,1);
    const wa=worldA.length?worldA.reduce((s,a)=>s+a.score,0)/worldA.length:0;

    newsCache={articles,sentiment:cs,overall:{score:Math.round(as*100)/100,bias:as>0.3?'bullish':as<-0.3?'bearish':'neutral',macroScore:Math.round(wa*100)/100,macroBias:wa>0.3?'bullish':wa<-0.3?'bearish':'neutral',worldCount:worldA.length,cryptoCount:cryptoA.length},updated:Date.now()};
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
  const volTrend=TA.volTrend(v),sentiment=await getSentiment(),news=await fetchNews();
  const coin=sym.split('-')[0],coinNews=news.sentiment[coin]||{score:0,n:0,bias:'neutral'};
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
  // Agent 1: Trend Master — EMA alignment + ADX
  trend_master(a){
    if(!a.ema9||!a.ema21||a.adx===null)return{vote:'hold',confidence:0,reason:'no data'};
    const strong=a.adx>25;
    // BUY conditions
    if(a.ema9>a.ema21&&a.ema21>a.ema50&&strong)return{vote:'buy',confidence:90,reason:'strong uptrend, EMAs aligned'};
    if(a.ema9>a.ema21&&a.ema21>a.ema50)return{vote:'buy',confidence:65,reason:'uptrend'};
    if(a.ema9>a.ema21)return{vote:'buy',confidence:45,reason:'mild uptrend'};
    // SELL conditions (mirrored)
    if(a.ema9<a.ema21&&a.ema21<a.ema50&&strong)return{vote:'sell',confidence:90,reason:'strong downtrend, EMAs aligned'};
    if(a.ema9<a.ema21&&a.ema21<a.ema50)return{vote:'sell',confidence:65,reason:'downtrend'};
    if(a.ema9<a.ema21)return{vote:'sell',confidence:45,reason:'mild downtrend'};
    return{vote:'hold',confidence:0,reason:'no clear trend'};
  },

  // Agent 2: Momentum Hunter — RSI + StochRSI
  momentum_hunter(a){
    if(a.rsi===null||a.stochK===null)return{vote:'hold',confidence:0,reason:'no data'};
    // BUY: oversold
    if(a.rsi<30&&a.stochK<20)return{vote:'buy',confidence:85,reason:'deeply oversold RSI:'+a.rsi.toFixed(0)};
    if(a.rsi<40&&a.stochK<30&&a.stochK>a.stochD)return{vote:'buy',confidence:65,reason:'oversold, StochRSI turning up'};
    if(a.rsi<45&&a.prevRsi&&a.rsi>a.prevRsi)return{vote:'buy',confidence:45,reason:'RSI rising from low'};
    // SELL: overbought (mirrored thresholds)
    if(a.rsi>70&&a.stochK>80)return{vote:'sell',confidence:85,reason:'deeply overbought RSI:'+a.rsi.toFixed(0)};
    if(a.rsi>60&&a.stochK>70&&a.stochK<a.stochD)return{vote:'sell',confidence:65,reason:'overbought, StochRSI turning down'};
    if(a.rsi>55&&a.prevRsi&&a.rsi<a.prevRsi)return{vote:'sell',confidence:45,reason:'RSI falling from high'};
    return{vote:'hold',confidence:0,reason:'neutral momentum'};
  },

  // Agent 3: MACD Specialist — MACD crossovers + histogram
  macd_specialist(a){
    if(a.macdHist===null||a.prevMacdHist===null)return{vote:'hold',confidence:0,reason:'no data'};
    const crossUp=a.macdHist>0&&a.prevMacdHist<=0;
    const crossDn=a.macdHist<0&&a.prevMacdHist>=0;
    const growing=Math.abs(a.macdHist)>Math.abs(a.prevMacdHist);
    // BUY
    if(crossUp)return{vote:'buy',confidence:growing?85:70,reason:'MACD bullish cross'+(growing?' +growing':'')};
    if(a.macdHist>0&&growing)return{vote:'buy',confidence:50,reason:'MACD positive growing'};
    // SELL (mirrored)
    if(crossDn)return{vote:'sell',confidence:growing?85:70,reason:'MACD bearish cross'+(growing?' +growing':'')};
    if(a.macdHist<0&&growing)return{vote:'sell',confidence:50,reason:'MACD negative growing'};
    // Divergence hints
    if(a.macdHist<0&&!growing&&a.prevMacdHist<a.macdHist)return{vote:'buy',confidence:40,reason:'MACD neg but recovering'};
    if(a.macdHist>0&&!growing&&a.prevMacdHist>a.macdHist)return{vote:'sell',confidence:40,reason:'MACD pos but weakening'};
    return{vote:'hold',confidence:0,reason:'MACD neutral'};
  },

  // Agent 4: Fibonacci Analyst
  fibonacci_analyst(a){
    if(!a.fib||!a.price||!a.atr)return{vote:'hold',confidence:0,reason:'no data'};
    const distSup=Math.abs(a.price-a.support)/a.price*100;
    const distRes=Math.abs(a.resistance-a.price)/a.price*100;
    // BUY near support
    if(a.inGoldenPocket&&a.rsi<55)return{vote:'buy',confidence:80,reason:'golden pocket zone'};
    if(distSup<0.5)return{vote:'buy',confidence:70,reason:'at fib support'};
    if(distSup<1.5&&a.rsi<50)return{vote:'buy',confidence:50,reason:'near fib support'};
    // SELL near resistance (mirrored)
    if(distRes<0.5)return{vote:'sell',confidence:70,reason:'at fib resistance'};
    if(distRes<1.5&&a.rsi>50)return{vote:'sell',confidence:50,reason:'near fib resistance'};
    if(a.price>a.fib.high*0.98)return{vote:'sell',confidence:60,reason:'near recent high'};
    return{vote:'hold',confidence:0,reason:'between levels'};
  },

  // Agent 5: Volume Expert — OBV + VWAP
  volume_expert(a){
    if(!a.vwap||!a.price)return{vote:'hold',confidence:0,reason:'no data'};
    let score=0,reasons=[];
    if(a.obvTrend==='bullish'){score+=25;reasons.push('OBV+')}
    if(a.obvTrend==='bearish'){score-=25;reasons.push('OBV-')}
    if(a.volTrend==='high'){const dir=score>=0?1:-1;score+=15*dir;reasons.push('high vol')}
    if(a.price>a.vwap*1.005){score+=15;reasons.push('>VWAP')}
    if(a.price<a.vwap*0.995){score-=15;reasons.push('<VWAP')}
    if(score>=30)return{vote:'buy',confidence:55+Math.min(score-30,30),reason:reasons.join(', ')};
    if(score<=-30)return{vote:'sell',confidence:55+Math.min(Math.abs(score)-30,30),reason:reasons.join(', ')};
    if(score>=15)return{vote:'buy',confidence:40,reason:reasons.join(', ')};
    if(score<=-15)return{vote:'sell',confidence:40,reason:reasons.join(', ')};
    return{vote:'hold',confidence:0,reason:'volume neutral'};
  },

  // Agent 6: Bollinger Trader
  bollinger_trader(a){
    if(!a.bbUpper||!a.bbLower||!a.price)return{vote:'hold',confidence:0,reason:'no data'};
    const pos=(a.price-a.bbLower)/(a.bbUpper-a.bbLower);
    // BUY at lower band
    if(pos<0.1)return{vote:'buy',confidence:80,reason:'at lower BB ('+Math.round(pos*100)+'%)'};
    if(pos<0.25)return{vote:'buy',confidence:55,reason:'near lower BB'};
    // SELL at upper band (mirrored)
    if(pos>0.9)return{vote:'sell',confidence:80,reason:'at upper BB ('+Math.round(pos*100)+'%)'};
    if(pos>0.75)return{vote:'sell',confidence:55,reason:'near upper BB'};
    return{vote:'hold',confidence:0,reason:'mid BB ('+Math.round(pos*100)+'%)'};
  },

  // Agent 7: Sentiment & News (including world/macro)
  sentiment_analyst(a){
    if(!a.sentiment||!a.news)return{vote:'hold',confidence:0,reason:'No sentiment data available'};
    let score=0,reasons=[];
    const fg=a.sentiment.value;
    if(fg<20){score+=35;reasons.push('Extreme fear index ('+fg+') — historically a contrarian buy signal, smart money buys when others panic')}
    else if(fg<35){score+=20;reasons.push('Fear zone (F&G:'+fg+') — market is scared, potential buying opportunity')}
    else if(fg>80){score-=35;reasons.push('Extreme greed ('+fg+') — market is euphoric, historically precedes corrections')}
    else if(fg>65){score-=20;reasons.push('Greed zone (F&G:'+fg+') — caution, market may be overheated')}
    else{reasons.push('Fear & Greed neutral at '+fg)}
    const cn=a.news.coin;
    if(cn&&cn.bias==='bullish'){score+=20;reasons.push('Coin-specific news is bullish ('+cn.n+' articles, score:'+cn.score+')')}
    if(cn&&cn.bias==='bearish'){score-=20;reasons.push('Coin-specific news is bearish ('+cn.n+' articles, score:'+cn.score+')')}
    const ov=a.news.overall;
    if(ov&&ov.bias==='bullish'){score+=10;reasons.push('Overall market news positive')}
    if(ov&&ov.bias==='bearish'){score-=10;reasons.push('Overall market news negative')}
    if(ov&&ov.macroBias==='bullish'){score+=15;reasons.push('World/macro news bullish — favorable for risk assets')}
    if(ov&&ov.macroBias==='bearish'){score-=15;reasons.push('World/macro news bearish — risk-off environment')}
    if(score>=25)return{vote:'buy',confidence:50+Math.min(score-25,35),reason:reasons.join('. ')};
    if(score<=-25)return{vote:'sell',confidence:50+Math.min(Math.abs(score)-25,35),reason:reasons.join('. ')};
    return{vote:'hold',confidence:0,reason:reasons.join('. ')};
  },

  // Agent 8: Quant AI — Statistical analysis, z-score, rate of change, mean reversion
  quant_ai(a){
    if(!a.price||!a.ema21||!a.atr||!a.bbUpper||!a.bbLower||a.rsi===null)return{vote:'hold',confidence:0,reason:'no data'};

    let score=0,reasons=[];

    // Z-score: how many std devs from BB mean
    const bbMid=a.bbSma||(a.bbUpper+a.bbLower)/2;
    const bbStd=(a.bbUpper-a.bbLower)/4; // approx 2 std = BB width
    const zScore=bbStd>0?(a.price-bbMid)/bbStd:0;

    if(zScore<-1.5){score+=30;reasons.push('z-score:'+zScore.toFixed(1)+' (undervalued)')}
    else if(zScore<-0.8){score+=15;reasons.push('z:'+zScore.toFixed(1))}
    else if(zScore>1.5){score-=30;reasons.push('z-score:'+zScore.toFixed(1)+' (overvalued)')}
    else if(zScore>0.8){score-=15;reasons.push('z:'+zScore.toFixed(1))}

    // Rate of change (price vs EMA21)
    const roc=((a.price-a.ema21)/a.ema21)*100;
    if(roc<-3){score+=20;reasons.push('ROC:-'+Math.abs(roc).toFixed(1)+'% (oversold vs EMA)')}
    else if(roc<-1.5){score+=10;reasons.push('ROC:'+roc.toFixed(1)+'%')}
    else if(roc>3){score-=20;reasons.push('ROC:+'+roc.toFixed(1)+'% (overbought vs EMA)')}
    else if(roc>1.5){score-=10;reasons.push('ROC:+'+roc.toFixed(1)+'%')}

    // RSI divergence detection
    if(a.rsi>70&&roc<0){score-=15;reasons.push('bearish RSI divergence')}
    if(a.rsi<30&&roc>0){score+=15;reasons.push('bullish RSI divergence')}

    // Volatility regime (high ATR = mean reversion more likely)
    const atrPct=(a.atr/a.price)*100;
    if(atrPct>2&&zScore>1){score-=10;reasons.push('high vol + extended = revert down')}
    if(atrPct>2&&zScore<-1){score+=10;reasons.push('high vol + depressed = revert up')}

    // Price vs VWAP momentum
    if(a.vwap){
      const vwapDist=((a.price-a.vwap)/a.vwap)*100;
      if(vwapDist<-1){score+=10;reasons.push('below VWAP')}
      if(vwapDist>1){score-=10;reasons.push('above VWAP')}
    }

    if(score>=25)return{vote:'buy',confidence:50+Math.min(score-25,40),reason:reasons.join(', ')};
    if(score<=-25)return{vote:'sell',confidence:50+Math.min(Math.abs(score)-25,40),reason:reasons.join(', ')};
    if(score>=10)return{vote:'buy',confidence:35,reason:reasons.join(', ')};
    if(score<=-10)return{vote:'sell',confidence:35,reason:reasons.join(', ')};
    return{vote:'hold',confidence:0,reason:'quant neutral (z:'+zScore.toFixed(1)+' roc:'+roc.toFixed(1)+'%)'};
  },

  // Agent 9: ATR Volatility Specialist — volatility breakouts, squeeze, expansion
  atr_volatility(a){
    if(!a.atr||!a.price||!a.bbUpper||!a.bbLower)return{vote:'hold',confidence:0,reason:'no ATR data'};
    const atrPct=(a.atr/a.price)*100;
    const bbWidth=((a.bbUpper-a.bbLower)/a.bbSma)*100;
    let score=0,reasons=[];

    // ATR expansion/contraction
    reasons.push('ATR: $'+a.atr.toFixed(2)+' ('+atrPct.toFixed(2)+'% of price)');

    // Volatility squeeze (low ATR + tight BB = breakout coming)
    if(atrPct<1&&bbWidth<3){
      // Squeeze detected — direction from trend
      if(a.ema9>a.ema21){score+=25;reasons.push('SQUEEZE detected — EMAs bullish, expect upside breakout')}
      else if(a.ema9<a.ema21){score-=25;reasons.push('SQUEEZE detected — EMAs bearish, expect downside breakout')}
      else{reasons.push('SQUEEZE detected — waiting for direction')}
    }

    // High volatility + overextension = mean reversion
    if(atrPct>3){
      const bbPos=(a.price-a.bbLower)/(a.bbUpper-a.bbLower);
      if(bbPos>0.85){score-=30;reasons.push('HIGH volatility + price at top of range — likely pullback')}
      else if(bbPos<0.15){score+=30;reasons.push('HIGH volatility + price at bottom — likely bounce')}
      else{reasons.push('HIGH volatility — choppy, be careful')}
    }

    // ATR relative to price movement
    if(a.ema9&&a.ema21){
      const emaDist=Math.abs(a.ema9-a.ema21);
      const atrRatio=emaDist/a.atr;
      if(atrRatio>2&&a.ema9>a.ema21){score+=15;reasons.push('strong trend move ('+atrRatio.toFixed(1)+'x ATR separation)')}
      if(atrRatio>2&&a.ema9<a.ema21){score-=15;reasons.push('strong down move ('+atrRatio.toFixed(1)+'x ATR separation)')}
    }

    // Normal volatility — use ATR for stop placement quality
    if(atrPct>=1&&atrPct<=3){
      reasons.push('normal volatility — good for trading');
      // In normal vol, follow the trend
      if(a.condition&&a.condition.includes('bullish')){score+=10;reasons.push('trend is up')}
      if(a.condition&&a.condition.includes('bearish')){score-=10;reasons.push('trend is down')}
    }

    if(score>=20)return{vote:'buy',confidence:50+Math.min(score-20,35),reason:reasons.join('. ')};
    if(score<=-20)return{vote:'sell',confidence:50+Math.min(Math.abs(score)-20,35),reason:reasons.join('. ')};
    return{vote:'hold',confidence:0,reason:reasons.join('. ')};
  }
};

// ═══ COUNCIL VOTE (fixed: buy and sell are independent) ═══
function councilVote(a,requiredAgree=4){
  const votes={};
  for(const[name,fn]of Object.entries(AGENTS))votes[name]=fn(a);
  const buys=Object.entries(votes).filter(([_,v])=>v.vote==='buy');
  const sells=Object.entries(votes).filter(([_,v])=>v.vote==='sell');
  const buyConf=buys.length?Math.round(buys.reduce((s,[_,v])=>s+v.confidence,0)/buys.length):0;
  const sellConf=sells.length?Math.round(sells.reduce((s,[_,v])=>s+v.confidence,0)/sells.length):0;

  // In bearish conditions, lower sell threshold
  let buyReq=requiredAgree,sellReq=requiredAgree;
  if(a.condition&&a.condition.includes('bearish'))sellReq=Math.max(2,requiredAgree-1);
  if(a.condition&&a.condition.includes('bullish'))buyReq=Math.max(2,requiredAgree-1);

  let decision='hold',conf=0,agreeing=0;

  // BUY and SELL are evaluated INDEPENDENTLY
  // If both meet threshold, higher confidence wins
  const buyMet=buys.length>=buyReq;
  const sellMet=sells.length>=sellReq;

  if(buyMet&&sellMet){
    // Both met — go with higher confidence
    if(sellConf>=buyConf){decision='sell';conf=sellConf;agreeing=sells.length}
    else{decision='buy';conf=buyConf;agreeing=buys.length}
  }else if(buyMet){
    decision='buy';conf=buyConf;agreeing=buys.length;
  }else if(sellMet){
    decision='sell';conf=sellConf;agreeing=sells.length;
  }

  // Bonus for strong agreement
  if(agreeing>=7)conf=Math.min(conf+20,100);
  else if(agreeing>=6)conf=Math.min(conf+15,100);
  else if(agreeing>=5)conf=Math.min(conf+10,100);

  return{decision,confidence:conf,agreeing,total:Object.keys(AGENTS).length,votes,buyCount:buys.length,sellCount:sells.length,buyReq,sellReq};
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
    console.log('Settings loaded from disk')}}catch(e){console.log('No saved settings')}
  try{if(fs.existsSync(STATE_FILE)){const s=JSON.parse(fs.readFileSync(STATE_FILE,'utf8'));
    if(s.paperUSD!==undefined)bot.paperUSD=s.paperUSD;if(s.startBal)bot.startBal=s.startBal;
    if(s.peakBal)bot.peakBal=s.peakBal;if(s.totalPnL!==undefined)bot.totalPnL=s.totalPnL;
    if(s.winCount!==undefined)bot.winCount=s.winCount;if(s.lossCount!==undefined)bot.lossCount=s.lossCount;
    if(s.history)bot.history=s.history;if(s.openTrades)bot.openTrades=s.openTrades;
    console.log('State loaded from disk')}}catch(e){console.log('No saved state')}
}
function saveSettings(){
  try{fs.writeFileSync(SETTINGS_FILE,JSON.stringify({mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents,riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,credentials:bot.credentials}))}catch(e){console.log('Save settings err:',e.message)}
}
function saveState(){
  try{fs.writeFileSync(STATE_FILE,JSON.stringify({paperUSD:bot.paperUSD,startBal:bot.startBal,peakBal:bot.peakBal,totalPnL:bot.totalPnL,winCount:bot.winCount,lossCount:bot.lossCount,history:bot.history.slice(-200),openTrades:bot.openTrades}))}catch(e){console.log('Save state err:',e.message)}
}
loadSettings(); // load on startup
// Auto-save state every 60s
setInterval(saveState,60000);

function botLog(m){const e={time:new Date().toISOString(),msg:m};bot.log.push(e);if(bot.log.length>500)bot.log.shift();console.log('[BOT]',m)}

// ═══ FETCH CANDLES ═══
async function fetchKlines(sym,type='15min',limit=100){
  const end=Math.floor(Date.now()/1000),mins={'1min':1,'5min':5,'15min':15,'1hour':60,'4hour':240}[type]||15;
  const r=await fetch(`https://api.kucoin.com/api/v1/market/candles?type=${type}&symbol=${sym}&startAt=${end-limit*mins*60}&endAt=${end}`);
  const d=await safeJSON(r);if(d.code!=='200000'||!d.data)throw new Error('Candle fetch failed for '+sym);
  return d.data.reverse().map(c=>({time:+c[0]*1000,open:+c[1],close:+c[2],high:+c[3],low:+c[4],volume:+c[5]}));
}

// ═══ TRADE EXECUTION ═══
function paperBuy(sym,price,usd,sl,tp,conf,council,type='spot'){
  const qty=usd/price,lev=type==='futures'?bot.leverage:1,margin=type==='futures'?usd/lev:usd;
  bot.paperUSD-=margin;
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'buy',type,leverage:lev,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,agreeing:council.agreeing,trailingSl:bot.trailingStop?sl:null,highSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`BUY ${sym} @$${price.toFixed(2)} | ${council.agreeing}/${council.total} agents agree | conf:${conf}% | SL:$${sl.toFixed(2)} TP:$${tp.toFixed(2)}`);return t;
}
function paperSell(sym,price,usd,sl,tp,conf,council){
  const qty=usd/price,margin=usd/bot.leverage;bot.paperUSD-=margin;
  const t={id:crypto.randomUUID().slice(0,8),symbol:sym,side:'sell',type:'futures',leverage:bot.leverage,entryPrice:price,qty,usdAmount:usd,margin,sl,tp,confidence:conf,agreeing:council.agreeing,trailingSl:bot.trailingStop?sl:null,lowSince:price,openTime:new Date().toISOString(),status:'open'};
  bot.openTrades.push(t);botLog(`SHORT ${sym} @$${price.toFixed(2)} | ${council.agreeing}/${council.total} agents agree | conf:${conf}%`);return t;
}
function closeTrade(t,price,reason){
  t.status='closed';t.exitPrice=price;t.closeTime=new Date().toISOString();t.reason=reason;
  const dir=t.side==='buy'?1:-1;const raw=(price-t.entryPrice)*t.qty*dir;
  t.pnl=t.type==='futures'?raw*t.leverage:raw;t.pnlPct=((t.exitPrice-t.entryPrice)/t.entryPrice*100*dir*(t.type==='futures'?t.leverage:1));
  bot.paperUSD+=t.margin+t.pnl;bot.totalPnL+=t.pnl;t.pnl>0?bot.winCount++:bot.lossCount++;
  bot.openTrades=bot.openTrades.filter(x=>x.id!==t.id);bot.history.push(t);if(bot.history.length>500)bot.history.shift();
  botLog(`CLOSE ${t.side} ${t.symbol} @$${price.toFixed(2)} | PnL:${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)} (${t.pnlPct.toFixed(1)}%) | ${reason}`);saveState();
}

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
    await fetchNews(); // refresh news
    for(const sym of bot.symbols){
      try{
        const candles=await fetchKlines(sym,'15min',100);
        const a=await analyze(candles,sym);bot.lastAnalysis[sym]=a;
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

        // Drawdown
        const bal=getCurBal();if(bal>bot.peakBal)bot.peakBal=bal;
        const dd=((bot.peakBal-bal)/bot.peakBal)*100;
        if(dd>=bot.maxDrawdownPct)continue;

        // Limits
        if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<600000)continue;
        if(bot.openTrades.length>=bot.maxOpenTrades)continue;
        if(bot.openTrades.filter(t=>t.symbol===sym).length>=2)continue;

        // ═══ COUNCIL VOTE ═══
        const council=councilVote(a,bot.requiredAgents);
        bot.lastCouncil[sym]=council;
        // Log significant sell signals even if not enough agree yet
        if(council.sellCount>=2&&council.decision==='hold'){
          botLog(`${sym.replace('-USDT','')} ${council.buyCount}buy/${council.sellCount}sell (need ${council.sellReq}) — watching`);
        }
        if(council.decision==='hold')continue;
        if(council.confidence<50)continue;

        // Position sizing
        const riskUSD=bal*(bot.riskPct/100);const slDist=atr*bot.slATR;
        const posUSD=Math.min(riskUSD/(slDist/price),bal*0.15);
        if(posUSD<10)continue;
        const sl=council.decision==='buy'?price-slDist:price+slDist;
        const tp=council.decision==='buy'?price+atr*bot.tpATR:price-atr*bot.tpATR;

        // Execute
        if(bot.mode==='paper'){
          if(council.decision==='buy')paperBuy(sym,price,posUSD,sl,tp,council.confidence,council,bot.tradingType==='spot'?'spot':'spot');
          else if(council.decision==='sell')paperSell(sym,price,posUSD,sl,tp,council.confidence,council);
        }else{
          try{await liveOrder(council.decision,sym,(posUSD/price).toFixed(6));
            bot.openTrades.push({id:crypto.randomUUID().slice(0,8),symbol:sym,side:council.decision,type:bot.tradingType,leverage:bot.tradingType==='futures'?bot.leverage:1,entryPrice:price,qty:posUSD/price,usdAmount:posUSD,margin:posUSD,sl,tp,confidence:council.confidence,agreeing:council.agreeing,openTime:new Date().toISOString(),status:'open',highSince:price,trailingSl:bot.trailingStop?sl:null});
            botLog(`LIVE ${council.decision.toUpperCase()} ${sym} @$${price.toFixed(2)} | ${council.agreeing}/${council.total} agents`);
          }catch(e){botLog(`ORDER ERR ${sym}: ${e.message}`)}
        }
        bot.cooldown[sym]=Date.now();
      }catch(e){/* skip coin */}
    }
  }catch(e){botLog(`TICK ERROR: ${e.message}`)}
}

function getCurBal(){
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
    if(council.decision==='hold'||council.confidence<50)continue;
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

app.get('/api/bot/status',mw,(req,res)=>{
  const bal=getCurBal(),dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0,tot=bot.winCount+bot.lossCount;
  res.json({running:bot.running,mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,leverage:bot.leverage,
    balance:Math.round(bal*100)/100,startBal:bot.startBal,totalPnL:Math.round(bot.totalPnL*100)/100,
    totalPnLPct:bot.startBal>0?Math.round((bal-bot.startBal)/bot.startBal*10000)/100:0,
    winCount:bot.winCount,lossCount:bot.lossCount,winRate:tot>0?Math.round(bot.winCount/tot*10000)/100:0,
    drawdown:Math.round(dd*100)/100,requiredAgents:bot.requiredAgents,totalAgents:Object.keys(AGENTS).length,
    openTrades:bot.openTrades.map(t=>{const cp=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;const dir=t.side==='buy'?1:-1;return{...t,currentPrice:cp,unrealizedPnl:Math.round((cp-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)*100)/100}}),
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
  try{const candles=await fetchKlines(req.params.sym,'15min',100);const a=await analyze(candles,req.params.sym);const council=councilVote(a,bot.requiredAgents);res.json({success:true,analysis:a,council})}catch(e){res.status(500).json({error:e.message})}
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

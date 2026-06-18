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
app.post('/api/auth/reset',(req,res)=>{const{email}=req.body||{};if(!email)return res.status(400).json({error:'Email required'});if(AUTH.email&&email!==AUTH.email)return res.status(400).json({error:'Email does not match'});AUTH={email:null,password:null,tokens:[]};saveAuth();res.json({success:true,message:'Account reset. You can create a new one.'})});

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
  volTrend(v,p=20){if(v.length<p)return'normal';const rec=v.slice(-5).reduce((a,b)=>a+b,0)/5,avg=v.slice(-p).reduce((a,b)=>a+b,0)/p;return rec>avg*1.5?'high':rec<avg*0.5?'low':'normal'},
  // ═══ EXTENDED INDICATORS ═══
  choppiness(h,l,c,p=14){
    // Choppiness Index: <38=trending, >61=ranging
    if(h.length<p+1)return[];const atr=TA.atr(h,l,c,1);const res=[];
    for(let i=p;i<c.length;i++){
      const sumATR=atr.slice(i-p,i).reduce((a,b)=>a+b,0);
      const hh=Math.max(...h.slice(i-p,i));const ll=Math.min(...l.slice(i-p,i));
      const range=hh-ll;
      res.push(range>0?100*Math.log10(sumATR/range)/Math.log10(p):50);
    }
    return res;
  },
  pivotPoints(h,l,c){
    // Classic pivot points from last candle
    const i=c.length-2;if(i<0)return{pp:0,r1:0,r2:0,s1:0,s2:0};
    const pp=(h[i]+l[i]+c[i])/3;
    return{pp,r1:2*pp-l[i],r2:pp+(h[i]-l[i]),s1:2*pp-h[i],s2:pp-(h[i]-l[i])};
  },
  higherHighsLows(h,l,lookback=10){
    // Count higher highs and higher lows
    if(h.length<lookback)return{hh:0,hl:0,lh:0,ll:0,trend:'unclear'};
    let hh=0,hl=0,lh=0,ll=0;
    const start=h.length-lookback;
    for(let i=start+2;i<h.length;i+=2){
      if(h[i]>h[i-2])hh++;else lh++;
      if(l[i]>l[i-2])hl++;else ll++;
    }
    const trend=hh>lh&&hl>ll?'uptrend':lh>hh&&ll>hl?'downtrend':'unclear';
    return{hh,hl,lh,ll,trend};
  },
  trendSlope(c,p=20){
    // Linear regression slope of close prices
    if(c.length<p)return 0;
    const recent=c.slice(-p);const n=recent.length;
    const xMean=(n-1)/2;const yMean=recent.reduce((a,b)=>a+b,0)/n;
    let num=0,den=0;
    for(let i=0;i<n;i++){num+=(i-xMean)*(recent[i]-yMean);den+=(i-xMean)**2}
    return den>0?(num/den)/yMean*100:0; // % slope per candle
  },
  candlePatterns(o,h,l,c){
    // Detect key candlestick patterns on last 3 candles
    const n=c.length;if(n<3)return[];
    const patterns=[];
    const i=n-1;const body=Math.abs(c[i]-o[i]);const range=h[i]-l[i];
    const prevBody=Math.abs(c[i-1]-o[i-1]);const prevRange=h[i-1]-l[i-1];
    const isGreen=c[i]>o[i];const prevGreen=c[i-1]>o[i-1];
    const upperWick=isGreen?h[i]-c[i]:h[i]-o[i];
    const lowerWick=isGreen?o[i]-l[i]:c[i]-l[i];

    // Doji: tiny body, equal wicks
    if(range>0&&body/range<0.1)patterns.push('doji');
    // Hammer: small body at top, long lower wick (bullish reversal)
    if(range>0&&lowerWick>body*2&&upperWick<body*0.5)patterns.push('hammer');
    // Shooting star: small body at bottom, long upper wick (bearish reversal)
    if(range>0&&upperWick>body*2&&lowerWick<body*0.5)patterns.push('shooting_star');
    // Bullish engulfing
    if(isGreen&&!prevGreen&&c[i]>o[i-1]&&o[i]<c[i-1]&&body>prevBody)patterns.push('bullish_engulfing');
    // Bearish engulfing
    if(!isGreen&&prevGreen&&c[i]<o[i-1]&&o[i]>c[i-1]&&body>prevBody)patterns.push('bearish_engulfing');
    // Inside bar
    if(h[i]<h[i-1]&&l[i]>l[i-1])patterns.push('inside_bar');
    // Three green/red soldiers
    if(n>=3&&c[i]>o[i]&&c[i-1]>o[i-1]&&c[i-2]>o[i-2])patterns.push('three_green');
    if(n>=3&&c[i]<o[i]&&c[i-1]<o[i-1]&&c[i-2]<o[i-2])patterns.push('three_red');
    // Pin bar (long wick rejection)
    if(range>0&&(lowerWick>range*0.6||upperWick>range*0.6))patterns.push(lowerWick>upperWick?'pin_bar_bull':'pin_bar_bear');
    return patterns;
  },
  consecutiveCandles(o,c,lookback=5){
    const n=c.length;let green=0,red=0;
    for(let i=n-1;i>=Math.max(0,n-lookback);i--){
      if(c[i]>o[i]){if(red>0)break;green++}
      else{if(green>0)break;red++}
    }
    return{green,red};
  }
};

// ═══ NEWS + SENTIMENT ═══
let sentimentCache={value:50,label:'Neutral',updated:0};
let newsCache={articles:[],sentiment:{},overall:{score:0,bias:'neutral'},updated:0};
const BULL=['surge','rally','bullish','breakout','soar','pump','ath','gain','rise','jump','adoption','approval','etf','institutional','upgrade','partnership','launch','record','optimistic','growth','recovery','accumulate'];
const BEAR=['crash','dump','bearish','plunge','drop','fall','hack','ban','fraud','scam','regulation','crackdown','lawsuit','fine','risk','warning','decline','panic','correction','collapse','bankrupt','shutdown'];
const COINS_MAP={BTC:'bitcoin',ETH:'ethereum',SOL:'solana',XRP:'ripple',ADA:'cardano',DOGE:'dogecoin',DOT:'polkadot',LINK:'chainlink',AVAX:'avalanche',BNB:'binance',SHIB:'shiba',UNI:'uniswap',ATOM:'cosmos',LTC:'litecoin',FIL:'filecoin',NEAR:'near',APT:'aptos',ARB:'arbitrum',OP:'optimism',SUI:'sui',SEI:'sei',INJ:'injective',FET:'fetch',RENDER:'render',PEPE:'pepe',WIF:'dogwifhat',BONK:'bonk',FLOKI:'floki',TIA:'celestia',AAVE:'aave',XLM:'stellar',HBAR:'hedera',VET:'vechain',GRT:'graph',STX:'stacks',IMX:'immutable',JASMY:'jasmy',ALGO:'algorand',SAND:'sandbox',MANA:'decentraland',CRV:'curve',ONDO:'ondo',JUP:'jupiter',PENDLE:'pendle',KAS:'kaspa',RUNE:'thorchain',DYDX:'dydx'};
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
        if(d.Data){const articles_arr=Array.isArray(d.Data)?d.Data:d.Data.Data||Object.values(d.Data);if(Array.isArray(articles_arr))for(const a of articles_arr.slice(0,15)){const x=classify(a.title,a.body,a.source,a.url,(a.published_on||0)*1000);if(x)articles.push(x)}}
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

  // Extended indicators
  const o=candles.map(x=>x.open||x.close); // open prices
  const chop=TA.choppiness(h,l,c);const chopVal=chop.length?chop[chop.length-1]:50;
  const pivots=TA.pivotPoints(h,l,c);
  const hhll=TA.higherHighsLows(h,l);
  const slope=TA.trendSlope(c);
  const patterns=TA.candlePatterns(o,h,l,c);
  const consecutive=TA.consecutiveCandles(o,c);

  // BTC CORRELATION
  let btcContext=null;
  if(coin!=='BTC'&&btcAnalysisCache&&Date.now()-btcAnalysisCache.time<600000){
    btcContext={condition:btcAnalysisCache.condition,rsi:btcAnalysisCache.rsi,priceChange1h:btcAnalysisCache.priceChange1h,priceChange4h:btcAnalysisCache.priceChange4h,trendStrength:btcAnalysisCache.trendStrength};
  }

  return{price:L(c),condition:cond,trendStrength:ts,ema9:e9,ema21:e21,ema50:e50,rsi:r,prevRsi:P(rsi),atr:L(atr),macdLine:L(macd.line),macdSignal:L(macd.signal),macdHist:L(macd.hist),prevMacdHist:P(macd.hist),bbUpper:L(bb.upper),bbLower:L(bb.lower),bbSma:L(bb.sma),stochK:L(sr.k),stochD:L(sr.d),fib,vwap:L(vwap),adx:adxVal,diPlus:L(adx.diPlus),diMinus:L(adx.diMinus),obvTrend:L(obv)>L(obvSma)?'bullish':'bearish',volTrend,sentiment,news:{coin:coinNews,overall:news.overall},support:fib.nearestSupport,resistance:fib.nearestResistance,inGoldenPocket:fib.inGoldenPocket,btc:btcContext,coin,
    // Extended
    choppiness:chopVal,pivots,hhll,slope,patterns,consecutive}
}

// BTC analysis cache - updated every tick before alt analysis
let btcAnalysisCache=null;

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
  },

  // NEW AGENT: BTC CORRELATION — most alts follow BTC
  btc_correlation(a){
    // Skip this agent for BTC itself
    if(a.coin==='BTC')return{vote:'hold',confidence:0,reason:'This IS BTC — no correlation check needed'};
    if(!a.btc)return{vote:'hold',confidence:0,reason:'No BTC context available yet'};

    const btc=a.btc;const selfTrend=a.condition||'neutral';
    const btcDumping=btc.priceChange1h<-1.5||btc.priceChange4h<-3;
    const btcPumping=btc.priceChange1h>1.5||btc.priceChange4h>3;
    const btcBullish=btc.condition.includes('bullish');
    const btcBearish=btc.condition.includes('bearish');

    // STRONG SIGNAL: BTC is dumping hard — almost all alts will follow
    if(btcDumping){
      return{vote:'sell',confidence:85,reason:`BTC dumping (1h:${btc.priceChange1h.toFixed(1)}%, 4h:${btc.priceChange4h.toFixed(1)}%). Alts almost always follow BTC down, often harder. Short or stay out.`};
    }

    // STRONG SIGNAL: BTC pumping hard — alts typically follow
    if(btcPumping){
      return{vote:'buy',confidence:80,reason:`BTC pumping (1h:+${btc.priceChange1h.toFixed(1)}%, 4h:+${btc.priceChange4h.toFixed(1)}%). Alts usually follow BTC up. Riding the wave.`};
    }

    // MODERATE: BTC and alt both bullish = confirmed risk-on
    if(btcBullish&&selfTrend.includes('bullish')){
      return{vote:'buy',confidence:65,reason:`BTC (${btc.condition}, RSI:${btc.rsi?.toFixed(0)}) and this alt both bullish — confirmed risk-on environment.`};
    }

    // MODERATE: BTC and alt both bearish = confirmed risk-off
    if(btcBearish&&selfTrend.includes('bearish')){
      return{vote:'sell',confidence:65,reason:`BTC (${btc.condition}) and this alt both bearish — risk-off, trend confirmed.`};
    }

    // DIVERGENCE WARNING: Alt is bullish but BTC is bearish
    if(btcBearish&&selfTrend.includes('bullish')){
      return{vote:'hold',confidence:0,reason:`WARNING: This alt shows bullish signs but BTC is bearish. Alts rarely sustain rallies against BTC weakness. Wait for BTC to confirm.`};
    }

    // DIVERGENCE: Alt bearish but BTC bullish — might be coin-specific issue
    if(btcBullish&&selfTrend.includes('bearish')){
      return{vote:'sell',confidence:50,reason:`This alt bearish despite BTC bullish — coin-specific weakness. Better alts available.`};
    }

    // BTC flat — let other agents decide without correlation bias
    return{vote:'hold',confidence:0,reason:`BTC neutral (${btc.condition}, 1h:${btc.priceChange1h?.toFixed(1)||0}%). No strong correlation signal, let other agents decide.`};
  }
};


// ═══ AGENT TIERS — harder to manipulate = higher weight ═══
const AGENT_TIERS={
  // TIER 1 (weight 3x) — Hardest to manipulate
  trend_master:    {tier:1,weight:3,why:'Multi-TF EMA alignment is nearly impossible to fake'},
  fibonacci_analyst:{tier:1,weight:3,why:'Math-based price levels from historical structure'},
  atr_volatility:  {tier:1,weight:3,why:'Volatility patterns are structural, not easily spoofed'},
  sentiment_analyst:{tier:1,weight:3,why:'External data outside exchange control'},
  btc_correlation: {tier:1,weight:3,why:'BTC is the market leader — altcoins almost always follow'},

  // TIER 2 (weight 2x) — Moderate manipulation risk
  macd_specialist:  {tier:2,weight:2,why:'Lagging EMA derivative'},
  bollinger_trader: {tier:2,weight:2,why:'Statistical bands with 20-period lookback'},
  quant_ai:         {tier:2,weight:2,why:'Z-score and ROC use statistical baselines'},

  // TIER 3 (weight 1x) — Easiest to manipulate
  momentum_hunter:  {tier:3,weight:1,why:'RSI reacts to short-term pumps'},
  volume_expert:    {tier:3,weight:1,why:'Volume can be wash-traded'}
};

// ═══ FEATURE 1: CORRELATION GROUPS — don't stack correlated trades ═══
const CORR_GROUPS={
  'L1':['BTC-USDT'],  // BTC is its own group
  'ETH':['ETH-USDT'], // ETH semi-independent
  'ALT_HIGH':['SOL-USDT','AVAX-USDT','DOT-USDT','NEAR-USDT','APT-USDT','SUI-USDT','SEI-USDT','INJ-USDT','STX-USDT'], // L1 alts
  'ALT_MID':['LINK-USDT','UNI-USDT','ATOM-USDT','AAVE-USDT','RUNE-USDT','PENDLE-USDT','DYDX-USDT','CRV-USDT','GRT-USDT'], // DeFi
  'ALT_LOW':['ADA-USDT','XRP-USDT','XLM-USDT','HBAR-USDT','VET-USDT','ALGO-USDT','LTC-USDT'], // Old L1s
  'MEME':['DOGE-USDT','SHIB-USDT','PEPE-USDT','WIF-USDT','BONK-USDT','FLOKI-USDT'], // Meme coins move together
  'AI_GAMING':['FET-USDT','RENDER-USDT','IMX-USDT','SAND-USDT','MANA-USDT','JASMY-USDT'], // AI/Gaming
  'DEFI2':['FIL-USDT','ARB-USDT','OP-USDT','TIA-USDT','ONDO-USDT','JUP-USDT','KAS-USDT','BNB-USDT'] // L2/Infra
};

function getCorrelationGroup(sym){
  for(const[group,syms] of Object.entries(CORR_GROUPS)){
    if(syms.includes(sym))return group;
  }
  return 'OTHER';
}

function checkCorrelation(sym,side){
  const group=getCorrelationGroup(sym);
  // Allow max 1 open trade per correlation group in same direction
  const sameGroupTrades=bot.openTrades.filter(t=>{
    if(t.symbol===sym)return false; // same coin check is done elsewhere
    return getCorrelationGroup(t.symbol)===group&&t.side===side;
  });
  return sameGroupTrades.length===0; // true = OK to trade
}

// ═══ FEATURE 2: REGIME DETECTION — more granular than bullish/bearish ═══
function detectRegime(a){
  const atrPct=a.atr&&a.price?(a.atr/a.price)*100:2;
  const adx=a.adx||15;
  const bbWidth=a.bbUpper&&a.bbLower?((a.bbUpper-a.bbLower)/(a.bbSma||a.price))*100:4;
  const cond=a.condition||'neutral';
  const rsi=a.rsi||50;

  // High Volatility Chaos: ATR extreme, ADX low (no trend, just wild)
  if(atrPct>4&&adx<20)return{regime:'HIGH_VOL_CHAOS',tradeable:false,reason:'Wild price action with no trend — stay out'};

  // Breakout Compression: very tight BBs + low ATR = spring coiled
  if(bbWidth<3&&atrPct<1.5)return{regime:'BREAKOUT_COMPRESSION',tradeable:true,reason:'Volatility squeeze — big move coming. Trade the breakout direction.'};

  // Trending Up: strong bullish + high ADX
  if(cond.includes('bullish')&&adx>25)return{regime:'TRENDING_UP',tradeable:true,reason:'Strong uptrend — buy dips, trail stops.'};

  // Trending Down: strong bearish + high ADX
  if(cond.includes('bearish')&&adx>25)return{regime:'TRENDING_DOWN',tradeable:true,reason:'Strong downtrend — sell rallies.'};

  // Mean Reverting: sideways, RSI at extremes, low ADX
  if(adx<20&&(rsi<30||rsi>70))return{regime:'MEAN_REVERTING',tradeable:true,reason:'Range-bound with extreme RSI — fade the extreme.'};

  // Low Vol Drift: flat, no momentum, boring
  if(atrPct<1.5&&adx<15)return{regime:'LOW_VOL_DRIFT',tradeable:false,reason:'No volatility, no trend — nothing to trade.'};

  // Mild trend
  if(cond.includes('bullish'))return{regime:'MILD_UPTREND',tradeable:true,reason:'Moderate uptrend — be cautious.'};
  if(cond.includes('bearish'))return{regime:'MILD_DOWNTREND',tradeable:true,reason:'Moderate downtrend — be cautious.'};

  return{regime:'UNCERTAIN',tradeable:false,reason:'No clear regime — wait for clarity.'};
}

// ═══ FEATURE 3: MONTE CARLO SIMULATION ═══
function monteCarloSim(price,slDist,tpDist,side,atr,trendBias=0,numSims=200){
  const volPerStep=atr/price*0.5;
  // Dynamic steps: price needs sqrt(N)*vol to travel distance D
  // So N = (D/vol)^2. We need enough steps to reach TP
  const tpFracDist=tpDist/price;
  const stepsNeeded=Math.ceil((tpFracDist/volPerStep)**2);
  const steps=Math.max(40,Math.min(100,stepsNeeded));

  let tpHits=0,slHits=0,noHits=0;
  let totalReturn=0,worstReturn=0;
  const sl=side==='buy'?price-slDist:price+slDist;
  const tp=side==='buy'?price+tpDist:price-tpDist;
  const rawDrift=side==='buy'?trendBias:-trendBias;
  const driftPerStep=rawDrift*volPerStep*0.12;

  for(let i=0;i<numSims;i++){
    let p=price;
    let hitTP=false,hitSL=false;
    for(let s=0;s<steps;s++){
      const r=(Math.random()+Math.random()+Math.random()-1.5)/1.5;
      const move=driftPerStep+r*volPerStep;
      p=p*(1+move);
      if(side==='buy'){
        if(p<=sl){hitSL=true;break}
        if(p>=tp){hitTP=true;break}
      }else{
        if(p>=sl){hitSL=true;break}
        if(p<=tp){hitTP=true;break}
      }
    }
    const thisReturn=hitTP?(tpDist/price)*100:hitSL?-(slDist/price)*100:(side==='buy'?((p-price)/price)*100:((price-p)/price)*100);
    if(hitTP)tpHits++;else if(hitSL)slHits++;else noHits++;
    totalReturn+=thisReturn;
    if(thisReturn<worstReturn)worstReturn=thisReturn;
  }

  return{
    tpProb:Math.round(tpHits/numSims*100),
    slProb:Math.round(slHits/numSims*100),
    noHitPct:Math.round(noHits/numSims*100),
    expectedReturn:Math.round(totalReturn/numSims*100)/100,
    worstCase:Math.round(worstReturn*100)/100,
    sims:numSims,steps
  };
}

// ═══ FEATURE 4: QUANT GRADE — A+/A/B/C/Reject ═══
function quantGrade(council,tpProb,regime,mc,btcContext){
  let score=0;

  // Council strength (0-30)
  if(council.confidence>=90)score+=30;
  else if(council.confidence>=80)score+=22;
  else if(council.confidence>=70)score+=15;
  else score+=5;

  // TP probability (0-25)
  if(tpProb>=85)score+=25;
  else if(tpProb>=75)score+=18;
  else if(tpProb>=65)score+=12;
  else score+=3;

  // Monte Carlo confirmation (0-20)
  if(mc.tpProb>=70)score+=20;
  else if(mc.tpProb>=55)score+=12;
  else if(mc.tpProb>=45)score+=5;
  else score-=5;

  // Regime (0-15)
  if(regime.regime==='TRENDING_UP'||regime.regime==='TRENDING_DOWN')score+=15;
  else if(regime.regime==='BREAKOUT_COMPRESSION')score+=12;
  else if(regime.regime==='MEAN_REVERTING')score+=8;
  else if(regime.regime==='MILD_UPTREND'||regime.regime==='MILD_DOWNTREND')score+=5;
  else if(!regime.tradeable)score-=10;

  // BTC alignment (0-10)
  if(btcContext){
    const btcBull=btcContext.condition&&btcContext.condition.includes('bullish');
    const btcBear=btcContext.condition&&btcContext.condition.includes('bearish');
    if((council.decision==='buy'&&btcBull)||(council.decision==='sell'&&btcBear))score+=10;
    else if((council.decision==='buy'&&btcBear)||(council.decision==='sell'&&btcBull))score-=8;
  }

  // Grade
  let grade,sizeMultiplier;
  if(score>=85){grade='A+';sizeMultiplier=1.0}
  else if(score>=70){grade='A';sizeMultiplier=0.8}
  else if(score>=55){grade='B';sizeMultiplier=0.6}
  else if(score>=40){grade='C';sizeMultiplier=0.4}
  else{grade='Reject';sizeMultiplier=0}

  return{grade,score,sizeMultiplier,breakdown:{council:council.confidence,tpProb,mcTP:mc.tpProb,regime:regime.regime,btc:btcContext?.condition||'?'}};
}

// ═══ FEATURE 5: SHADOW PAPER TRADING — silent track record for Sharpe ═══
let shadowTrades={active:[],history:[],stats:{wins:0,losses:0,totalPnL:0,totalRR:0}};

function shadowRecord(sym,side,price,sl,tp,confidence,grade){
  // Record every signal — whether we actually trade or not
  shadowTrades.active.push({
    symbol:sym,side,entryPrice:price,sl,tp,confidence,grade,
    time:Date.now(),resolved:false
  });
  // Keep max 500 active shadows
  if(shadowTrades.active.length>500)shadowTrades.active=shadowTrades.active.slice(-500);
}

function shadowUpdate(sym,currentPrice){
  // Check all active shadow trades for this symbol
  shadowTrades.active=shadowTrades.active.filter(s=>{
    if(s.symbol!==sym||s.resolved)return true;
    const hit_tp=(s.side==='buy'&&currentPrice>=s.tp)||(s.side==='sell'&&currentPrice<=s.tp);
    const hit_sl=(s.side==='buy'&&currentPrice<=s.sl)||(s.side==='sell'&&currentPrice>=s.sl);
    if(!hit_tp&&!hit_sl){
      // Check timeout — 4 hours max
      if(Date.now()-s.time>12*60*60*1000){
        s.resolved=true;
        const dir=s.side==='buy'?1:-1;
        s.exitPrice=currentPrice;
        s.pnlPct=((currentPrice-s.entryPrice)/s.entryPrice)*100*dir;
        s.result='timeout';
        shadowTrades.history.push(s);
        if(s.pnlPct>0)shadowTrades.stats.wins++;else shadowTrades.stats.losses++;
        shadowTrades.stats.totalPnL+=s.pnlPct;
        return false;
      }
      return true;
    }
    s.resolved=true;
    if(hit_tp){s.exitPrice=s.tp;s.result='tp';s.pnlPct=Math.abs((s.tp-s.entryPrice)/s.entryPrice)*100;shadowTrades.stats.wins++}
    else{s.exitPrice=s.sl;s.result='sl';s.pnlPct=-Math.abs((s.sl-s.entryPrice)/s.entryPrice)*100;shadowTrades.stats.losses++}
    shadowTrades.stats.totalPnL+=s.pnlPct;
    shadowTrades.history.push(s);
    if(shadowTrades.history.length>1000)shadowTrades.history=shadowTrades.history.slice(-1000);
    return false;
  });
}

function getSharpe(){
  const h=shadowTrades.history;
  if(h.length<10)return{sharpe:0,trades:h.length,note:'Need 10+ shadow trades'};
  const returns=h.map(t=>t.pnlPct);
  const mean=returns.reduce((a,b)=>a+b,0)/returns.length;
  const variance=returns.reduce((a,b)=>a+(b-mean)**2,0)/returns.length;
  const std=Math.sqrt(variance);
  const sharpe=std>0?mean/std*Math.sqrt(252):0;
  const winRate=shadowTrades.stats.wins/(shadowTrades.stats.wins+shadowTrades.stats.losses)*100;
  return{sharpe:Math.round(sharpe*100)/100,mean:Math.round(mean*100)/100,std:Math.round(std*100)/100,winRate:Math.round(winRate),trades:h.length};
}

// ═══ SHADOW LEARNING — learns from shadow trade outcomes ═══
let shadowLearning={
  confBuckets:{},   // confidence range → win rate
  sideBias:null,     // buy vs sell performance
  lastAnalysis:0,
  insights:[]
};

function shadowLearn(){
  const h=shadowTrades.history;
  if(h.length<15||Date.now()-shadowLearning.lastAnalysis<300000)return;
  shadowLearning.lastAnalysis=Date.now();
  supervisorSaveOriginal();
  const orig=supervisor.originalSettings||{};
  const recent=h.slice(-50);
  const slHits=recent.filter(t=>t.result==='sl').length;
  const tpHits=recent.filter(t=>t.result==='tp').length;
  const timeouts=recent.filter(t=>t.result==='timeout').length;
  const totalResolved=slHits+tpHits+timeouts;
  const confBuckets={'70-79':{w:0,l:0},'80-89':{w:0,l:0},'90-100':{w:0,l:0}};
  for(const t of recent){
    const c=t.confidence||0;
    const bucket=c>=90?'90-100':c>=80?'80-89':'70-79';
    if(t.result==='tp')confBuckets[bucket].w++;
    else if(t.result==='sl')confBuckets[bucket].l++;
  }
  shadowLearning.confBuckets=confBuckets;
  const buys=recent.filter(t=>t.side==='buy');
  const sells=recent.filter(t=>t.side==='sell');
  const buyWR=buys.length>=5?buys.filter(t=>t.result==='tp').length/buys.length:null;
  const sellWR=sells.length>=5?sells.filter(t=>t.result==='tp').length/sells.length:null;
  shadowLearning.sideBias={buyWinRate:buyWR?Math.round(buyWR*100):null,sellWinRate:sellWR?Math.round(sellWR*100):null,buyCount:buys.length,sellCount:sells.length};
  const insights=[];

  // ACTION 1: SL hit too often -> widen SL
  if(totalResolved>=15&&slHits/totalResolved>0.6){
    const r=Math.round(slHits/totalResolved*100);
    insights.push({type:'action',msg:'SL hit '+r+'% -> widening SL +0.5 ATR'});
    const nv=Math.min(+(bot.slATR+0.5).toFixed(1),5.0);
    if(nv!==bot.slATR)supervisorAdjust('slATR',nv,'shadow: SL hit '+r+'%');
  }

  // ACTION 2: TP rarely reached -> bring TP closer
  if(totalResolved>=15&&tpHits/totalResolved<0.25){
    const r=Math.round(tpHits/totalResolved*100);
    insights.push({type:'action',msg:'TP hit only '+r+'% -> bringing TP -0.5 ATR'});
    const nv=Math.max(+(bot.tpATR-0.5).toFixed(1),1.0);
    if(nv!==bot.tpATR)supervisorAdjust('tpATR',nv,'shadow: TP hit only '+r+'%');
  }

  // ACTION 3: Negative Sharpe -> reduce leverage
  const sharpe=getSharpe();
  if(sharpe.sharpe<-0.5&&h.length>=20){
    insights.push({type:'action',msg:'Sharpe '+sharpe.sharpe+' -> reducing leverage -1'});
    const nv=Math.max(1,bot.leverage-1);
    if(nv!==bot.leverage)supervisorAdjust('leverage',nv,'shadow: Sharpe '+sharpe.sharpe);
  }else if(sharpe.sharpe>=1.0&&h.length>=30){
    const mx=orig.leverage||5;
    if(bot.leverage<mx){
      insights.push({type:'action',msg:'Sharpe '+sharpe.sharpe+' -> restoring leverage +1'});
      supervisorAdjust('leverage',Math.min(bot.leverage+1,mx),'shadow: Sharpe '+sharpe.sharpe);
    }
  }

  // ACTION 4: TP rate high + SL rate low -> strategy working, can tighten SL
  if(totalResolved>=15&&tpHits/totalResolved>0.55&&slHits/totalResolved<0.3){
    const r=Math.round(tpHits/totalResolved*100);
    insights.push({type:'positive',msg:'TP hit '+r+'% -> tightening SL -0.3 ATR'});
    const mn=orig.slATR||1.5;
    if(bot.slATR>mn+0.3)supervisorAdjust('slATR',+(bot.slATR-0.3).toFixed(1),'shadow: TP rate '+r+'%');
  }

  // Confidence bucket insights
  for(const[range,data] of Object.entries(confBuckets)){
    const total=data.w+data.l;
    if(total>=8){
      const wr=Math.round(data.w/total*100);
      if(wr<35)insights.push({type:'warning',msg:range+'% conf win rate '+wr+'%'});
      else if(wr>=65)insights.push({type:'positive',msg:range+'% conf win rate '+wr+'%'});
    }
  }

  // Side bias
  if(buyWR!==null&&sellWR!==null){
    if(buyWR>sellWR+0.15)insights.push({type:'info',msg:'BUY outperforms SELL by '+Math.round((buyWR-sellWR)*100)+'%'});
    else if(sellWR>buyWR+0.15)insights.push({type:'info',msg:'SELL outperforms BUY by '+Math.round((sellWR-buyWR)*100)+'%'});
  }

  // Summary
  if(sharpe.sharpe<0)insights.push({type:'warning',msg:'Sharpe '+sharpe.sharpe+' — net negative'});
  else if(sharpe.sharpe>=1.5)insights.push({type:'positive',msg:'Sharpe '+sharpe.sharpe+' — strong edge'});
  else if(sharpe.sharpe>=0.5)insights.push({type:'info',msg:'Sharpe '+sharpe.sharpe+' — mild edge'});
  insights.push({type:'info',msg:'SL/TP/Timeout: '+slHits+'/'+tpHits+'/'+timeouts+' of '+totalResolved});
  shadowLearning.insights=insights;

  const actionCount=insights.filter(i=>i.type==='action').length;
  if(actionCount>0)botLog('\ud83e\udde0 SHADOW LEARNING: '+actionCount+' adjustment(s) from '+h.length+' signals | SL:'+bot.slATR+' TP:'+bot.tpATR+' Lev:'+bot.leverage);
}

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
  const weightThreshold=Math.max(6,Math.floor(requiredAgree*1.5)); // e.g., 4 agents = need 8 pts
  // Gate 2: At least 1 Tier 1 agent must agree (anti-manipulation)
  const t1Required=2;

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
const ALL_SYMBOLS=['BTC-USDT','ETH-USDT','SOL-USDT','XRP-USDT','ADA-USDT','DOGE-USDT','LINK-USDT','AVAX-USDT','DOT-USDT','BNB-USDT','SHIB-USDT','UNI-USDT','ATOM-USDT','LTC-USDT','FIL-USDT','NEAR-USDT','APT-USDT','ARB-USDT','OP-USDT','SUI-USDT','SEI-USDT','INJ-USDT','FET-USDT','RENDER-USDT','PEPE-USDT','WIF-USDT','BONK-USDT','FLOKI-USDT','TIA-USDT','AAVE-USDT','XLM-USDT','HBAR-USDT','VET-USDT','GRT-USDT','STX-USDT','IMX-USDT','JASMY-USDT','ALGO-USDT','SAND-USDT','MANA-USDT','CRV-USDT','ONDO-USDT','JUP-USDT','PENDLE-USDT','KAS-USDT','RUNE-USDT','DYDX-USDT'];
const SETTINGS_FILE=path.join(__dirname,'.bot-settings.json');
const STATE_FILE=path.join(__dirname,'.bot-state.json');
const bot={
  running:false,mode:'paper',tradingType:'combined',
  symbols:ALL_SYMBOLS,intervalMs:45000,intervalId:null,
  requiredAgents:4,
  riskPct:2,maxDrawdownPct:15,slATR:1.0,tpATR:3.0,trailingStop:true,trailATR:1.0,maxOpenTrades:10,leverage:5,smallBalanceMode:'auto',
  dailyTargetPct:1.5, // stop trading after 1.5% daily profit
  dailyPnL:0,dailyDate:null, // reset each day
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
    if(s.smallBalanceMode)bot.smallBalanceMode=s.smallBalanceMode;if(s.dailyTargetPct!==undefined)bot.dailyTargetPct=Math.max(0.5,Math.min(10,+s.dailyTargetPct));if(s.dailyTargetPct)bot.dailyTargetPct=s.dailyTargetPct;
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
  try{const data=JSON.stringify({mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents,riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,dailyTargetPct:bot.dailyTargetPct,credentials:bot.credentials});
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
setTimeout(()=>{fetchNews().catch(e=>console.log('Initial news err:',e.message));getSentiment().catch(e=>console.log('Initial sentiment err:',e.message));syncKuCoinPositions().catch(e=>console.log('Initial sync err:',e.message));fetchLiveBalance().then(bal=>autoTuneForBalance(bal||bot.paperUSD)).catch(()=>autoTuneForBalance(bot.paperUSD))},5000);

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

  // Supervisor: track performance
  supervisorOnTradeClose(t);

  // Track daily PnL
  const today=new Date().toISOString().slice(0,10);
  if(bot.dailyDate!==today){bot.dailyPnL=0;bot.dailyDate=today} // reset at midnight
  bot.dailyPnL+=t.pnl;

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

  async function attemptOrder(contracts,marginMode){
    if(contracts<info.lotSize)throw new Error(`contracts ${contracts} < min lot ${info.lotSize}`);
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const ep='/api/v1/orders';
    const body={
      clientOid:crypto.randomUUID(),
      side,
      symbol:info.contract,
      type:'market',
      size:contracts,
      leverage:String(leverage),
      marginMode:marginMode
    };
    const r=await fetch('https://api-futures.kucoin.com'+ep,{method:'POST',headers:kcH('POST',ep,body,apiKey,apiSecret,passphrase),body:JSON.stringify(body)});
    return{data:await safeJSON(r),contracts};
  }

  let contracts=Math.floor((usdAmount*leverage)/(price*info.multiplier));
  let marginMode=bot.marginMode||'ISOLATED';
  let result=await attemptOrder(contracts,marginMode);

  // Retry with opposite margin mode if mismatch
  if(result.data.code!=='200000'&&result.data.msg&&result.data.msg.toLowerCase().includes('margin mode')){
    const otherMode=marginMode==='ISOLATED'?'CROSS':'ISOLATED';
    console.log('Retrying with marginMode='+otherMode);
    result=await attemptOrder(contracts,otherMode);
    if(result.data.code==='200000'){bot.marginMode=otherMode;saveSettings()}
    marginMode=otherMode;
  }

  // Retry with smaller sizes on insufficient balance
  let attempts=0;
  while(result.data.code!=='200000'&&result.data.msg&&result.data.msg.toLowerCase().includes('insufficient')&&attempts<3){
    attempts++;
    const match=result.data.msg.match(/(\d+\.?\d*)\s*is required/i);
    if(match){
      const required=+match[1];
      // KuCoin says it needs $X. Reduce contracts so margin fits within what we can afford.
      const newContracts=Math.floor(contracts*(contracts*price*info.multiplier/leverage)/required*0.8);
      if(newContracts>=info.lotSize&&newContracts<contracts){
        contracts=newContracts;
      }else{
        contracts=Math.floor(contracts*0.5); // halve it
      }
    }else{
      contracts=Math.floor(contracts*0.5);
    }
    if(contracts<info.lotSize){
      throw new Error(`Balance too low. KuCoin needs $${match?match[1]:'?'} but position is at minimum lot.`);
    }
    botLog(`Retry ${attempts}: reducing to ${contracts} contracts (${(contracts*price*info.multiplier).toFixed(2)} notional)`);
    result=await attemptOrder(contracts,marginMode);
  }

  if(result.data.code!=='200000')throw new Error('Futures: '+(result.data.msg||'Order failed'));
  return{orderId:result.data.data.orderId,qty:result.contracts*info.multiplier,price,contracts:result.contracts};
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
    reduceOnly:true,
    marginMode:bot.marginMode||'ISOLATED'
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
// ═══ SUPERVISOR BOT — monitors performance, adjusts risk, changes settings ═══
const supervisor={
  consecutiveLosses:0,consecutiveWins:0,recentTrades:[],agentAccuracy:{},
  circuitBroken:false,circuitBreakUntil:0,adjustments:[],
  originalSettings:null,
  mode:'normal' // normal, cautious, aggressive, recovery
};

function supervisorSaveOriginal(){
  if(!supervisor.originalSettings){
    supervisor.originalSettings={leverage:bot.leverage,riskPct:bot.riskPct,slATR:bot.slATR,tpATR:bot.tpATR,requiredAgents:bot.requiredAgents,maxOpenTrades:bot.maxOpenTrades};
  }
}

// ═══ AUTO-TUNE SETTINGS BASED ON PORTFOLIO SIZE ═══
let lastAutoTuneBal=0;
function autoTuneForBalance(bal){
  if(!bal||bal<=0)return;
  // Only re-tune if balance changed significantly (>15%)
  if(lastAutoTuneBal>0&&Math.abs(bal-lastAutoTuneBal)/lastAutoTuneBal<0.15)return;
  lastAutoTuneBal=bal;

  let tier,settings;

  if(bal<10){
    tier='MICRO (<$10)';
    // Priority: SURVIVE. Wide SL, close TP, win often with small gains
    settings={leverage:2,riskPct:2,slATR:3.0,tpATR:2.0,maxOpenTrades:1,requiredAgents:5,smallBalanceMode:'on'};
  }else if(bal<25){
    tier='TINY ($10-25)';
    settings={leverage:3,riskPct:3,slATR:2.5,tpATR:2.0,maxOpenTrades:2,requiredAgents:5,smallBalanceMode:'on'};
  }else if(bal<50){
    tier='SMALL ($25-50)';
    settings={leverage:3,riskPct:3,slATR:2.0,tpATR:2.5,maxOpenTrades:2,requiredAgents:4,smallBalanceMode:'on'};
  }else if(bal<100){
    tier='STARTER ($50-100)';
    settings={leverage:5,riskPct:2.5,slATR:2.0,tpATR:3.0,maxOpenTrades:3,requiredAgents:4,smallBalanceMode:'auto'};
  }else if(bal<500){
    tier='GROWING ($100-500)';
    settings={leverage:5,riskPct:2,slATR:1.5,tpATR:3.0,maxOpenTrades:5,requiredAgents:4,smallBalanceMode:'off'};
  }else if(bal<1000){
    tier='MODERATE ($500-1K)';
    settings={leverage:3,riskPct:1.5,slATR:1.5,tpATR:3.0,maxOpenTrades:7,requiredAgents:4,smallBalanceMode:'off'};
  }else{
    tier='STANDARD ($1K+)';
    settings={leverage:3,riskPct:1,slATR:1.5,tpATR:3.0,maxOpenTrades:10,requiredAgents:4,smallBalanceMode:'off'};
  }

  let changed=false;
  for(const[key,val] of Object.entries(settings)){
    if(bot[key]!==val){
      bot[key]=val;
      changed=true;
    }
  }

  if(changed){
    botLog(`📊 AUTO-TUNE: Balance $${bal.toFixed(2)} → ${tier} | lev:${settings.leverage}x risk:${settings.riskPct}% SL:${settings.slATR} TP:${settings.tpATR} max:${settings.maxOpenTrades} agents:${settings.requiredAgents}`);
    // Update supervisor's original settings to match new tier
    supervisor.originalSettings={leverage:settings.leverage,riskPct:settings.riskPct,slATR:settings.slATR,tpATR:settings.tpATR,requiredAgents:settings.requiredAgents,maxOpenTrades:settings.maxOpenTrades};
    saveSettings();
  }
}

function supervisorAdjust(param,newVal,reason){
  const old=bot[param];if(old===newVal)return;
  bot[param]=newVal;
  const adj=param+': '+old+' -> '+newVal+' — '+reason;
  supervisor.adjustments.push({time:Date.now(),action:adj,param,from:old,to:newVal});
  if(supervisor.adjustments.length>50)supervisor.adjustments=supervisor.adjustments.slice(-50);
  botLog('🔧 SUPERVISOR '+adj);
  saveSettings();
}

function supervisorOnTradeClose(trade){
  supervisorSaveOriginal();
  const isWin=trade.pnl>0;
  if(isWin){supervisor.consecutiveWins++;supervisor.consecutiveLosses=0}
  else{supervisor.consecutiveLosses++;supervisor.consecutiveWins=0}

  supervisor.recentTrades.push({symbol:trade.symbol,side:trade.side,pnl:trade.pnl,pnlPct:trade.pnlPct,result:trade.reason,time:Date.now(),isWin});
  if(supervisor.recentTrades.length>20)supervisor.recentTrades.shift();

  const orig=supervisor.originalSettings||{};

  // 2 LOSSES: go cautious
  if(supervisor.consecutiveLosses===2){
    supervisor.mode='cautious';
    supervisorAdjust('leverage',Math.max(1,Math.floor((orig.leverage||5)*0.6)),'2 losses — reducing leverage');
    supervisorAdjust('slATR',Math.min(bot.slATR+0.5,(orig.slATR||2)*1.5),'wider stops to survive volatility');
    supervisorAdjust('riskPct',Math.max(0.5,+(bot.riskPct*0.7).toFixed(1)),'reducing risk per trade');
  }

  // 3 LOSSES: circuit breaker + max safety
  if(supervisor.consecutiveLosses>=3&&!supervisor.circuitBroken){
    supervisor.circuitBroken=true;
    supervisor.circuitBreakUntil=Date.now()+15*60*1000;
    supervisor.mode='recovery';
    supervisorAdjust('leverage',Math.max(1,Math.floor((orig.leverage||5)*0.5)),'circuit breaker');
    supervisorAdjust('maxOpenTrades',1,'circuit breaker — 1 trade only');
    supervisorAdjust('requiredAgents',Math.min(6,(orig.requiredAgents||4)+1),'circuit breaker — stricter');
    botLog('🛑 SUPERVISOR CIRCUIT BREAKER: 3 losses. Pausing 15min. Lev:'+bot.leverage+'x MaxTrades:1 Agents:'+bot.requiredAgents);
  }

  // 3 WINS after cautious/recovery: restore toward original
  if(supervisor.consecutiveWins===3&&supervisor.mode!=='normal'){
    supervisor.mode='normal';
    supervisorAdjust('leverage',Math.min(bot.leverage+1,orig.leverage||5),'3 wins — restoring leverage');
    supervisorAdjust('riskPct',Math.min(+(bot.riskPct*1.3).toFixed(1),orig.riskPct||2),'3 wins — restoring risk');
    supervisorAdjust('slATR',Math.max(+(bot.slATR-0.3).toFixed(1),orig.slATR||2),'3 wins — tightening SL back');
    supervisorAdjust('requiredAgents',Math.max(bot.requiredAgents-1,orig.requiredAgents||4),'3 wins — restoring threshold');
    supervisorAdjust('maxOpenTrades',Math.min(bot.maxOpenTrades+1,orig.maxOpenTrades||3),'3 wins — more slots');
    botLog('🟢 SUPERVISOR: 3 wins — restoring to normal settings');
  }

  // 5 WINS: can push toward original ceiling
  if(supervisor.consecutiveWins>=5){
    if(bot.leverage<(orig.leverage||5))supervisorAdjust('leverage',Math.min(bot.leverage+1,orig.leverage||5),'hot streak');
    botLog('🟢 SUPERVISOR: '+supervisor.consecutiveWins+' win streak!');
  }

  // AGENT ACCURACY
  if(trade.councilVotes){
    const correctSide=isWin?trade.side:(trade.side==='buy'?'sell':'buy');
    for(const[agent,vote] of Object.entries(trade.councilVotes)){
      if(!supervisor.agentAccuracy[agent])supervisor.agentAccuracy[agent]={correct:0,wrong:0,total:0};
      supervisor.agentAccuracy[agent].total++;
      if(vote.vote===correctSide)supervisor.agentAccuracy[agent].correct++;
      else if(vote.vote!=='hold')supervisor.agentAccuracy[agent].wrong++;
    }
  }

  // WIN RATE CHECK every 5 trades
  if(supervisor.recentTrades.length>=10&&supervisor.recentTrades.length%5===0){
    const recent=supervisor.recentTrades.slice(-10);
    const wr=recent.filter(t=>t.isWin).length/recent.length;
    if(wr<0.3&&supervisor.mode!=='recovery'){
      supervisor.mode='cautious';
      supervisorAdjust('leverage',Math.max(1,bot.leverage-1),'win rate '+Math.round(wr*100)+'%');
      supervisorAdjust('riskPct',Math.max(0.5,+(bot.riskPct*0.8).toFixed(1)),'poor win rate');
      botLog('⚠ SUPERVISOR: Win rate '+Math.round(wr*100)+'% — cutting risk');
    }else if(wr>=0.6&&supervisor.mode==='cautious'){
      supervisor.mode='normal';
      botLog('🟢 SUPERVISOR: Win rate '+Math.round(wr*100)+'% — back to normal');
    }
  }
}

function supervisorCheck(){
  if(supervisor.circuitBroken){
    if(Date.now()>=supervisor.circuitBreakUntil){
      supervisor.circuitBroken=false;
      supervisor.mode='cautious';
      botLog('🟢 SUPERVISOR: Circuit breaker released — cautious mode');
      supervisor.adjustments.push({time:Date.now(),action:'Circuit breaker released'});
    }
    return{canTrade:false,reason:'🛑 Circuit breaker — '+Math.round((supervisor.circuitBreakUntil-Date.now())/60000)+'min left'};
  }
  const recent=supervisor.recentTrades.slice(-10);
  if(recent.length>=5){
    const wr=recent.filter(t=>t.isWin).length/recent.length;
    if(wr<0.2)return{canTrade:true,reason:'⚠ win rate '+Math.round(wr*100)+'%',riskReduction:0.5};
  }
  return{canTrade:true,reason:'✅ '+supervisor.mode,riskReduction:supervisor.mode==='cautious'?0.7:supervisor.mode==='recovery'?0.5:1.0};
}

function getAgentReport(){
  const report={};
  for(const[agent,stats] of Object.entries(supervisor.agentAccuracy)){
    const accuracy=stats.total>0?Math.round(stats.correct/stats.total*100):0;
    const rating=accuracy>=60?'reliable':accuracy>=45?'average':'underperforming';
    report[agent]={accuracy,correct:stats.correct,wrong:stats.wrong,total:stats.total,rating};
  }
  return report;
}

// ═══════════════════════════════════════════════════════════════
// STRATEGY COMBINATION ENGINE — tests hundreds of combos silently
// ═══════════════════════════════════════════════════════════════

// Binary signal generators — each returns {signal:'buy'|'sell'|'none', name}
const SIGNALS={
  ema_cross_9_21(a){return{signal:a.ema9>a.ema21?'buy':a.ema9<a.ema21?'sell':'none',name:'EMA 9/21 cross'}},
  ema_cross_21_50(a){return{signal:a.ema21>a.ema50?'buy':a.ema21<a.ema50?'sell':'none',name:'EMA 21/50 cross'}},
  ema_stack(a){return{signal:a.ema9>a.ema21&&a.ema21>a.ema50?'buy':a.ema9<a.ema21&&a.ema21<a.ema50?'sell':'none',name:'EMA stack'}},
  macd_cross(a){return{signal:a.macdLine>a.macdSignal?'buy':a.macdLine<a.macdSignal?'sell':'none',name:'MACD cross'}},
  macd_hist_flip(a){return{signal:a.macdHist>0&&a.prevMacdHist<=0?'buy':a.macdHist<0&&a.prevMacdHist>=0?'sell':'none',name:'MACD hist flip'}},
  rsi_extreme(a){return{signal:a.rsi<30?'buy':a.rsi>70?'sell':'none',name:'RSI extreme'}},
  rsi_mid_trend(a){return{signal:a.rsi>50&&a.rsi<65&&a.condition.includes('bullish')?'buy':a.rsi<50&&a.rsi>35&&a.condition.includes('bearish')?'sell':'none',name:'RSI mid-trend'}},
  bb_touch(a){if(!a.bbUpper||!a.bbLower)return{signal:'none',name:'BB touch'};return{signal:a.price<=a.bbLower?'buy':a.price>=a.bbUpper?'sell':'none',name:'BB touch'}},
  bb_squeeze(a){if(!a.bbUpper||!a.bbLower)return{signal:'none',name:'BB squeeze'};const w=((a.bbUpper-a.bbLower)/a.bbSma)*100;return{signal:w<3?'buy':'none',name:'BB squeeze'}},
  adx_strong(a){return{signal:a.adx>25?'buy':'none',name:'ADX strong'}},
  stoch_cross(a){return{signal:a.stochK<20&&a.stochD<20?'buy':a.stochK>80&&a.stochD>80?'sell':'none',name:'Stoch extreme'}},
  vwap_position(a){return{signal:a.price>a.vwap?'buy':a.price<a.vwap?'sell':'none',name:'VWAP position'}},
  obv_trend(a){return{signal:a.obvTrend==='bullish'?'buy':a.obvTrend==='bearish'?'sell':'none',name:'OBV trend'}},
  volume_spike(a){return{signal:a.volTrend==='high'?'buy':'none',name:'Volume spike'}},
  fib_support(a){if(!a.support||!a.price)return{signal:'none',name:'Fib support'};const dist=Math.abs(a.price-a.support)/a.price;return{signal:dist<0.01?'buy':'none',name:'Fib support'}},
  fib_resist(a){if(!a.resistance||!a.price)return{signal:'none',name:'Fib resistance'};const dist=Math.abs(a.price-a.resistance)/a.price;return{signal:dist<0.01?'sell':'none',name:'Fib resistance'}},
  golden_pocket(a){return{signal:a.inGoldenPocket?'buy':'none',name:'Golden pocket'}},
  higher_highs(a){return{signal:a.hhll?.trend==='uptrend'?'buy':a.hhll?.trend==='downtrend'?'sell':'none',name:'HH/HL pattern'}},
  trend_slope(a){return{signal:a.slope>0.1?'buy':a.slope<-0.1?'sell':'none',name:'Trend slope'}},
  chop_trending(a){return{signal:a.choppiness<38?'buy':a.choppiness>61?'sell':'none',name:'Chop trending/ranging'}},
  hammer(a){return{signal:a.patterns?.includes('hammer')||a.patterns?.includes('pin_bar_bull')?'buy':a.patterns?.includes('shooting_star')||a.patterns?.includes('pin_bar_bear')?'sell':'none',name:'Hammer/Star'}},
  engulfing(a){return{signal:a.patterns?.includes('bullish_engulfing')?'buy':a.patterns?.includes('bearish_engulfing')?'sell':'none',name:'Engulfing'}},
  three_soldiers(a){return{signal:a.patterns?.includes('three_green')?'buy':a.patterns?.includes('three_red')?'sell':'none',name:'3 soldiers/crows'}},
  inside_bar(a){return{signal:a.patterns?.includes('inside_bar')?(a.condition.includes('bullish')?'buy':'sell'):'none',name:'Inside bar break'}},
  btc_aligned(a){if(!a.btc)return{signal:'none',name:'BTC aligned'};return{signal:a.btc.condition.includes('bullish')?'buy':a.btc.condition.includes('bearish')?'sell':'none',name:'BTC aligned'}},
  btc_momentum(a){if(!a.btc)return{signal:'none',name:'BTC momentum'};return{signal:a.btc.priceChange1h>0.5?'buy':a.btc.priceChange1h<-0.5?'sell':'none',name:'BTC 1h momentum'}},
  pivot_support(a){if(!a.pivots)return{signal:'none',name:'Pivot S/R'};const dist_s=Math.abs(a.price-a.pivots.s1)/a.price;const dist_r=Math.abs(a.price-a.pivots.r1)/a.price;return{signal:dist_s<0.005?'buy':dist_r<0.005?'sell':'none',name:'Pivot S/R'}},
  news_positive(a){return{signal:a.news?.overall?.bias==='bullish'?'buy':a.news?.overall?.bias==='bearish'?'sell':'none',name:'News sentiment'}},
  fear_greed(a){return{signal:a.sentiment?.value<25?'buy':a.sentiment?.value>75?'sell':'none',name:'F&G extreme'}}
};

const SIGNAL_NAMES=Object.keys(SIGNALS);

// Pre-define logical combo templates (not random — these make trading sense)
const COMBO_TEMPLATES=[
  // Trend following combos
  ['ema_stack','adx_strong','btc_aligned'],
  ['ema_cross_9_21','macd_cross','vwap_position'],
  ['ema_cross_21_50','trend_slope','obv_trend'],
  ['ema_stack','higher_highs','volume_spike'],
  ['ema_cross_9_21','adx_strong','higher_highs'],
  ['trend_slope','chop_trending','btc_aligned'],
  ['ema_stack','macd_cross','btc_momentum'],
  // Mean reversion combos
  ['rsi_extreme','bb_touch','volume_spike'],
  ['stoch_cross','bb_touch','obv_trend'],
  ['rsi_extreme','fib_support','hammer'],
  ['bb_touch','pivot_support','three_soldiers'],
  ['rsi_extreme','engulfing','btc_aligned'],
  // Breakout combos
  ['bb_squeeze','adx_strong','volume_spike'],
  ['inside_bar','adx_strong','btc_aligned'],
  ['bb_squeeze','macd_hist_flip','trend_slope'],
  ['chop_trending','ema_cross_9_21','volume_spike'],
  // Pattern combos
  ['hammer','rsi_extreme','btc_aligned'],
  ['engulfing','vwap_position','obv_trend'],
  ['three_soldiers','ema_stack','adx_strong'],
  ['inside_bar','bb_squeeze','trend_slope'],
  // BTC-context combos
  ['btc_aligned','ema_cross_9_21','rsi_mid_trend'],
  ['btc_momentum','macd_cross','volume_spike'],
  ['btc_aligned','trend_slope','higher_highs'],
  // Pairs (simpler)
  ['ema_stack','btc_aligned'],
  ['rsi_extreme','bb_touch'],
  ['macd_cross','adx_strong'],
  ['hammer','btc_aligned'],
  ['engulfing','volume_spike'],
  ['bb_squeeze','volume_spike'],
  ['trend_slope','obv_trend'],
  ['higher_highs','btc_momentum'],
  ['chop_trending','ema_cross_9_21'],
  ['fib_support','rsi_extreme'],
  ['pivot_support','hammer'],
  ['news_positive','ema_stack'],
  ['fear_greed','bb_touch']
];

// Combo performance tracker
let comboTracker={
  combos:{},
  rankings:[],
  promotedCombo:null,
  lastRankUpdate:0
};

// Persist combo data to disk
function saveComboData(){
  try{
    const data={combos:{},promotedCombo:comboTracker.promotedCombo,rankings:comboTracker.rankings};
    // Save only resolved stats, not active trades (too large)
    for(const[id,c] of Object.entries(comboTracker.combos)){
      data.combos[id]={wins:c.wins,losses:c.losses,returns:c.returns.slice(-100),signals:c.signals,lastUpdated:c.lastUpdated,trades:c.trades.filter(t=>!t.resolved).slice(-50)};
    }
    fs.writeFileSync('.combo-data.json',JSON.stringify(data));
  }catch(e){console.log('Combo save err:',e.message)}
}

// Load combo data from disk
function loadComboData(){
  try{
    if(!fs.existsSync('.combo-data.json'))return;
    const data=JSON.parse(fs.readFileSync('.combo-data.json','utf8'));
    if(data.combos){
      for(const[id,c] of Object.entries(data.combos)){
        comboTracker.combos[id]={...c,trades:c.trades||[]};
      }
    }
    if(data.promotedCombo)comboTracker.promotedCombo=data.promotedCombo;
    if(data.rankings)comboTracker.rankings=data.rankings;
    const totalTrades=Object.values(comboTracker.combos).reduce((s,c)=>s+c.wins+c.losses,0);
    console.log('Combo data loaded:',Object.keys(comboTracker.combos).length,'combos,',totalTrades,'trades');
    if(comboTracker.promotedCombo)console.log('Promoted combo:',comboTracker.promotedCombo.id,'WR:'+comboTracker.promotedCombo.winRate+'%');
  }catch(e){console.log('Combo load err:',e.message)}
}
loadComboData();

function getComboId(signals){return signals.sort().join('+')}

function evaluateCombo(comboSignals,analysis){
  // Run each signal and check if they agree
  const results=comboSignals.map(s=>SIGNALS[s]?SIGNALS[s](analysis):null).filter(Boolean);
  if(!results.length)return null;

  // All signals must agree on direction (or be 'none' which is abstain)
  const buys=results.filter(r=>r.signal==='buy').length;
  const sells=results.filter(r=>r.signal==='sell').length;
  const active=buys+sells;

  // Need majority agreement, no conflicts
  if(buys>0&&sells>0)return null; // conflict = no trade
  if(active<Math.ceil(results.length*0.6))return null; // not enough signals active

  return buys>sells?'buy':'sell';
}

function comboShadowRecord(comboId,sym,side,price,atr){
  if(!comboTracker.combos[comboId])comboTracker.combos[comboId]={wins:0,losses:0,trades:[],returns:[],signals:comboId.split('+'),lastUpdated:Date.now()};
  const slDist=atr*2.0; // fixed 2 ATR SL for fair comparison
  const tpDist=atr*2.0; // fixed 2 ATR TP (1:1 R:R for fair win rate comparison)
  comboTracker.combos[comboId].trades.push({
    sym,side,entry:price,sl:side==='buy'?price-slDist:price+slDist,
    tp:side==='buy'?price+tpDist:price-tpDist,
    time:Date.now(),resolved:false
  });
  // Cap at 200 trades per combo
  if(comboTracker.combos[comboId].trades.length>200)comboTracker.combos[comboId].trades=comboTracker.combos[comboId].trades.slice(-200);
}

function comboShadowUpdate(sym,currentPrice){
  for(const[id,data] of Object.entries(comboTracker.combos)){
    for(const t of data.trades){
      if(t.resolved||t.sym!==sym)continue;
      const hitTP=(t.side==='buy'&&currentPrice>=t.tp)||(t.side==='sell'&&currentPrice<=t.tp);
      const hitSL=(t.side==='buy'&&currentPrice<=t.sl)||(t.side==='sell'&&currentPrice>=t.sl);
      const timeout=Date.now()-t.time>12*60*60*1000;
      if(!hitTP&&!hitSL&&!timeout)continue;
      t.resolved=true;
      const pnlPct=hitTP?Math.abs((t.tp-t.entry)/t.entry)*100:hitSL?-Math.abs((t.sl-t.entry)/t.entry)*100:((t.side==='buy'?1:-1)*(currentPrice-t.entry)/t.entry)*100;
      data.returns.push(pnlPct);
      if(data.returns.length>200)data.returns.shift();
      if(pnlPct>0)data.wins++;else data.losses++;
      data.lastUpdated=Date.now();
    }
    // Clean resolved trades
    data.trades=data.trades.filter(t=>!t.resolved);
  }
}

function rankCombos(){
  if(Date.now()-comboTracker.lastRankUpdate<60000)return; // rank every 1 min
  comboTracker.lastRankUpdate=Date.now();

  const rankings=[];
  for(const[id,data] of Object.entries(comboTracker.combos)){
    const total=data.wins+data.losses;
    if(total<8)continue; // need 8+ resolved trades

    const winRate=data.wins/total;
    const returns=data.returns.slice(-50);
    const mean=returns.reduce((a,b)=>a+b,0)/returns.length;
    const variance=returns.reduce((a,b)=>a+(b-mean)**2,0)/returns.length;
    const std=Math.sqrt(variance);
    const sharpe=std>0?mean/std:0;
    const consistency=std>0?1/std:999; // lower volatility = higher consistency
    const profitFactor=data.losses>0?(data.wins*Math.abs(mean>0?mean:0.01))/(data.losses*Math.abs(mean<0?mean:0.01)):data.wins;

    rankings.push({
      id,signals:data.signals||id.split('+'),
      wins:data.wins,losses:data.losses,total,
      winRate:Math.round(winRate*100),
      avgReturn:Math.round(mean*100)/100,
      sharpe:Math.round(sharpe*100)/100,
      consistency:Math.round(consistency*100)/100,
      profitFactor:Math.round(profitFactor*100)/100,
      score:Math.round((winRate*40+Math.min(sharpe,3)*20+Math.min(consistency,10)*20+(mean>0?20:0))*100)/100
    });
  }

  // Sort by CONSISTENCY first (low volatility), then profit factor
  rankings.sort((a,b)=>b.score-a.score);
  comboTracker.rankings=rankings;
  saveComboData(); // persist to disk

  // Auto-promote top combo if it has 20+ trades and positive everything
  if(rankings.length&&rankings[0].total>=20&&rankings[0].winRate>=50&&rankings[0].sharpe>0){
    const best=rankings[0];
    if(!comboTracker.promotedCombo||comboTracker.promotedCombo.id!==best.id){
      comboTracker.promotedCombo=best;
      botLog('🏆 COMBO ENGINE: Promoted '+best.id+' (WR:'+best.winRate+'% Sharpe:'+best.sharpe+' trades:'+best.total+')');
    }
  }

  // Demote if promoted combo drops below threshold
  if(comboTracker.promotedCombo){
    const promoted=rankings.find(r=>r.id===comboTracker.promotedCombo.id);
    if(promoted&&promoted.total>=20&&promoted.profitFactor<1.2){
      botLog('📉 COMBO ENGINE: Demoted '+promoted.id+' (profit factor '+promoted.profitFactor+' < 1.2)');
      comboTracker.promotedCombo=rankings[0]?.profitFactor>=1.2?rankings[0]:null;
    }
  }
}

// Run combo testing on each analysis (called in tick loop)
function runComboTests(analysis,sym){
  if(!analysis||!analysis.price)return;
  // Update existing combo shadow trades
  comboShadowUpdate(sym,analysis.price);

  // Test each combo template against current analysis
  for(const combo of COMBO_TEMPLATES){
    const decision=evaluateCombo(combo,analysis);
    if(decision){
      const id=getComboId([...combo]);
      comboShadowRecord(id,sym,decision,analysis.price,analysis.atr);
    }
  }

  // Rank every minute
  rankCombos();
}

let tickCount=0;
async function tick(){
  tickCount++;
  try{
    fetchNews().catch(()=>{});
    getSentiment().catch(()=>{});
    if(bot.mode==='live'&&bot.credentials){try{await fetchLiveBalance()}catch(e){botLog('Balance fetch err: '+e.message)}}
    // Sync real positions from KuCoin (fixes margin display, recovers after redeploy)
    if(bot.mode==='live')await syncKuCoinPositions().catch(()=>{});

    // Auto-tune settings based on current portfolio size
    autoTuneForBalance(getCurBal());

    // Shadow learning — analyze patterns from shadow trades
    shadowLearn();

    // ALWAYS fetch BTC first so altcoin agents know BTC's state
    try{
      const btcCandles=await fetchKlines('BTC-USDT','15min',100);
      const btcA=await analyze(btcCandles,'BTC-USDT');
      const c=btcCandles.map(x=>x.close);
      const priceNow=c[c.length-1];
      const price1hAgo=c[c.length-5]||priceNow; // 4 x 15min = 1h
      const price4hAgo=c[c.length-17]||priceNow; // 16 x 15min = 4h
      btcAnalysisCache={
        condition:btcA.condition,
        rsi:btcA.rsi,
        trendStrength:btcA.trendStrength,
        priceChange1h:((priceNow-price1hAgo)/price1hAgo)*100,
        priceChange4h:((priceNow-price4hAgo)/price4hAgo)*100,
        time:Date.now()
      };
    }catch(e){console.log('BTC context fetch err:',e.message)}

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

        // Update shadow trades for Sharpe tracking
        shadowUpdate(sym,price);
        // Run strategy combo tests in background
        runComboTests(a,sym);

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

        // ═══ SUPERVISOR CHECK ═══
        const supCheck=supervisorCheck();
        if(!supCheck.canTrade){
          if(sym===batch[0])botLog('🛑 '+supCheck.reason);
          continue;
        }

        // Drawdown
        const bal=getCurBal();if(bal>bot.peakBal)bot.peakBal=bal;
        const dd=((bot.peakBal-bal)/bot.peakBal)*100;
        const coin=sym.replace('-USDT','');
        if(dd>=bot.maxDrawdownPct){botLog(`${coin} SKIP: drawdown ${dd.toFixed(1)}% >= max ${bot.maxDrawdownPct}%`);continue}

        // ═══ DAILY PROFIT TARGET — stop trading when target hit ═══
        const today=new Date().toISOString().slice(0,10);
        if(bot.dailyDate!==today){bot.dailyPnL=0;bot.dailyDate=today}
        const dailyPctGain=(bot.dailyPnL/Math.max(bal,1))*100;
        const dailyTargetHit=dailyPctGain>=bot.dailyTargetPct;

        // After daily target: don't stop — just raise the bar significantly
        const confThreshold=dailyTargetHit?85:70;
        const tpProbThreshold=dailyTargetHit?85:65;

        // Limits
        if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<300000){continue}
        if(bot.openTrades.length>=bot.maxOpenTrades){botLog(`${coin} SKIP: max open trades ${bot.openTrades.length}/${bot.maxOpenTrades}`);continue}
        if(bot.openTrades.filter(t=>t.symbol===sym).length>=2){botLog(`${coin} SKIP: already 2 open trades for this coin`);continue}

        // ═══ TRADING DECISION — Promoted Combo (primary) or Council (fallback) ═══
        const council=councilVote(a,bot.requiredAgents);
        bot.lastCouncil[sym]=council;

        // Determine trade decision: promoted combo takes priority
        let tradeDecision=null;
        let tradeSource='council';
        let tradeConfidence=0;

        if(comboTracker.promotedCombo&&comboTracker.promotedCombo.winRate>=50){
          // USE PROMOTED COMBO — proven profitable strategy
          const comboSignals=comboTracker.promotedCombo.signals||comboTracker.promotedCombo.id.split('+');
          const comboDecision=evaluateCombo(comboSignals,a);
          if(comboDecision){
            tradeDecision=comboDecision;
            tradeSource='combo:'+comboTracker.promotedCombo.id;
            tradeConfidence=comboTracker.promotedCombo.winRate; // use historical win rate as confidence
            botLog(`${coin} 🧬 COMBO ${comboDecision.toUpperCase()} | ${comboSignals.join('+')} | WR:${comboTracker.promotedCombo.winRate}% | Sharpe:${comboTracker.promotedCombo.sharpe}`);
          }
        }

        // FALLBACK: use council if no promoted combo or combo didn't fire
        if(!tradeDecision&&council.decision!=='hold'){
          tradeDecision=council.decision;
          tradeSource='council';
          tradeConfidence=council.confidence;
          botLog(`${coin} → ${council.decision.toUpperCase()} | ${council.buyCount}buy(${council.buyScore||0}pts)/${council.sellCount}sell(${council.sellScore||0}pts) | conf:${council.confidence}% | HTF:${council.htf||'?'}${dailyTargetHit?' 🎯':''}`);
        }else if(!tradeDecision){
          // Log council holds
          if(council.blockReason)botLog(`${coin} ${council.blockReason}`);
          continue;
        }

        if(!tradeDecision)continue;

        // Shadow record
        const _slD=atr*bot.slATR,_tpD=atr*bot.tpATR;
        const _sl=tradeDecision==='buy'?price-_slD:price+_slD;
        const _tp=tradeDecision==='buy'?price+_tpD:price-_tpD;
        shadowRecord(sym,tradeDecision,price,_sl,_tp,tradeConfidence,tradeSource);

        // Confidence check (combo uses win rate, council uses vote confidence)
        if(tradeConfidence<confThreshold){
          botLog(`${coin} ${tradeDecision} conf ${tradeConfidence}% < ${confThreshold}%${dailyTargetHit?' (raised after 🎯)':''} [${tradeSource}]`);
          continue;
        }

        // ═══ CORRELATION FILTER ═══
        if(!checkCorrelation(sym,tradeDecision)){
          botLog(`${coin} SKIP: correlated trade open in ${getCorrelationGroup(sym)} group`);
          continue;
        }

        // ═══ REGIME DETECTION ═══
        const regime=detectRegime(a);
        if(!regime.tradeable){
          botLog(`${coin} SKIP: regime ${regime.regime} — ${regime.reason}`);
          continue;
        }

        // ═══ MONTE CARLO SIMULATION ═══
        const slDist=atr*bot.slATR;
        const tpDist=atr*bot.tpATR;
        // Calculate trend bias from condition: -1 (strong bear) to +1 (strong bull)
        let trendBias=0;
        if(a.condition==='strong_bullish')trendBias=0.7;
        else if(a.condition==='bullish')trendBias=0.4;
        else if(a.condition==='mildly_bullish')trendBias=0.2;
        else if(a.condition==='strong_bearish')trendBias=-0.7;
        else if(a.condition==='bearish')trendBias=-0.4;
        else if(a.condition==='mildly_bearish')trendBias=-0.2;
        // HTF alignment boosts bias
        const htf=a.htf||{};
        if(htf.bias&&htf.bias.includes('strong_bullish'))trendBias=Math.min(1,trendBias+0.3);
        else if(htf.bias&&htf.bias.includes('strong_bearish'))trendBias=Math.max(-1,trendBias-0.3);
        const mc=monteCarloSim(price,slDist,tpDist,tradeDecision,atr,trendBias);

        // ═══ TP PROBABILITY (hybrid: rule-based + Monte Carlo) ═══
        const htfAligned=(tradeDecision==='buy'&&htf.bias&&htf.bias.includes('bullish'))||
                         (tradeDecision==='sell'&&htf.bias&&htf.bias.includes('bearish'));
        const htfStrong=htf.bias&&htf.bias.includes('strong');
        let tpProb=50;
        if(htfAligned)tpProb+=15;
        if(htfStrong)tpProb+=10;
        if(council.confidence>=85)tpProb+=10;
        if(council.confidence>=75)tpProb+=5;
        if(tpDist/slDist>=2)tpProb+=5;
        if(tpDist/slDist<0.5)tpProb-=10; // only penalize really bad RR
        if(a.btc){
          const btcAgrees=(tradeDecision==='buy'&&a.btc.condition.includes('bullish'))||
                          (tradeDecision==='sell'&&a.btc.condition.includes('bearish'));
          if(btcAgrees)tpProb+=10;
          if(!btcAgrees&&!a.btc.condition.includes('neutral'))tpProb-=15;
        }
        // Blend with Monte Carlo (70% rule-based, 30% MC)
        tpProb=Math.round(tpProb*0.7+mc.tpProb*0.3);

        // Shadow learning adjustment: if shadow data shows one side winning more, adjust
        if(shadowLearning.preferredSide){
          if(tradeDecision===shadowLearning.preferredSide)tpProb+=5; // bonus for winning side
          else tpProb-=5; // penalty for losing side
        }

        if(tpProb<tpProbThreshold){
          botLog(`${coin} SKIP: TP ${tpProb}% < ${tpProbThreshold}% | MC:${mc.tpProb}%tp/${mc.slProb}%sl | regime:${regime.regime}${dailyTargetHit?' 🎯':''}`);
          // Still record as shadow trade for Sharpe tracking
          shadowRecord(sym,tradeDecision,price,price-(tradeDecision==='buy'?slDist:-slDist),price+(tradeDecision==='buy'?tpDist:-tpDist),council.confidence,'Skip');
          continue;
        }

        // ═══ QUANT GRADE — A+/A/B/C/Reject ═══
        const qg=quantGrade(council,tpProb,regime,mc,a.btc);
        if(qg.grade==='Reject'){
          botLog(`${coin} REJECT: quant score ${qg.score} — not worth the risk`);
          shadowRecord(sym,tradeDecision,price,price-(tradeDecision==='buy'?slDist:-slDist),price+(tradeDecision==='buy'?tpDist:-tpDist),council.confidence,qg.grade);
          continue;
        }

        const sl=tradeDecision==='buy'?price-slDist:price+slDist;
        const tp=tradeDecision==='buy'?price+tpDist:price-tpDist;

        // Record shadow trade (even if we execute — tracks all signals)
        shadowRecord(sym,tradeDecision,price,sl,tp,council.confidence,qg.grade);

        botLog(`${coin} ✓ Grade:${qg.grade}(${qg.score}) | TP:${tpProb}% | MC:${mc.tpProb}%tp | regime:${regime.regime} | R:R=${(tpDist/slDist).toFixed(1)} | exp:${mc.expectedReturn}%${dailyTargetHit?' 🎯 BONUS':''}`);

        // Auto-leverage: tighter SL = higher leverage for same risk
        const slDistPct=(atr*bot.slATR)/price*100;
        let autoLev=1;
        if(bot.tradingType!=='spot'){
          autoLev=Math.max(1,Math.min(bot.leverage,Math.round(bot.riskPct/slDistPct)));
          autoLev=Math.min(autoLev,bot.leverage);
        }

        // Position sizing (slDist already calculated above for TP probability)
        const riskUSD=bal*(bot.riskPct/100);
        let posUSD=Math.min(riskUSD/(slDist/price)*autoLev,bal*0.15);

        // KuCoin minimums
        const minSize=bot.tradingType==='spot'?1:1;

        // Use the RIGHT balance for the trade type (spot vs futures are separate accounts on KuCoin)
        let effectiveBal=bal;
        if(bot.mode==='live'&&liveBalanceCache){
          if(bot.tradingType==='spot'){
            effectiveBal=liveBalanceCache.spotUSD||bal;
          }else{
            effectiveBal=liveBalanceCache.futuresUSD||bal;
          }
        }

        // Subtract margin already locked in open trades (of same type)
        const lockedMargin=bot.openTrades.filter(t=>(bot.tradingType==='spot')?t.type==='spot':t.type!=='spot').reduce((s,t)=>s+(t.margin||t.usdAmount||0),0);
        const availableBal=Math.max(0,effectiveBal-lockedMargin);

        // GUARD: if available balance too low to trade meaningfully
        const minNeededForAnyTrade=bot.tradingType==='spot'?minSize*1.05:minSize*1.1; // just slightly above KuCoin min
        if(availableBal<minNeededForAnyTrade){
          botLog(`${coin} SKIP: available $${availableBal.toFixed(2)} < min $${minNeededForAnyTrade.toFixed(2)}`);
          continue;
        }

        // Hard cap: no single trade can exceed 40% of the effective account balance
        const hardCapMargin=effectiveBal*0.4;
        const useSmall=bot.smallBalanceMode==='on'||(bot.smallBalanceMode==='auto'&&effectiveBal<100);

        // Divide across remaining slots
        // For small balances: cap slots at 3 so each trade gets a meaningful budget
        let remainingSlots=Math.max(1,bot.maxOpenTrades-bot.openTrades.length);
        if(useSmall)remainingSlots=Math.min(remainingSlots,3);
        const perTradeBudget=Math.min(availableBal/remainingSlots,hardCapMargin);

        if(bot.tradingType==='spot'){
          if(useSmall){
            posUSD=perTradeBudget*0.95;
          }else{
            posUSD=Math.min(perTradeBudget*0.95,posUSD);
          }
          autoLev=1;
        }else{
          // Futures: KuCoin needs margin × 1.5 for fees/maintenance
          // So max usable margin = budget / 1.5
          const maxMargin=perTradeBudget/1.5;
          if(useSmall){
            posUSD=maxMargin*bot.leverage;
            autoLev=bot.leverage;
          }else{
            posUSD=Math.min(maxMargin*bot.leverage,posUSD);
          }
        }

        // Final check with realistic margin needed
        const theoreticalMargin=bot.tradingType==='spot'?posUSD:posUSD/autoLev;
        const realNeed=bot.tradingType==='spot'?theoreticalMargin:theoreticalMargin*1.5; // KuCoin needs ~50% extra for fees+maintenance
        if(realNeed>availableBal){
          botLog(`${coin} SKIP: KuCoin needs ~$${realNeed.toFixed(2)} (margin $${theoreticalMargin.toFixed(2)} +50% buffer) but only $${availableBal.toFixed(2)} free`);
          continue;
        }

        if(posUSD<minSize){
          botLog(`${coin} SKIP: pos $${posUSD.toFixed(2)} < min $${minSize}`);
          continue;
        }

        // Apply quant grade size multiplier (A+=100%, A=80%, B=60%, C=40%)
        // Apply grade multiplier only for accounts >$100 — small accounts can't afford to reduce further
        const gradeMult=bal>=100?qg.sizeMultiplier:Math.max(0.8,qg.sizeMultiplier); // small accounts: min 80%
        posUSD=Math.round(posUSD*gradeMult*(supCheck.riskReduction||1.0)*100)/100;
        if(posUSD<minSize){
          botLog(`${coin} SKIP: grade ${qg.grade} reduced pos to $${posUSD.toFixed(2)} < min $${minSize}`);
          continue;
        }

        const slPct=((slDist/price)*100).toFixed(2);

        // Execute
        if(bot.mode==='paper'){
          if(tradeDecision==='buy')paperBuy(sym,price,posUSD,sl,tp,council.confidence,council,'spot',autoLev);
          else if(tradeDecision==='sell')paperSell(sym,price,posUSD,sl,tp,council.confidence,council,autoLev);
        }else{
          // LIVE MODE
          const useFutures=bot.tradingType==='futures'||bot.tradingType==='combined';
          try{
            let orderResult,fillPrice=price,fillQty,realUSD,lev=autoLev;

            if(useFutures){
              // FUTURES — supports both long and short with leverage
              lev=bot.leverage;  // use configured leverage
              orderResult=await futuresOrder(tradeDecision,sym,posUSD,price,lev);
              fillQty=orderResult.qty;
              realUSD=posUSD;  // notional position value
              botLog(`LIVE FUTURES ${tradeDecision.toUpperCase()} ${sym} @$${fillPrice.toFixed(4)} | notional:$${realUSD.toFixed(2)} | lev:${lev}x | contracts:${orderResult.contracts} | margin:$${(realUSD/lev).toFixed(2)}`);
            }else{
              // SPOT — only long
              if(tradeDecision==='sell'){
                botLog(`${coin} SKIP: cannot short on spot. Switch to Futures/Combined mode.`);
                continue;
              }
              orderResult=await liveOrder(tradeDecision,sym,posUSD,price);
              fillQty=orderResult.qty||(posUSD/price);
              realUSD=fillPrice*fillQty;
              lev=1;
              botLog(`LIVE SPOT BUY ${sym} @$${fillPrice.toFixed(4)} | size:$${realUSD.toFixed(2)} | qty:${fillQty.toFixed(6)}`);
            }

            bot.openTrades.push({
              id:crypto.randomUUID().slice(0,8),
              orderId:orderResult.orderId,
              symbol:sym,
              side:tradeDecision,
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

// ═══ SYNC REAL POSITIONS FROM KUCOIN ═══
// Fixes: wrong margin display, position recovery after redeploy
let lastPositionSync=0;
async function syncKuCoinPositions(){
  if(!bot.credentials||bot.mode!=='live')return;
  if(Date.now()-lastPositionSync<30000)return; // max once per 30s
  lastPositionSync=Date.now();
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const ep='/api/v1/positions';
    const r=await fetch('https://api-futures.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
    const d=await safeJSON(r);
    if(d.code!=='200000'||!d.data)return;

    const realPositions=d.data.filter(p=>p.currentQty&&p.currentQty!==0);

    // Build contract→spot symbol map
    await getFuturesInfo('BTC-USDT');
    const contractToSpot={};
    for(const[spot,contract] of Object.entries(futuresInfoCache.symbolMap)){
      contractToSpot[contract]=spot;
    }

    // Update existing bot trades with REAL KuCoin data
    for(const pos of realPositions){
      const spotSym=contractToSpot[pos.symbol];
      if(!spotSym)continue;
      const side=pos.currentQty>0?'buy':'sell';
      const existing=bot.openTrades.find(t=>t.symbol===spotSym&&t.isLive&&t.type==='futures'&&t.side===side);
      const realLev=+pos.realLeverage||+pos.leverage||1;
      const entryPrice=+pos.avgEntryPrice||0;
      const uPnl=+pos.unrealisedPnl||0;
      const multiplier=futuresInfoCache.data[pos.symbol]?.multiplier||1;
      const qty=Math.abs(pos.currentQty)*multiplier;

      // KuCoin fields:
      // posCost = full position value (notional)
      // posInit = initial margin deposited
      // posMargin = total margin (init + maintenance buffer)
      // maintMarginReq = maintenance margin requirement
      const notional=Math.abs(+pos.posCost||0)||entryPrice*qty;
      const margin=Math.abs(+pos.posInit||+pos.posMargin||0)||(notional/realLev);

      if(existing){
        existing.margin=margin;
        existing.usdAmount=notional;
        existing.entryPrice=entryPrice;
        existing.leverage=realLev;
        existing.qty=qty;
        existing.realUPnL=uPnl;
      }else{
        bot.openTrades.push({
          id:crypto.randomUUID().slice(0,8),symbol:spotSym,side,type:'futures',
          leverage:realLev,entryPrice,qty,contracts:Math.abs(pos.currentQty),
          usdAmount:notional,margin:margin,realUPnL:uPnl,
          sl:null,tp:null,confidence:0,agreeing:0,
          openTime:new Date().toISOString(),status:'open',
          highSince:entryPrice,lowSince:entryPrice,trailingSl:null,
          isLive:true,recovered:true
        });
        botLog(`RECOVERED: ${side.toUpperCase()} ${spotSym} @$${entryPrice.toFixed(6)} | margin:$${margin.toFixed(2)} | notional:$${notional.toFixed(2)} | lev:${realLev.toFixed(1)}x`);
      }
    }

    // Remove bot trades that were closed on KuCoin directly
    const realSymSides=new Set(realPositions.map(p=>{
      const sp=contractToSpot[p.symbol]||'';
      return sp+'|'+(p.currentQty>0?'buy':'sell');
    }));
    const before=bot.openTrades.length;
    bot.openTrades=bot.openTrades.filter(t=>{
      if(!t.isLive||t.type!=='futures')return true;
      return realSymSides.has(t.symbol+'|'+t.side);
    });
    if(bot.openTrades.length<before)botLog(`Removed ${before-bot.openTrades.length} stale trade(s) — closed on KuCoin directly`);

    saveState();
  }catch(e){console.log('Position sync err:',e.message)}
}
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
    if(council.decision==='hold'||council.confidence<70)continue;
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
  if(bot.mode==='live')await syncKuCoinPositions().catch(()=>{});
  const bal=getCurBal(),dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0,tot=bot.winCount+bot.lossCount;
  const liveBal=bot.mode==='live'?liveBalanceCache:{};
  res.json({running:bot.running,mode:bot.mode,tradingType:bot.tradingType,symbols:bot.symbols,leverage:bot.leverage,
    tickCount,dailyPnL:bot.dailyPnL,dailyPctGain:bal>0?((bot.dailyPnL/bal)*100):0,dailyTargetPct:bot.dailyTargetPct,dailyTargetHit:bal>0&&((bot.dailyPnL/bal)*100)>=bot.dailyTargetPct,newsAge:newsCache.updated?Math.round((Date.now()-newsCache.updated)/1000):null,newsArticles:(newsCache.articles||[]).length,
    balance:Math.round(bal*100)/100,startBal:bot.startBal,totalPnL:Math.round(bot.totalPnL*100)/100,
    totalPnLPct:bot.startBal>0?Math.round((bal-bot.startBal)/bot.startBal*10000)/100:0,
    // Real portfolio data (live mode only)
    liveBalance:liveBal.totalUSD||null,liveBalances:liveBal.balances||null,
    isLive:bot.mode==='live',
    winCount:bot.winCount,lossCount:bot.lossCount,winRate:tot>0?Math.round(bot.winCount/tot*10000)/100:0,
    drawdown:Math.round(dd*100)/100,requiredAgents:bot.requiredAgents,totalAgents:Object.keys(AGENTS).length,
    openTrades:bot.openTrades.map(t=>{const cp=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;const dir=t.side==='buy'?1:-1;const calcUpnl=Math.round((cp-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)*100)/100;const upnl=t.realUPnL!==undefined?Math.round(t.realUPnL*100)/100:calcUpnl;return{...t,currentPrice:cp,unrealizedPnl:upnl,slPct:t.sl?((Math.abs(t.entryPrice-t.sl)/t.entryPrice)*100).toFixed(2)+'%':'—'}}),
    recentHistory:bot.history.slice(-30).reverse(),council:bot.lastCouncil,log:bot.log.slice(-50).reverse(),
    hasCredentials:!!bot.credentials,sentiment:sentimentCache,newsOverall:newsCache.overall,newsSentiment:newsCache.sentiment,recentNews:(newsCache.articles||[]).slice(0,15),
    // Top opportunities — ranked by council score
    opportunities:Object.entries(bot.lastCouncil).map(([sym,c])=>({symbol:sym.replace('-USDT',''),decision:c.decision,confidence:c.confidence,buyScore:c.buyScore,sellScore:c.sellScore,score:Math.max(c.buyScore||0,c.sellScore||0),htf:c.htf||'?'})).sort((a,b)=>b.score-a.score).slice(0,10),
    sharpe:getSharpe(),
    supervisor:{circuitBroken:supervisor.circuitBroken,mode:supervisor.mode,consecutiveLosses:supervisor.consecutiveLosses,consecutiveWins:supervisor.consecutiveWins,recentWinRate:supervisor.recentTrades.length>=5?Math.round(supervisor.recentTrades.slice(-10).filter(t=>t.isWin).length/Math.min(supervisor.recentTrades.length,10)*100):null,agentReport:getAgentReport(),recentAdjustments:supervisor.adjustments.slice(-5),autoTuneBal:lastAutoTuneBal},
    shadowStats:{active:shadowTrades.active.length,history:shadowTrades.history.length,wins:shadowTrades.stats.wins,losses:shadowTrades.stats.losses},
    learning:{confBuckets:shadowLearning.confBuckets,sideBias:shadowLearning.sideBias,insights:shadowLearning.insights},
    combos:{rankings:comboTracker.rankings.slice(0,15),promoted:comboTracker.promotedCombo,totalCombos:Object.keys(comboTracker.combos).length,totalTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.wins+c.losses,0)},
    // Market regime
    regime:{
      btc:btcAnalysisCache?{condition:btcAnalysisCache.condition,rsi:btcAnalysisCache.rsi,change1h:btcAnalysisCache.priceChange1h,change4h:btcAnalysisCache.priceChange4h}:null,
      sentiment:sentimentCache,
      newsOverall:newsCache.overall||{},
      volatility:btcAnalysisCache&&btcAnalysisCache.trendStrength?btcAnalysisCache.trendStrength:'unknown'
    },
    settings:{riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,dailyTargetPct:bot.dailyTargetPct,intervalMs:bot.intervalMs,requiredAgents:bot.requiredAgents}
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
  if(s.smallBalanceMode)bot.smallBalanceMode=s.smallBalanceMode;if(s.dailyTargetPct!==undefined)bot.dailyTargetPct=Math.max(0.5,Math.min(10,+s.dailyTargetPct));if(s.dailyTargetPct)bot.dailyTargetPct=s.dailyTargetPct;
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
// Full quant analysis for a single coin
app.get('/api/bot/quant/:sym',mw,async(req,res)=>{
  const sym=req.params.sym;
  try{
    const c15=await fetchKlines(sym,'15min',100);
    const a=await analyze(c15,sym);
    const council=councilVote(a,bot.requiredAgents);
    const regime=detectRegime(a);
    const slDist=a.atr*bot.slATR;const tpDist=a.atr*bot.tpATR;
    let trendBias=0;
    if(a.condition==='strong_bullish')trendBias=0.7;
    else if(a.condition==='bullish')trendBias=0.4;
    else if(a.condition==='mildly_bullish')trendBias=0.2;
    else if(a.condition==='strong_bearish')trendBias=-0.7;
    else if(a.condition==='bearish')trendBias=-0.4;
    else if(a.condition==='mildly_bearish')trendBias=-0.2;
    const side=council.decision!=='hold'?council.decision:'buy';
    const mc=monteCarloSim(a.price,slDist,tpDist,side,a.atr,trendBias);
    const qg=quantGrade(council,mc.tpProb,regime,mc,a.btc);
    const sharpe=getSharpe();
    const bbPos=a.bbUpper&&a.bbLower?Math.round((a.price-a.bbLower)/(a.bbUpper-a.bbLower)*100):null;
    const atrPct=a.atr&&a.price?Math.round((a.atr/a.price)*10000)/100:null;
    res.json({success:true,symbol:sym,price:a.price,condition:a.condition,trendStrength:a.trendStrength,
      indicators:{
        ema9:a.ema9,ema21:a.ema21,ema50:a.ema50,
        rsi:a.rsi,prevRsi:a.prevRsi,
        macdHist:a.macdHist,macdLine:a.macdLine,macdSignal:a.macdSignal,
        bbUpper:a.bbUpper,bbLower:a.bbLower,bbSma:a.bbSma,bbPosition:bbPos,
        atr:a.atr,atrPct,
        adx:a.adx,diPlus:a.diPlus,diMinus:a.diMinus,
        vwap:a.vwap,obvTrend:a.obvTrend,volTrend:a.volTrend,
        support:a.support,resistance:a.resistance,inGoldenPocket:a.inGoldenPocket,
        stochK:a.stochK,stochD:a.stochD
      },
      council:{decision:council.decision,confidence:council.confidence,buyCount:council.buyCount,sellCount:council.sellCount,buyScore:council.buyScore,sellScore:council.sellScore,weightThreshold:council.weightThreshold,votes:council.votes},
      regime,monteCarlo:mc,quantGrade:qg,sharpe,
      levels:{sl:side==='buy'?a.price-slDist:a.price+slDist,tp:side==='buy'?a.price+tpDist:a.price-tpDist,slDist,tpDist,rrRatio:Math.round(tpDist/slDist*10)/10},
      btc:a.btc||null,
      correlation:{group:getCorrelationGroup(sym),canTrade:checkCorrelation(sym,side)}
    });
  }catch(e){res.json({success:false,error:e.message})}
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
  const dBal=getCurBal();const dPct=dBal>0?((bot.dailyPnL/dBal)*100):0;
  h+='dailyPnL: $'+bot.dailyPnL.toFixed(2)+' ('+dPct.toFixed(2)+'%) | target: '+bot.dailyTargetPct+'% '+(dPct>=bot.dailyTargetPct?'<span class="ok">🎯 TARGET HIT — only 85%+ TP prob trades allowed</span>':'<span class="warn">trading (65%+ TP prob)</span>')+'\n';
  const sharpe=getSharpe();
  h+='</pre><h2>QUANT STATS (Shadow Trading)</h2><pre>';
  h+='sharpe: '+(sharpe.sharpe>=1.5?'<span class="ok">':'<span class="warn">')+sharpe.sharpe+'</span> | winRate: '+sharpe.winRate+'% | avgReturn: '+sharpe.mean+'% | signals: '+sharpe.trades+'\n';
  h+='shadow active: '+shadowTrades.active.length+' | resolved: '+shadowTrades.history.length+' | W:'+shadowTrades.stats.wins+' L:'+shadowTrades.stats.losses+'\n';
  h+='</pre><h2>SUPERVISOR</h2><pre>';
  h+='circuit breaker: '+(supervisor.circuitBroken?'<span class="bad">ACTIVE — '+(Math.round((supervisor.circuitBreakUntil-Date.now())/60000))+'min left</span>':'<span class="ok">OFF</span>')+'\n';
  h+='consecutive: W:'+supervisor.consecutiveWins+' L:'+supervisor.consecutiveLosses+'\n';
  const ar=getAgentReport();
  if(Object.keys(ar).length){
    h+='agent accuracy:\n';
    for(const[name,s] of Object.entries(ar)){
      const col=s.rating==='reliable'?'ok':s.rating==='average'?'warn':'bad';
      h+='  '+name.padEnd(18)+' <span class="'+col+'">'+s.accuracy+'%</span> ('+s.correct+'/'+s.total+') '+s.rating+'\n';
    }
  }else h+='agent accuracy: no data yet\n';
  if(supervisor.adjustments.length){
    h+='recent adjustments:\n';
    for(const a of supervisor.adjustments.slice(-5))h+='  '+new Date(a.time).toLocaleTimeString()+' '+a.action+'\n';
  }
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

// Raw KuCoin positions — shows exactly what KuCoin returns
app.get('/debug/positions',async(req,res)=>{
  if(!bot.credentials)return res.json({error:'No credentials'});
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const ep='/api/v1/positions';
    const r=await fetch('https://api-futures.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
    const d=await safeJSON(r);
    if(d.code!=='200000')return res.json({error:d.msg});
    const positions=d.data.filter(p=>p.currentQty&&p.currentQty!==0);
    // Show relevant fields
    const summary=positions.map(p=>({
      symbol:p.symbol,
      side:p.currentQty>0?'LONG':'SHORT',
      contracts:Math.abs(p.currentQty),
      entryPrice:p.avgEntryPrice,
      markPrice:p.markPrice,
      leverage:p.realLeverage,
      posCost:p.posCost,     // what we THOUGHT was margin
      posInit:p.posInit,     // actual initial margin
      posMargin:p.posMargin, // total margin held
      posMaint:p.posMaint,   // maintenance margin
      unrealisedPnl:p.unrealisedPnl,
      liquidationPrice:p.liquidationPrice,
      marginType:p.marginType
    }));
    // Also show what the bot thinks
    const botTrades=bot.openTrades.filter(t=>t.isLive).map(t=>({
      symbol:t.symbol,side:t.side,botMargin:t.margin,botUsdAmount:t.usdAmount,botLev:t.leverage
    }));
    res.json({success:true,kucoin:summary,bot:botTrades,raw:positions});
  }catch(e){res.json({error:e.message})}
});
app.get('/api/bot/wallet',mw,async(req,res)=>{
  if(!bot.credentials)return res.json({connected:false});
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;
    const bals={};let spotUSD=0,futuresUSD=0,mainUSD=0;

    // Check ALL spot account types (trade + main + margin)
    for(const type of ['trade','main','margin']){
      try{
        const ep='/api/v1/accounts?type='+type;
        const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
        const d=await safeJSON(r);
        if(d.code==='200000'&&d.data){
          for(const a of d.data){const v=parseFloat(a.available)+parseFloat(a.holds||0);if(v>0){const key=a.currency+' ('+type+')';bals[key]=v}}
        }
      }catch(e){console.log(type+' bal err:',e.message)}
    }

    // Price map
    let pm={USDT:1,USDC:1};
    try{
      const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);
      if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;
    }catch{}

    // Sum spot/main value
    for(const[k,v] of Object.entries(bals)){
      const cur=k.split(' ')[0];
      const usd=(pm[cur]||0)*v;
      if(k.includes('(trade)'))spotUSD+=usd;
      else if(k.includes('(main)'))mainUSD+=usd;
    }

    // Check FUTURES account
    try{
      const fep='/api/v1/account-overview?currency=USDT';
      const fr=await fetch('https://api-futures.kucoin.com'+fep,{headers:kcH('GET',fep,null,apiKey,apiSecret,passphrase)});
      const fd=await safeJSON(fr);
      if(fd.code==='200000'&&fd.data){
        futuresUSD=+fd.data.accountEquity||+fd.data.availableBalance||0;
        if(futuresUSD>0)bals['USDT (futures)']=futuresUSD;
      }else{
        bals['_futures_error']=fd.msg||'Cannot access futures (check API permissions)';
      }
    }catch(e){bals['_futures_error']=e.message}

    const total=spotUSD+mainUSD+futuresUSD;
    res.json({connected:true,balances:bals,totalUSD:Math.round(total*100)/100,spotUSD:Math.round(spotUSD*100)/100,futuresUSD:Math.round(futuresUSD*100)/100,mainUSD:Math.round(mainUSD*100)/100});
  }catch(e){res.json({connected:false,error:e.message})}
});

app.post('/api/kucoin/balance',async(req,res)=>{
  const{apiKey,apiSecret,passphrase}=req.body||{};
  if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All required'});
  try{
    const bals={};let spotUSD=0,futuresUSD=0,mainUSD=0;

    // Spot/trade/main accounts
    for(const type of ['trade','main','margin']){
      try{
        const ep='/api/v1/accounts?type='+type;
        const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});
        const d=await safeJSON(r);
        if(d.code==='200000'&&d.data){
          for(const a of d.data){const v=parseFloat(a.available)+parseFloat(a.holds||0);if(v>0)bals[a.currency+' ('+type+')']=v}
        }
      }catch{}
    }

    let pm={USDT:1,USDC:1};
    try{
      const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);
      if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0;
    }catch{}

    for(const[k,v] of Object.entries(bals)){
      const cur=k.split(' ')[0];const usd=(pm[cur]||0)*v;
      if(k.includes('(trade)'))spotUSD+=usd;
      else if(k.includes('(main)'))mainUSD+=usd;
    }

    let futuresError=null;
    try{
      const fep='/api/v1/account-overview?currency=USDT';
      const fr=await fetch('https://api-futures.kucoin.com'+fep,{headers:kcH('GET',fep,null,apiKey,apiSecret,passphrase)});
      const fd=await safeJSON(fr);
      if(fd.code==='200000'&&fd.data){
        futuresUSD=+fd.data.accountEquity||+fd.data.availableBalance||0;
        if(futuresUSD>0)bals['USDT (futures)']=futuresUSD;
      }else{
        futuresError=fd.msg||'Cannot access futures — API key may lack futures permissions';
      }
    }catch(e){futuresError=e.message}

    const total=spotUSD+mainUSD+futuresUSD;
    res.json({success:true,balances:bals,totalUSD:total,spotUSD,futuresUSD,mainUSD,futuresError});
  }catch(e){res.status(500).json({error:e.message})}
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

// Combo rankings — full detail
app.get('/api/bot/combos',mw,(req,res)=>{
  rankCombos();
  res.json({
    success:true,
    totalCombos:Object.keys(comboTracker.combos).length,
    totalDemoTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.wins+c.losses,0),
    activeTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.trades.filter(t=>!t.resolved).length,0),
    promoted:comboTracker.promotedCombo,
    rankings:comboTracker.rankings,
    signalLibrary:SIGNAL_NAMES
  });
});

app.get('/health',(_,res)=>res.json({status:'ok'}));

// Public overview page — shareable with AI tools, no auth needed
app.get('/about',(req,res)=>{
  const format=req.query.format;
  const data={
    name:'TradeMatrix Pro',
    version:'v4 (Quant Edition)',
    description:'Autonomous multi-agent crypto trading bot with institutional quant features. Runs 24/7 on Railway cloud, connected to KuCoin exchange (spot + futures). Uses 10 specialist AI agents organized in 3 manipulation-resistant tiers that vote on every trade. Only executes when strict 5-gate consensus + Monte Carlo simulation + quant grading confirms edge.',
    architecture:{
      backend:'Node.js / Express',
      hosting:'Railway cloud (Singapore region, 24/7)',
      exchange:'KuCoin (spot + futures via REST API)',
      frontend:'Vanilla HTML/CSS/JS single-page dashboard',
      dataSources:['KuCoin (price/candle data)','CryptoCompare (crypto news)','CoinGecko (news + market data)','CoinPaprika (events)','Alternative.me (Fear & Greed Index)'],
      auth:'Email/password with JWT tokens'
    },
    tradingEngine:{
      coinsScanned:ALL_SYMBOLS.length,
      coinList:ALL_SYMBOLS.map(s=>s.replace('-USDT','')),
      timeframes:['15-minute (entry)','1-hour (confirmation)','4-hour (big picture)'],
      scanInterval:'45 seconds per batch of 5 coins',
      fullScanTime:Math.ceil(ALL_SYMBOLS.length/5)+' batches (~'+(Math.ceil(ALL_SYMBOLS.length/5)*0.75).toFixed(0)+' minutes)'
    },
    agentCouncil:{
      totalAgents:10,
      tiers:{
        tier1:{weight:'3x',agents:['Trend Master (EMA 9/21/50 + ADX)','Fibonacci Analyst (S/R + golden pocket)','ATR Volatility (squeeze detection)','Sentiment Analyst (Fear & Greed + news)','BTC Correlation (alt-BTC alignment)'],description:'Hardest to manipulate — whales cannot fake these signals'},
        tier2:{weight:'2x',agents:['MACD Specialist (crossovers + divergence)','Bollinger Trader (band position + mean reversion)','Quant AI (z-score + ROC + mean reversion)'],description:'Moderate manipulation risk — lagging indicators provide buffer'},
        tier3:{weight:'1x',agents:['Momentum Hunter (RSI context-aware)','Volume Expert (OBV + VWAP)'],description:'Easiest to manipulate — lowest voting weight'}
      },
      contextAware:'Agents interpret indicators based on market trend (RSI 42 in uptrend = buy dip, not sell)'
    },
    tradeExecution:{
      gates:[
        {gate:1,name:'Council Consensus',requirement:'70%+ confidence, weighted points threshold, 2+ Tier 1 agents'},
        {gate:2,name:'Correlation Filter',requirement:'Max 1 trade per correlated asset group (8 groups defined)'},
        {gate:3,name:'Regime Detection',requirement:'7 regime types — refuses trades in HIGH_VOL_CHAOS, LOW_VOL_DRIFT, UNCERTAIN'},
        {gate:4,name:'Monte Carlo Simulation',requirement:'200 random price path simulations using real ATR volatility + trend drift'},
        {gate:5,name:'TP Probability',requirement:'65%+ blended probability (70% rule-based + 30% Monte Carlo)'},
        {gate:6,name:'Quant Grade',requirement:'A+/A/B/C/Reject scoring (85-100 = A+, <40 = Reject)'},
        {gate:7,name:'Daily Profit Target',requirement:'After 1.5% daily gain, thresholds raise to 85%+ (only A+ setups)'},
        {gate:8,name:'Supervisor Check',requirement:'Circuit breaker (3 losses = 15min pause), risk reduction on losing streaks'},
        {gate:9,name:'Position Sizing',requirement:'Divided across trade slots, margin buffer for KuCoin, grade multiplier'}
      ]
    },
    quantFeatures:{
      monteCarlo:'200 simulations with dynamic step count based on ATR/price ratio. Uses trend-aligned drift (12% of vol). Reports TP%, SL%, expected return, worst case.',
      regimeDetection:'7 regimes: TRENDING_UP, TRENDING_DOWN, MEAN_REVERTING, BREAKOUT_COMPRESSION, HIGH_VOL_CHAOS, LOW_VOL_DRIFT, UNCERTAIN. Uses ATR, ADX, BB width, RSI.',
      quantGrade:'0-100 scoring → A+/A/B/C/Reject. Factors: council confidence (30pts), TP probability (25pts), MC confirmation (20pts), regime quality (15pts), BTC alignment (10pts). Grade determines position size multiplier.',
      correlationGroups:'8 asset groups (L1, ETH, ALT_HIGH, ALT_MID, ALT_LOW, MEME, AI_GAMING, DEFI2). Max 1 open trade per group per direction.',
      shadowTrading:'Silent paper portfolio tracks ALL council signals. Resolves against real price within 12 hours. Builds Sharpe ratio, win rate by confidence bucket, buy/sell bias analysis.',
      shadowLearning:'Every 5 minutes, analyzes shadow results and AUTO-ADJUSTS: widens SL if hit too often, brings TP closer if rarely reached, reduces leverage on negative Sharpe, restores on positive Sharpe.',
      supervisorBot:'Monitors real trade performance. 3 consecutive losses → circuit breaker (15min pause + reduced leverage + stricter agent requirements). Tracks per-agent accuracy. 4 modes: NORMAL, CAUTIOUS, RECOVERY, AGGRESSIVE.',
      autoTune:'Automatically adjusts leverage, risk%, SL, TP, max trades based on portfolio size. 7 tiers from MICRO (<$10) to STANDARD ($1K+).'
    },
    riskManagement:{
      stopLoss:'ATR-based (configurable multiplier)',
      takeProfit:'ATR-based (configurable multiplier)',
      trailingStop:'ATR-based trailing, activates after entry',
      maxDrawdown:'15% (configurable)',
      dailyTarget:'1.5% (configurable, raises thresholds when hit)',
      circuitBreaker:'3 consecutive losses → 15 minute pause + auto-reduce risk parameters',
      positionSizing:'Risk-based with balance division across trade slots, KuCoin margin buffer'
    },
    indicators:['EMA 9/21/50','RSI (context-aware)','MACD (line/signal/histogram)','Bollinger Bands (upper/lower/position%)','ATR (Average True Range)','ADX (trend strength)','Fibonacci (support/resistance/golden pocket)','VWAP','OBV (On-Balance Volume)','Stochastic RSI','Volume Trend','BTC price correlation (1h/4h change)'],
    dashboardPages:['Overview (wallet, stats, positions, log, market regime, opportunities, quant stats, supervisor)','Council (10-agent vote visualization with confidence bars)','Trades (history with PnL)','News (live crypto + macro news with sentiment scoring)','Chart (TradingView embed with all timeframes)','Analysis (full quant report per coin — all indicators + MC + regime + grade + agent votes)','Backtest (historical strategy testing)','AI Advisor (Claude-powered analysis via Anthropic API)','Settings (configurable everything)','Connect (KuCoin API setup)'],
    currentStatus:{
      running:bot.running,
      mode:bot.mode,
      tradingType:bot.tradingType,
      openTrades:bot.openTrades.length,
      completedTrades:bot.history.length,
      tickCount:typeof tickCount!=='undefined'?tickCount:0,
      supervisorMode:supervisor.mode,
      shadowSignals:shadowTrades.history.length,
      sharpe:getSharpe()
    }
  };

  if(format==='json')return res.json(data);

  // HTML version
  let h='<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TradeMatrix Pro — About</title><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#06090f;color:#c8d6e5;font-family:system-ui,-apple-system,sans-serif;padding:20px;max-width:900px;margin:0 auto;line-height:1.7;font-size:14px}h1{color:#00e676;font-size:24px;margin-bottom:4px}h2{color:#40c4ff;font-size:16px;margin:24px 0 8px;border-bottom:1px solid #1a2a3c;padding-bottom:4px}h3{color:#ffab40;font-size:13px;margin:12px 0 4px}p{margin:4px 0;color:#7a96b4}code{background:#0f1923;padding:2px 6px;border-radius:3px;font-size:12px;color:#e2eaf3}ul{margin:4px 0 4px 20px;color:#7a96b4}li{margin:2px 0}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin:2px 0}.bg{background:rgba(0,230,118,0.15);color:#00e676}.bb{background:rgba(64,196,255,0.15);color:#40c4ff}.bp{background:rgba(179,136,255,0.15);color:#b388ff}.ba{background:rgba(255,171,64,0.15);color:#ffab40}.br{background:rgba(255,82,82,0.15);color:#ff5252}.card{background:#0a1018;border:1px solid #1a2a3c;border-radius:8px;padding:14px;margin:8px 0}.mono{font-family:monospace;font-size:12px}.status{display:flex;flex-wrap:wrap;gap:8px}.stat{background:#0f1923;padding:8px 12px;border-radius:6px;text-align:center}.stat-label{font-size:9px;color:#3d5a78;text-transform:uppercase}.stat-val{font-size:16px;font-weight:700;color:#e2eaf3;font-family:monospace}</style></head><body>';
  h+='<h1>◆ '+data.name+' '+data.version+'</h1>';
  h+='<p>'+data.description+'</p>';
  h+='<p style="margin-top:8px"><span class="badge bg">'+data.tradingEngine.coinsScanned+' Coins</span> <span class="badge bb">10 Agents</span> <span class="badge bp">3 Tiers</span> <span class="badge ba">9 Gates</span> <span class="badge br">Monte Carlo</span></p>';

  h+='<h2>Live Status</h2><div class="status">';
  h+='<div class="stat"><div class="stat-label">Bot</div><div class="stat-val" style="color:'+(data.currentStatus.running?'#00e676':'#ff5252')+'">'+(data.currentStatus.running?'RUNNING':'OFF')+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Mode</div><div class="stat-val">'+data.currentStatus.mode.toUpperCase()+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Open</div><div class="stat-val">'+data.currentStatus.openTrades+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Completed</div><div class="stat-val">'+data.currentStatus.completedTrades+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Scans</div><div class="stat-val">'+data.currentStatus.tickCount+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Supervisor</div><div class="stat-val">'+data.currentStatus.supervisorMode.toUpperCase()+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Shadow</div><div class="stat-val">'+data.currentStatus.shadowSignals+'</div></div>';
  h+='<div class="stat"><div class="stat-label">Sharpe</div><div class="stat-val">'+data.currentStatus.sharpe.sharpe+'</div></div>';
  h+='</div>';

  h+='<h2>Agent Council</h2>';
  for(const[tier,info] of Object.entries(data.agentCouncil.tiers)){
    const cls=tier==='tier1'?'bg':tier==='tier2'?'bb':'bp';
    h+='<h3><span class="badge '+cls+'">'+tier.toUpperCase()+' ('+info.weight+')</span> '+info.description+'</h3><ul>';
    for(const a of info.agents)h+='<li>'+a+'</li>';
    h+='</ul>';
  }

  h+='<h2>Trade Execution (9 Gates)</h2>';
  for(const g of data.tradeExecution.gates)h+='<div class="card"><strong style="color:#40c4ff">Gate '+g.gate+': '+g.name+'</strong><br/><span style="color:#7a96b4">'+g.requirement+'</span></div>';

  h+='<h2>Quant Features</h2>';
  for(const[k,v] of Object.entries(data.quantFeatures))h+='<div class="card"><strong style="color:#ffab40">'+k.replace(/([A-Z])/g,' $1').trim()+'</strong><br/><span style="color:#7a96b4">'+v+'</span></div>';

  h+='<h2>Indicators ('+data.indicators.length+')</h2><p>'+data.indicators.join(' · ')+'</p>';
  h+='<h2>Coins ('+data.tradingEngine.coinsScanned+')</h2><p>'+data.tradingEngine.coinList.join(', ')+'</p>';
  h+='<h2>Dashboard Pages ('+data.dashboardPages.length+')</h2><ul>';
  for(const p of data.dashboardPages)h+='<li>'+p+'</li>';
  h+='</ul>';
  h+='<h2>Architecture</h2><ul>';
  for(const[k,v] of Object.entries(data.architecture)){if(Array.isArray(v))h+='<li><strong>'+k+':</strong> '+v.join(', ')+'</li>';else h+='<li><strong>'+k+':</strong> '+v+'</li>'}
  h+='</ul>';

  h+='<div style="margin-top:30px;padding:12px;border:1px solid #1a2a3c;border-radius:8px;font-size:11px;color:#3d5a78">API: Add <code>?format=json</code> to get this data as JSON for programmatic access.</div>';
  h+='</body></html>';
  res.send(h);
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(_,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const PORT=process.env.PORT||3000;
app.listen(PORT,'0.0.0.0',()=>console.log(`TradeMatrix Pro v4 Council → http://localhost:${PORT}`));

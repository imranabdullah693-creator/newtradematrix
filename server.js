const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const app=express(),PORT=process.env.PORT||3000;
app.use(express.json());app.use(express.static('public'));

// ═══ FULL INDICATOR LIBRARY ═══
const TA={
  sma(c,p){const r=[];for(let i=p-1;i<c.length;i++)r.push(c.slice(i-p+1,i+1).reduce((a,b)=>a+b,0)/p);return r},
  ema(c,p){const k=2/(p+1);const r=[c[0]];for(let i=1;i<c.length;i++)r.push(c[i]*k+r[i-1]*(1-k));return r},
  rsi(c,p=14){const r=[];let g=0,l=0;for(let i=1;i<=p;i++){const d=c[i]-c[i-1];if(d>0)g+=d;else l-=d}g/=p;l/=p;r.push(l===0?100:100-100/(1+g/l));for(let i=p+1;i<c.length;i++){const d=c[i]-c[i-1];g=(g*(p-1)+(d>0?d:0))/p;l=(l*(p-1)+(d<0?-d:0))/p;r.push(l===0?100:100-100/(1+g/l))}return r},
  atr(h,l,c,p=14){const tr=[];for(let i=1;i<c.length;i++)tr.push(Math.max(h[i]-l[i],Math.abs(h[i]-c[i-1]),Math.abs(l[i]-c[i-1])));return TA.sma(tr,p)},
  macd(c,f=12,s=26,sig=9){const fast=TA.ema(c,f),slow=TA.ema(c,s),line=[];for(let i=0;i<c.length;i++)line.push((fast[i]||0)-(slow[i]||0));const signal=TA.ema(line,sig),hist=[];for(let i=0;i<line.length;i++)hist.push(line[i]-(signal[i]||0));return{line,signal,hist}},
  bollinger(c,p=20,m=2){const sma=TA.sma(c,p),u=[],lo=[];for(let i=p-1;i<c.length;i++){const sl=c.slice(i-p+1,i+1),mn=sma[i-p+1],std=Math.sqrt(sl.reduce((a,v)=>a+(v-mn)**2,0)/p);u.push(mn+m*std);lo.push(mn-m*std)}return{sma,upper:u,lower:lo}},
  stochRSI(c,rP=14,sP=14,kP=3,dP=3){const rsi=TA.rsi(c,rP);if(rsi.length<sP)return{k:[],d:[]};const st=[];for(let i=sP-1;i<rsi.length;i++){const sl=rsi.slice(i-sP+1,i+1),mn=Math.min(...sl),mx=Math.max(...sl);st.push(mx===mn?50:((rsi[i]-mn)/(mx-mn))*100)}return{k:TA.sma(st,kP),d:TA.sma(TA.sma(st,kP),dP)}},
  adx(h,l,c,p=14){const pDI=[],nDI=[],tr=[];for(let i=1;i<c.length;i++){const pH=h[i]-h[i-1],nL=l[i-1]-l[i];pDI.push(pH>nL&&pH>0?pH:0);nDI.push(nL>pH&&nL>0?nL:0);tr.push(Math.max(h[i]-l[i],Math.abs(h[i]-c[i-1]),Math.abs(l[i]-c[i-1])))}const sTR=TA.ema(tr,p),sPDI=TA.ema(pDI,p),sNDI=TA.ema(nDI,p);const diP=[],diM=[],dx=[];for(let i=0;i<sTR.length;i++){const dp=sTR[i]?sPDI[i]/sTR[i]*100:0,dm=sTR[i]?sNDI[i]/sTR[i]*100:0;diP.push(dp);diM.push(dm);dx.push(dp+dm>0?Math.abs(dp-dm)/(dp+dm)*100:0)}return{adx:TA.ema(dx,p),diPlus:diP,diMinus:diM}},
  vwap(h,l,c,v){let cv=0,ct=0;const r=[];for(let i=0;i<c.length;i++){const tp=(h[i]+l[i]+c[i])/3;ct+=tp*v[i];cv+=v[i];r.push(cv>0?ct/cv:tp)}return r},
  obv(c,v){const r=[0];for(let i=1;i<c.length;i++)r.push(r[i-1]+(c[i]>c[i-1]?v[i]:c[i]<c[i-1]?-v[i]:0));return r},
  fibonacci(h,l,c){const hh=Math.max(...h.slice(-50)),ll=Math.min(...l.slice(-50)),d=hh-ll,p=c[c.length-1];const levels={0:hh,0.236:hh-d*0.236,0.382:hh-d*0.382,0.5:hh-d*0.5,0.618:hh-d*0.618,0.786:hh-d*0.786,1:ll};let nearS=ll,nearR=hh;for(const lv of Object.values(levels)){if(lv<p&&lv>nearS)nearS=lv;if(lv>p&&lv<nearR)nearR=lv}return{levels,nearestSupport:nearS,nearestResistance:nearR,inGoldenPocket:p>=levels[0.618]&&p<=levels[0.5]}},
  cci(h,l,c,p=20){const r=[];for(let i=p-1;i<c.length;i++){const tp_arr=[];for(let j=i-p+1;j<=i;j++)tp_arr.push((h[j]+l[j]+c[j])/3);const tp=(h[i]+l[i]+c[i])/3;const mean=tp_arr.reduce((a,b)=>a+b,0)/p;const md=tp_arr.reduce((a,b)=>a+Math.abs(b-mean),0)/p;r.push(md>0?(tp-mean)/(0.015*md):0)}return r},
  supertrend(h,l,c,p=10,m=3){const atr=TA.atr(h,l,c,p);const r=[];let trend=1,ub=0,lb=0;for(let i=0;i<c.length;i++){if(i<p){r.push({trend:1,val:c[i]});continue}const a=atr[Math.min(i-1,atr.length-1)]||0;const bub=(h[i]+l[i])/2+m*a;const blb=(h[i]+l[i])/2-m*a;ub=c[i-1]>ub?Math.min(bub,ub):bub;lb=c[i-1]<lb?Math.max(blb,lb):blb;if(c[i]>ub)trend=1;else if(c[i]<lb)trend=-1;r.push({trend,val:trend===1?lb:ub})}return r},
  choppiness(h,l,c,p=14){if(h.length<p+1)return[];const atr=TA.atr(h,l,c,1);const res=[];for(let i=p;i<c.length;i++){const sa=atr.slice(Math.max(0,i-p),i).reduce((a,b)=>a+b,0);const hh=Math.max(...h.slice(i-p,i));const ll=Math.min(...l.slice(i-p,i));const rng=hh-ll;res.push(rng>0?100*Math.log10(sa/rng)/Math.log10(p):50)}return res},
  pivotPoints(h,l,c){const i=c.length-2;if(i<0)return{pp:0,r1:0,r2:0,s1:0,s2:0};const pp=(h[i]+l[i]+c[i])/3;return{pp,r1:2*pp-l[i],r2:pp+(h[i]-l[i]),s1:2*pp-h[i],s2:pp-(h[i]-l[i])}},
  higherHighsLows(h,l,n=10){if(h.length<n)return{hh:0,hl:0,lh:0,ll:0,trend:'unclear'};let hh=0,hl=0,lh=0,ll=0;const s=h.length-n;for(let i=s+2;i<h.length;i+=2){if(h[i]>h[i-2])hh++;else lh++;if(l[i]>l[i-2])hl++;else ll++}return{hh,hl,lh,ll,trend:hh>lh&&hl>ll?'uptrend':lh>hh&&ll>hl?'downtrend':'unclear'}},
  trendSlope(c,p=20){if(c.length<p)return 0;const r=c.slice(-p);const n=r.length;const xM=(n-1)/2,yM=r.reduce((a,b)=>a+b,0)/n;let num=0,den=0;for(let i=0;i<n;i++){num+=(i-xM)*(r[i]-yM);den+=(i-xM)**2}return den>0?(num/den)/yM*100:0},
  candlePatterns(o,h,l,c){const n=c.length;if(n<3)return[];const pats=[];const i=n-1;const body=Math.abs(c[i]-o[i]),range=h[i]-l[i];const isG=c[i]>o[i],prevG=c[i-1]>o[i-1];const uW=isG?h[i]-c[i]:h[i]-o[i],lW=isG?o[i]-l[i]:c[i]-l[i];const pBody=Math.abs(c[i-1]-o[i-1]);
    if(range>0&&body/range<0.1)pats.push('doji');
    if(range>0&&lW>body*2&&uW<body*0.5)pats.push('hammer');
    if(range>0&&uW>body*2&&lW<body*0.5)pats.push('shooting_star');
    if(isG&&!prevG&&c[i]>o[i-1]&&o[i]<c[i-1]&&body>pBody)pats.push('bullish_engulfing');
    if(!isG&&prevG&&c[i]<o[i-1]&&o[i]>c[i-1]&&body>pBody)pats.push('bearish_engulfing');
    if(h[i]<h[i-1]&&l[i]>l[i-1])pats.push('inside_bar');
    if(n>=3&&c[i]>o[i]&&c[i-1]>o[i-1]&&c[i-2]>o[i-2])pats.push('three_green');
    if(n>=3&&c[i]<o[i]&&c[i-1]<o[i-1]&&c[i-2]<o[i-2])pats.push('three_red');
    if(range>0&&lW>range*0.6)pats.push('pin_bar_bull');
    if(range>0&&uW>range*0.6)pats.push('pin_bar_bear');
    return pats;
  },
  volTrend(v,p=20){if(v.length<p)return'normal';const rec=v.slice(-5).reduce((a,b)=>a+b,0)/5,avg=v.slice(-p).reduce((a,b)=>a+b,0)/p;return rec>avg*1.5?'high':rec<avg*0.5?'low':'normal'}
};

const L=a=>a&&a.length?a[a.length-1]:null;
const P=a=>a&&a.length>1?a[a.length-2]:null;

// ═══ NEWS & SENTIMENT ═══
const COINS_MAP={BTC:'bitcoin',ETH:'ethereum',SOL:'solana',XRP:'ripple',ADA:'cardano',DOGE:'dogecoin',DOT:'polkadot',LINK:'chainlink',AVAX:'avalanche',BNB:'binance',SHIB:'shiba',UNI:'uniswap',ATOM:'cosmos',LTC:'litecoin',NEAR:'near',APT:'aptos',ARB:'arbitrum',OP:'optimism',SUI:'sui',SEI:'sei',INJ:'injective',FET:'fetch',RENDER:'render',PEPE:'pepe',WIF:'dogwifhat',BONK:'bonk',FLOKI:'floki',TIA:'celestia',AAVE:'aave',XLM:'stellar',HBAR:'hedera',VET:'vechain',GRT:'graph',STX:'stacks',IMX:'immutable',JASMY:'jasmy',ALGO:'algorand',SAND:'sandbox',MANA:'decentraland',CRV:'curve',ONDO:'ondo',JUP:'jupiter',PENDLE:'pendle',KAS:'kaspa',RUNE:'thorchain',DYDX:'dydx'};

let newsCache={articles:[],sentiment:{},overall:{},updated:0};
let sentimentCache={value:50,label:'Neutral'};

function classify(title,body,source,url,time){
  const t=(title+' '+body).toLowerCase();
  const bullish=['surge','rally','bull','breakout','adoption','launch','partnership','approval','record high','upgrade','institutional','etf approved','accumulation'];
  const bearish=['crash','dump','hack','exploit','ban','lawsuit','sec','fraud','liquidat','bear','sell-off','panic','regulation','arrest','bankrupt'];
  const world=['fed','interest rate','inflation','gdp','employment','tariff','war','sanction','election','government','china','trump','biden','ecb','boj','recession'];
  let score=0;
  bullish.forEach(w=>{if(t.includes(w))score++});bearish.forEach(w=>{if(t.includes(w))score--});
  const type=world.some(w=>t.includes(w))?'world':'crypto';
  return{title,source:source||'Unknown',time:time||Date.now(),score,type,url};
}

async function fetchNews(){
  if(Date.now()-newsCache.updated<300000)return newsCache;
  try{
    const articles=[];
    // CryptoCompare
    for(const cat of['blockchain','market','regulation','mining']){
      try{const r=await fetch('https://min-api.cryptocompare.com/data/v2/news/?categories='+cat+'&feeds=coindesk,cointelegraph,cryptonews&extraParams=tradematrix');
        const d=await safeJSON(r);
        if(d.Data){const arr=Array.isArray(d.Data)?d.Data:d.Data.Data||[];if(Array.isArray(arr))for(const a of arr.slice(0,10)){const x=classify(a.title,a.body,a.source,a.url,(a.published_on||0)*1000);if(x)articles.push(x)}}
      }catch{}}
    // CoinGecko
    try{const r=await fetch('https://api.coingecko.com/api/v3/events');const d=await safeJSON(r);if(d.data)for(const e of d.data.slice(0,8)){articles.push(classify(e.title,e.description||'',e.organizer||'CoinGecko',e.website||'',Date.now()))}}catch{}
    const cs={};
    for(const[sym,name]of Object.entries(COINS_MAP)){const rel=articles.filter(a=>(a.title+' '+(a.body||'')).toLowerCase().includes(name)||a.title.toLowerCase().includes(sym.toLowerCase()));if(rel.length)cs[sym]={score:Math.round(rel.reduce((s,a)=>s+a.score,0)/rel.length*100)/100,n:rel.length,bias:rel.reduce((s,a)=>s+a.score,0)/rel.length>0.5?'bullish':rel.reduce((s,a)=>s+a.score,0)/rel.length<-0.5?'bearish':'neutral'}}
    const overall=articles.length?{avgScore:Math.round(articles.reduce((s,a)=>s+a.score,0)/articles.length*100)/100,count:articles.length,bias:articles.reduce((s,a)=>s+a.score,0)/articles.length>0.3?'bullish':articles.reduce((s,a)=>s+a.score,0)/articles.length<-0.3?'bearish':'neutral'}:{};
    newsCache={articles,sentiment:cs,overall,updated:Date.now()};
    console.log('News:',articles.length,'articles',articles.filter(a=>a.type==='world').length,'world',articles.filter(a=>a.type==='crypto').length,'crypto');
    return newsCache;
  }catch(e){console.log('News err:',e.message);return newsCache}
}

async function getSentiment(){
  try{const r=await fetch('https://api.alternative.me/fng/?limit=1');const d=await safeJSON(r);if(d.data&&d.data[0]){sentimentCache={value:+d.data[0].value,label:d.data[0].value_classification}}}catch{}
  return sentimentCache;
}

async function safeJSON(r){try{return await r.json()}catch{return{}}}

// ═══ SWING TRADE ANALYZER (1H + 4H) ═══
async function fetchKlines(sym,tf,limit=100){
  const r=await fetch(`https://api.kucoin.com/api/v1/market/candles?type=${tf}&symbol=${sym}&limit=${limit||100}`);
  const d=await safeJSON(r);if(!d.data||!d.data.length)throw new Error('Candle fetch failed for '+sym);
  return d.data.map(k=>({time:+k[0]*1000,open:+k[1],close:+k[2],high:+k[3],low:+k[4],volume:+k[5]})).reverse();
}

function analyzeCandles(candles){
  const c=candles.map(x=>x.close),h=candles.map(x=>x.high),l=candles.map(x=>x.low),v=candles.map(x=>x.volume),o=candles.map(x=>x.open);
  const sma20=TA.sma(c,20),sma50=TA.sma(c,50),sma100=TA.sma(c,100),sma200=TA.sma(c,200);
  const ema9=TA.ema(c,9),ema21=TA.ema(c,21),ema50=TA.ema(c,50),ema100=TA.ema(c,100),ema200=TA.ema(c,200);
  const rsi=TA.rsi(c),atr=TA.atr(h,l,c),macd=TA.macd(c),bb=TA.bollinger(c),sr=TA.stochRSI(c);
  const adx=TA.adx(h,l,c),vwap=TA.vwap(h,l,c,v),obv=TA.obv(c,v),fib=TA.fibonacci(h,l,c);
  const cci=TA.cci(h,l,c),st=TA.supertrend(h,l,c),chop=TA.choppiness(h,l,c),pivots=TA.pivotPoints(h,l,c);
  const hhll=TA.higherHighsLows(h,l),slope=TA.trendSlope(c),patterns=TA.candlePatterns(o,h,l,c);
  const obvSma=TA.sma(obv,20),volTrend=TA.volTrend(v);
  return{
    price:L(c),open:L(o),high:L(h),low:L(l),
    sma20:L(sma20),sma50:L(sma50),sma100:L(sma100),sma200:L(sma200),
    ema9:L(ema9),ema21:L(ema21),ema50:L(ema50),ema100:L(ema100),ema200:L(ema200),
    rsi:L(rsi),prevRsi:P(rsi),atr:L(atr),
    macdLine:L(macd.line),macdSignal:L(macd.signal),macdHist:L(macd.hist),prevMacdHist:P(macd.hist),
    bbUpper:L(bb.upper),bbLower:L(bb.lower),bbSma:L(bb.sma),
    stochK:L(sr.k),stochD:L(sr.d),
    adx:L(adx.adx),diPlus:L(adx.diPlus),diMinus:L(adx.diMinus),
    vwap:L(vwap),obvTrend:L(obv)>L(obvSma)?'bullish':'bearish',volTrend,
    cci:L(cci),
    supertrend:st.length?st[st.length-1]:{trend:0,val:0},
    choppiness:chop.length?chop[chop.length-1]:50,
    pivots,fib,hhll,slope,patterns,
    support:fib.nearestSupport,resistance:fib.nearestResistance,inGoldenPocket:fib.inGoldenPocket
  };
}

async function swingAnalysis(sym){
  // Fetch BOTH 1H and 4H candles
  const c1h=await fetchKlines(sym,'1hour',100);
  const c4h=await fetchKlines(sym,'4hour',100);
  const a1h=analyzeCandles(c1h);
  const a4h=analyzeCandles(c4h);
  // 4H is the primary, 1H is for entry timing
  return{
    price:a1h.price,atr:a1h.atr,
    h1:a1h,h4:a4h,
    // Combined signals
    trendAligned:a4h.ema21>a4h.ema50&&a1h.ema9>a1h.ema21?'bullish':a4h.ema21<a4h.ema50&&a1h.ema9<a1h.ema21?'bearish':'mixed',
    coin:sym.replace('-USDT','')
  };
}

// ═══ 35+ BINARY SIGNALS ═══
const SIGNALS={
  // TREND (using both 1H and 4H)
  ema_cross_9_21(a){const e=a.h1;return{signal:e.ema9>e.ema21?'buy':e.ema9<e.ema21?'sell':'none',name:'EMA 9/21'}},
  ema_cross_21_50(a){const e=a.h4;return{signal:e.ema21>e.ema50?'buy':e.ema21<e.ema50?'sell':'none',name:'EMA 21/50 (4H)'}},
  ema_stack(a){const e=a.h4;return{signal:e.ema9>e.ema21&&e.ema21>e.ema50?'buy':e.ema9<e.ema21&&e.ema21<e.ema50?'sell':'none',name:'EMA stack (4H)'}},
  sma_cross_20_50(a){const e=a.h4;return{signal:e.sma20>e.sma50?'buy':e.sma20<e.sma50?'sell':'none',name:'SMA 20/50 (4H)'}},
  sma_cross_50_200(a){const e=a.h4;return{signal:e.sma50>e.sma200?'buy':e.sma50<e.sma200?'sell':'none',name:'SMA 50/200 golden cross'}},
  price_above_sma200(a){return{signal:a.price>a.h4.sma200?'buy':a.price<a.h4.sma200?'sell':'none',name:'Price vs SMA200'}},
  supertrend_4h(a){return{signal:a.h4.supertrend.trend===1?'buy':a.h4.supertrend.trend===-1?'sell':'none',name:'Supertrend (4H)'}},
  trend_slope(a){return{signal:a.h4.slope>0.1?'buy':a.h4.slope<-0.1?'sell':'none',name:'Trend slope (4H)'}},
  higher_highs(a){return{signal:a.h4.hhll.trend==='uptrend'?'buy':a.h4.hhll.trend==='downtrend'?'sell':'none',name:'HH/HL (4H)'}},
  // MOMENTUM
  rsi_oversold(a){return{signal:a.h1.rsi<30?'buy':a.h1.rsi>70?'sell':'none',name:'RSI extreme'}},
  rsi_pullback(a){return{signal:a.h4.rsi>40&&a.h4.rsi<55&&a.h1.rsi<40?'buy':a.h4.rsi<60&&a.h4.rsi>45&&a.h1.rsi>60?'sell':'none',name:'RSI pullback'}},
  macd_cross(a){return{signal:a.h1.macdLine>a.h1.macdSignal&&a.h1.prevMacdHist<=0?'buy':a.h1.macdLine<a.h1.macdSignal&&a.h1.prevMacdHist>=0?'sell':'none',name:'MACD cross (1H)'}},
  macd_4h(a){return{signal:a.h4.macdHist>0?'buy':a.h4.macdHist<0?'sell':'none',name:'MACD histogram (4H)'}},
  stoch_cross(a){return{signal:a.h1.stochK<20&&a.h1.stochD<20?'buy':a.h1.stochK>80&&a.h1.stochD>80?'sell':'none',name:'Stoch oversold/overbought'}},
  cci_extreme(a){return{signal:a.h1.cci<-100?'buy':a.h1.cci>100?'sell':'none',name:'CCI extreme'}},
  adx_strong(a){return{signal:a.h4.adx>25&&a.h4.diPlus>a.h4.diMinus?'buy':a.h4.adx>25&&a.h4.diMinus>a.h4.diPlus?'sell':'none',name:'ADX directional (4H)'}},
  // VOLATILITY
  bb_touch(a){return{signal:a.h1.price<=a.h1.bbLower?'buy':a.h1.price>=a.h1.bbUpper?'sell':'none',name:'BB touch (1H)'}},
  bb_squeeze(a){if(!a.h1.bbUpper||!a.h1.bbLower)return{signal:'none',name:'BB squeeze'};const w=((a.h1.bbUpper-a.h1.bbLower)/a.h1.bbSma)*100;return{signal:w<3?(a.h4.slope>0?'buy':'sell'):'none',name:'BB squeeze + 4H direction'}},
  chop_trending(a){return{signal:a.h4.choppiness<38?'buy':a.h4.choppiness>61?'sell':'none',name:'Choppiness (4H)'}},
  // VOLUME
  vwap_position(a){return{signal:a.price>a.h1.vwap?'buy':a.price<a.h1.vwap?'sell':'none',name:'VWAP position'}},
  obv_trend(a){return{signal:a.h4.obvTrend==='bullish'?'buy':a.h4.obvTrend==='bearish'?'sell':'none',name:'OBV trend (4H)'}},
  volume_spike(a){return{signal:a.h1.volTrend==='high'?'buy':'none',name:'Volume spike'}},
  // LEVELS
  fib_support(a){if(!a.h4.support)return{signal:'none',name:'Fib'};const d=Math.abs(a.price-a.h4.support)/a.price;return{signal:d<0.015?'buy':'none',name:'Fib support (4H)'}},
  fib_resist(a){if(!a.h4.resistance)return{signal:'none',name:'Fib'};const d=Math.abs(a.price-a.h4.resistance)/a.price;return{signal:d<0.015?'sell':'none',name:'Fib resistance (4H)'}},
  golden_pocket(a){return{signal:a.h4.inGoldenPocket?'buy':'none',name:'Golden pocket (4H)'}},
  pivot_support(a){if(!a.h1.pivots)return{signal:'none',name:'Pivot'};const ds=Math.abs(a.price-a.h1.pivots.s1)/a.price;const dr=Math.abs(a.price-a.h1.pivots.r1)/a.price;return{signal:ds<0.005?'buy':dr<0.005?'sell':'none',name:'Pivot S/R'}},
  // PATTERNS
  hammer(a){return{signal:a.h1.patterns?.includes('hammer')||a.h1.patterns?.includes('pin_bar_bull')?'buy':a.h1.patterns?.includes('shooting_star')||a.h1.patterns?.includes('pin_bar_bear')?'sell':'none',name:'Hammer/Star (1H)'}},
  engulfing(a){return{signal:a.h1.patterns?.includes('bullish_engulfing')?'buy':a.h1.patterns?.includes('bearish_engulfing')?'sell':'none',name:'Engulfing (1H)'}},
  three_soldiers(a){return{signal:a.h1.patterns?.includes('three_green')?'buy':a.h1.patterns?.includes('three_red')?'sell':'none',name:'3 soldiers/crows'}},
  inside_bar(a){return{signal:a.h1.patterns?.includes('inside_bar')?(a.h4.slope>0?'buy':'sell'):'none',name:'Inside bar + 4H direction'}},
  doji_reversal(a){return{signal:a.h1.patterns?.includes('doji')&&a.h1.rsi<30?'buy':a.h1.patterns?.includes('doji')&&a.h1.rsi>70?'sell':'none',name:'Doji + RSI extreme'}},
  // MULTI-TF ALIGNMENT
  dual_tf_trend(a){return{signal:a.trendAligned==='bullish'?'buy':a.trendAligned==='bearish'?'sell':'none',name:'1H+4H trend aligned'}},
  ema21_pullback(a){const dist=(a.price-a.h4.ema21)/a.price*100;return{signal:dist>-1.5&&dist<0&&a.h4.ema21>a.h4.ema50?'buy':dist<1.5&&dist>0&&a.h4.ema21<a.h4.ema50?'sell':'none',name:'4H EMA21 pullback'}},
  news_sentiment(a){return{signal:a.news?.overall?.bias==='bullish'?'buy':a.news?.overall?.bias==='bearish'?'sell':'none',name:'News sentiment'}},
  fear_greed(a){return{signal:a.sentiment?.value<25?'buy':a.sentiment?.value>75?'sell':'none',name:'F&G extreme'}}
};

const SIGNAL_NAMES=Object.keys(SIGNALS);

// ═══ COMBO TEMPLATES (logical swing trade combos) ═══
const COMBO_TEMPLATES=[
  // Trend following (4H trend + 1H entry)
  ['ema_stack','adx_strong','ema21_pullback'],
  ['sma_cross_20_50','supertrend_4h','macd_4h'],
  ['ema_cross_21_50','trend_slope','obv_trend'],
  ['higher_highs','ema_stack','volume_spike'],
  ['dual_tf_trend','adx_strong','vwap_position'],
  ['supertrend_4h','macd_4h','higher_highs'],
  ['price_above_sma200','ema_stack','rsi_pullback'],
  ['sma_cross_50_200','supertrend_4h','adx_strong'],
  ['trend_slope','chop_trending','obv_trend'],
  // Pullback entries
  ['ema21_pullback','rsi_pullback','macd_cross'],
  ['ema_stack','bb_touch','stoch_cross'],
  ['supertrend_4h','rsi_oversold','volume_spike'],
  ['higher_highs','fib_support','hammer'],
  ['ema_cross_21_50','golden_pocket','macd_cross'],
  ['adx_strong','ema21_pullback','engulfing'],
  // Mean reversion
  ['rsi_oversold','bb_touch','volume_spike'],
  ['stoch_cross','bb_touch','cci_extreme'],
  ['rsi_oversold','fib_support','hammer'],
  ['bb_touch','pivot_support','doji_reversal'],
  // Breakout
  ['bb_squeeze','adx_strong','volume_spike'],
  ['inside_bar','adx_strong','chop_trending'],
  ['bb_squeeze','macd_cross','trend_slope'],
  // Pattern combos
  ['hammer','rsi_oversold','fib_support'],
  ['engulfing','vwap_position','macd_cross'],
  ['three_soldiers','ema_stack','volume_spike'],
  ['inside_bar','bb_squeeze','supertrend_4h'],
  // Pairs (simpler)
  ['ema_stack','supertrend_4h'],
  ['adx_strong','macd_cross'],
  ['rsi_oversold','bb_touch'],
  ['ema21_pullback','macd_cross'],
  ['dual_tf_trend','volume_spike'],
  ['higher_highs','rsi_pullback'],
  ['hammer','fib_support'],
  ['engulfing','adx_strong'],
  ['supertrend_4h','ema21_pullback'],
  ['chop_trending','ema_cross_9_21'],
  ['golden_pocket','rsi_oversold'],
  ['bb_squeeze','volume_spike'],
  ['sma_cross_20_50','obv_trend'],
  ['pivot_support','hammer']
];

// ═══ COMBO ENGINE ═══
let comboTracker={combos:{},rankings:[],promotedCombos:[],lastRankUpdate:0};

function saveComboData(){
  try{
    const data={combos:{},promotedCombos:comboTracker.promotedCombos,rankings:comboTracker.rankings};
    for(const[id,c]of Object.entries(comboTracker.combos)){
      data.combos[id]={wins:c.wins,losses:c.losses,returns:c.returns.slice(-200),signals:c.signals,lastUpdated:c.lastUpdated,trades:c.trades.filter(t=>!t.resolved).slice(-50)};
    }
    fs.writeFileSync('.combo-data.json',JSON.stringify(data));
  }catch(e){console.log('Combo save err:',e.message)}
}

function loadComboData(){
  try{
    if(!fs.existsSync('.combo-data.json'))return;
    const data=JSON.parse(fs.readFileSync('.combo-data.json','utf8'));
    if(data.combos)for(const[id,c]of Object.entries(data.combos))comboTracker.combos[id]={...c,trades:c.trades||[]};
    if(data.promotedCombos)comboTracker.promotedCombos=data.promotedCombos;
    if(data.rankings)comboTracker.rankings=data.rankings;
    console.log('Combo data loaded:',Object.keys(comboTracker.combos).length,'combos');
  }catch(e){console.log('Combo load err:',e.message)}
}
loadComboData();

function getComboId(sigs){return[...sigs].sort().join('+')}

function evaluateCombo(comboSignals,analysis){
  const results=comboSignals.map(s=>SIGNALS[s]?SIGNALS[s](analysis):null).filter(Boolean);
  if(!results.length)return null;
  const buys=results.filter(r=>r.signal==='buy').length;
  const sells=results.filter(r=>r.signal==='sell').length;
  if(buys>0&&sells>0)return null;
  if(buys+sells<Math.ceil(results.length*0.6))return null;
  return buys>sells?'buy':'sell';
}

function comboShadowRecord(id,sym,side,price,atr){
  if(!comboTracker.combos[id])comboTracker.combos[id]={wins:0,losses:0,trades:[],returns:[],signals:id.split('+'),lastUpdated:Date.now()};
  const sl=atr*2.0,tp=atr*2.0;
  comboTracker.combos[id].trades.push({sym,side,entry:price,sl:side==='buy'?price-sl:price+sl,tp:side==='buy'?price+tp:price-tp,time:Date.now(),resolved:false});
  if(comboTracker.combos[id].trades.length>200)comboTracker.combos[id].trades=comboTracker.combos[id].trades.slice(-200);
}

function comboShadowUpdate(sym,price){
  for(const[id,data]of Object.entries(comboTracker.combos)){
    for(const t of data.trades){
      if(t.resolved||t.sym!==sym)continue;
      const hitTP=(t.side==='buy'&&price>=t.tp)||(t.side==='sell'&&price<=t.tp);
      const hitSL=(t.side==='buy'&&price<=t.sl)||(t.side==='sell'&&price>=t.sl);
      const timeout=Date.now()-t.time>24*60*60*1000; // 24h timeout for swing
      if(!hitTP&&!hitSL&&!timeout)continue;
      t.resolved=true;
      const pnl=hitTP?Math.abs((t.tp-t.entry)/t.entry)*100:hitSL?-Math.abs((t.sl-t.entry)/t.entry)*100:((t.side==='buy'?1:-1)*(price-t.entry)/t.entry)*100;
      data.returns.push(pnl);if(data.returns.length>200)data.returns.shift();
      if(pnl>0)data.wins++;else data.losses++;
      data.lastUpdated=Date.now();
    }
    data.trades=data.trades.filter(t=>!t.resolved);
  }
}

function rankCombos(){
  if(Date.now()-comboTracker.lastRankUpdate<60000)return;
  comboTracker.lastRankUpdate=Date.now();
  const rankings=[];
  for(const[id,data]of Object.entries(comboTracker.combos)){
    const total=data.wins+data.losses;if(total<10)continue;
    const wr=data.wins/total;
    const returns=data.returns.slice(-100);
    const mean=returns.reduce((a,b)=>a+b,0)/returns.length;
    const variance=returns.reduce((a,b)=>a+(b-mean)**2,0)/returns.length;
    const std=Math.sqrt(variance);
    const sharpe=std>0?mean/std:0;
    const consistency=std>0?1/std:999;
    const pf=data.losses>0?(data.wins/data.losses):data.wins;
    rankings.push({id,signals:data.signals||id.split('+'),wins:data.wins,losses:data.losses,total,winRate:Math.round(wr*100),avgReturn:Math.round(mean*100)/100,sharpe:Math.round(sharpe*100)/100,consistency:Math.round(consistency*100)/100,profitFactor:Math.round(pf*100)/100,score:Math.round((wr*40+Math.min(sharpe,3)*20+Math.min(consistency,10)*20+(mean>0?20:0))*100)/100});
  }
  rankings.sort((a,b)=>b.score-a.score);
  comboTracker.rankings=rankings;
  // Promote top 3 that meet criteria
  comboTracker.promotedCombos=rankings.filter(r=>r.total>=20&&r.winRate>=55&&r.winRate<95&&r.sharpe>0.2).slice(0,3);
  if(comboTracker.promotedCombos.length)saveComboData();
}

function runComboTests(analysis,sym){
  if(!analysis||!analysis.price)return;
  comboShadowUpdate(sym,analysis.price);
  for(const combo of COMBO_TEMPLATES){
    const decision=evaluateCombo(combo,analysis);
    if(decision)comboShadowRecord(getComboId([...combo]),sym,decision,analysis.price,analysis.atr||analysis.h1?.atr||1);
  }
  rankCombos();
}

// ═══ AUTH ═══
let AUTH={email:null,hash:null,tokens:[]};
function hashPw(p){return crypto.createHash('sha256').update(p+'tradematrix_salt').digest('hex')}
function genToken(){const t=crypto.randomBytes(32).toString('hex');AUTH.tokens.push(t);return t}
function mw(req,res,next){const t=(req.headers.authorization||'').replace('Bearer ','');if(!AUTH.tokens.includes(t))return res.status(401).json({error:'Unauthorized'});next()}
try{const a=JSON.parse(fs.readFileSync('.auth.json','utf8'));AUTH=a;console.log('Auth loaded')}catch{console.log('No auth file')}
app.post('/api/auth/setup',(req,res)=>{if(AUTH.email)return res.status(400).json({error:'Account exists. Please login.'});const{email,password}=req.body;if(!email||!password||password.length<4)return res.status(400).json({error:'Email and password (4+) required'});AUTH.email=email;AUTH.hash=hashPw(password);const t=genToken();fs.writeFileSync('.auth.json',JSON.stringify(AUTH));res.json({token:t})});
app.post('/api/auth/login',(req,res)=>{if(!AUTH.email)return res.json({needsSetup:true});const{email,password}=req.body;if(email!==AUTH.email||hashPw(password)!==AUTH.hash)return res.status(401).json({error:'Invalid credentials'});const t=genToken();fs.writeFileSync('.auth.json',JSON.stringify(AUTH));res.json({token:t})});
app.get('/api/auth/check',(req,res)=>{if(!AUTH.email)return res.json({needsSetup:true});const t=(req.headers.authorization||'').replace('Bearer ','');res.json({authenticated:AUTH.tokens.includes(t)})});

// ═══ BOT STATE ═══
const ALL_SYMBOLS=['BTC-USDT','ETH-USDT','SOL-USDT','XRP-USDT','ADA-USDT','DOGE-USDT','LINK-USDT','AVAX-USDT','DOT-USDT','BNB-USDT','SHIB-USDT','UNI-USDT','ATOM-USDT','LTC-USDT','NEAR-USDT','APT-USDT','ARB-USDT','OP-USDT','SUI-USDT','SEI-USDT','INJ-USDT','FET-USDT','RENDER-USDT','PEPE-USDT','WIF-USDT','BONK-USDT','FLOKI-USDT','TIA-USDT','AAVE-USDT','XLM-USDT','HBAR-USDT','VET-USDT','GRT-USDT','STX-USDT','IMX-USDT','JASMY-USDT','ALGO-USDT','SAND-USDT','MANA-USDT','CRV-USDT','ONDO-USDT','JUP-USDT','PENDLE-USDT','KAS-USDT','RUNE-USDT','DYDX-USDT'];

const bot={
  mode:'paper',tradingType:'combined',running:false,
  symbols:ALL_SYMBOLS,intervalMs:300000, // 5 min for swing trades
  riskPct:2,maxDrawdownPct:15,slATR:2.0,tpATR:2.0,trailingStop:true,trailATR:1.5,
  maxOpenTrades:5,leverage:3,smallBalanceMode:'auto',dailyTargetPct:3,
  openTrades:[],history:[],cooldown:{},credentials:null,
  paperUSD:10000,startBal:10000,peakBal:10000,
  totalPnL:0,winCount:0,lossCount:0,dailyPnL:0,dailyDate:null,
  lastAnalysis:{},intervalId:null,log:[]
};

function botLog(msg){bot.log.push({time:Date.now(),msg});if(bot.log.length>200)bot.log.shift();console.log('[BOT]',msg)}
function saveSettings(){try{fs.writeFileSync('.bot-settings.json',JSON.stringify({mode:bot.mode,tradingType:bot.tradingType,riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,dailyTargetPct:bot.dailyTargetPct,intervalMs:bot.intervalMs,credentials:bot.credentials}));console.log('Settings saved: mode='+bot.mode)}catch{}}
function saveState(){try{fs.writeFileSync('.bot-state.json',JSON.stringify({openTrades:bot.openTrades,history:bot.history.slice(-200),paperUSD:bot.paperUSD,startBal:bot.startBal,peakBal:bot.peakBal,totalPnL:bot.totalPnL,winCount:bot.winCount,lossCount:bot.lossCount,dailyPnL:bot.dailyPnL,dailyDate:bot.dailyDate}))}catch{}}
function loadSettings(){try{const s=JSON.parse(fs.readFileSync('.bot-settings.json','utf8'));Object.assign(bot,s);console.log('Settings loaded: mode='+bot.mode)}catch{console.log('No settings file found, using defaults')}}
function loadState(){try{const s=JSON.parse(fs.readFileSync('.bot-state.json','utf8'));Object.assign(bot,s);console.log('State loaded:',bot.openTrades.length,'open trades')}catch{console.log('No state file found')}}
loadSettings();loadState();

// ═══ KuCoin API ═══
function kcH(method,ep,body,key,secret,pass){const ts=Date.now().toString();const str=ts+method+(ep)+(body?JSON.stringify(body):'');const sig=crypto.createHmac('sha256',secret).update(str).digest('base64');const pp=crypto.createHmac('sha256',secret).update(pass).digest('base64');return{'KC-API-KEY':key,'KC-API-SIGN':sig,'KC-API-TIMESTAMP':ts,'KC-API-PASSPHRASE':pp,'KC-API-KEY-VERSION':'2','Content-Type':'application/json'}}

function getCurBal(){return bot.mode==='live'?(liveBalanceCache.totalUSD||bot.paperUSD):bot.paperUSD}
let liveBalanceCache={totalUSD:0,updated:0};

async function fetchLiveBalance(){
  if(!bot.credentials)return 0;
  if(Date.now()-liveBalanceCache.updated<15000)return liveBalanceCache.totalUSD;
  try{
    const{apiKey,apiSecret,passphrase}=bot.credentials;let spotTotal=0,futuresTotal=0;const bals={};
    for(const type of['trade','main']){try{const ep='/api/v1/accounts?type='+type;const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});const d=await safeJSON(r);if(d.code==='200000'&&d.data)for(const a of d.data){const v=parseFloat(a.available)+parseFloat(a.holds||0);if(v>0)bals[a.currency+' ('+type+')']=v}}catch{}}
    let pm={USDT:1,USDC:1};try{const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);if(pd.code==='200000')for(const t of pd.data.ticker)if(t.symbol.endsWith('-USDT'))pm[t.symbol.replace('-USDT','')]=+t.last||0}catch{}
    for(const[k,v]of Object.entries(bals)){const cur=k.split(' ')[0];if(k.includes('(trade)'))spotTotal+=(pm[cur]||0)*v}
    try{const fep='/api/v1/account-overview?currency=USDT';const fr=await fetch('https://api-futures.kucoin.com'+fep,{headers:kcH('GET',fep,null,apiKey,apiSecret,passphrase)});const fd=await safeJSON(fr);if(fd.code==='200000'&&fd.data)futuresTotal=+fd.data.accountEquity||+fd.data.availableBalance||0}catch{}
    const total=spotTotal+futuresTotal;
    liveBalanceCache={totalUSD:Math.round(total*100)/100,spotUSD:Math.round(spotTotal*100)/100,futuresUSD:Math.round(futuresTotal*100)/100,balances:bals,updated:Date.now()};
    return total;
  }catch{return liveBalanceCache.totalUSD}
}

// ═══ SMART EXITS + TRADE CLOSE ═══
async function closeTrade(t,price,reason){
  t.status='closed';t.exitPrice=price;t.closeTime=new Date().toISOString();t.reason=reason;
  const dir=t.side==='buy'?1:-1;const raw=(price-t.entryPrice)*t.qty*dir;
  t.pnl=t.type==='futures'?raw*t.leverage:raw;
  t.pnlPct=((t.exitPrice-t.entryPrice)/t.entryPrice*100*dir*(t.type==='futures'?t.leverage:1));
  if(!t.isLive)bot.paperUSD+=t.margin+t.pnl;
  bot.totalPnL+=t.pnl;t.pnl>0?bot.winCount++:bot.lossCount++;
  const today=new Date().toISOString().slice(0,10);
  if(bot.dailyDate!==today){bot.dailyPnL=0;bot.dailyDate=today}
  bot.dailyPnL+=t.pnl;
  bot.openTrades=bot.openTrades.filter(x=>x.id!==t.id);bot.history.push(t);if(bot.history.length>500)bot.history.shift();
  botLog(`CLOSE ${t.side} ${t.symbol} @$${price.toFixed(4)} | PnL:${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)} (${t.pnlPct.toFixed(1)}%) | ${reason}`);
  saveState();
}

function smartExits(t,price,atr,analysis){
  const dir=t.side==='buy'?1:-1;
  const pnlPct=((price-t.entryPrice)/t.entryPrice)*100*dir;
  const tpDist=Math.abs(t.tp-t.entryPrice);
  const progressToTP=tpDist>0?Math.abs(price-t.entryPrice)/tpDist:0;
  const hoursOpen=(Date.now()-new Date(t.openTime).getTime())/(1000*60*60);

  // 1. Trailing stop
  if(bot.trailingStop&&t.trailingSl!==null){
    if(t.side==='buy'){if(price>(t.highSince||t.entryPrice))t.highSince=price;const ns=t.highSince-atr*bot.trailATR;if(ns>t.trailingSl)t.trailingSl=ns;if(price<=t.trailingSl)return'trailing_sl'}
    else{if(price<(t.lowSince||t.entryPrice))t.lowSince=price;const ns=t.lowSince+atr*bot.trailATR;if(ns<t.trailingSl)t.trailingSl=ns;if(price>=t.trailingSl)return'trailing_sl'}
  }
  // 2. Hard SL/TP
  if(t.side==='buy'&&price<=t.sl)return'stop_loss';
  if(t.side==='sell'&&price>=t.sl)return'stop_loss';
  if(t.side==='buy'&&price>=t.tp)return'take_profit';
  if(t.side==='sell'&&price<=t.tp)return'take_profit';
  // 3. Move SL to breakeven at 50% TP progress
  if(progressToTP>=0.5&&!t.slMovedToBE){
    const newSL=t.entryPrice+(dir*atr*0.1);
    if((t.side==='buy'&&newSL>t.sl)||(t.side==='sell'&&newSL<t.sl)){t.sl=newSL;t.slMovedToBE=true;botLog(`${t.symbol.replace('-USDT','')} SL→BE @$${newSL.toFixed(4)}`)}
  }
  // 4. Momentum fade — in profit but MACD/RSI turning
  if(pnlPct>0.5&&progressToTP>=0.3&&analysis){
    const a=analysis.h1||analysis;
    const macdFlip=(t.side==='buy'&&a.macdHist<0&&a.prevMacdHist>0)||(t.side==='sell'&&a.macdHist>0&&a.prevMacdHist<0);
    const rsiAgainst=(t.side==='buy'&&a.rsi>70)||(t.side==='sell'&&a.rsi<30);
    if(macdFlip||rsiAgainst){botLog(`${t.symbol.replace('-USDT','')} SMART EXIT: +${pnlPct.toFixed(2)}% — ${macdFlip?'MACD flip':'RSI extreme'}`);return'smart_exit_momentum'}
  }
  // 5. Time-based — in profit 6+ hours but stalling (swing trade = longer patience)
  if(hoursOpen>=6&&pnlPct>0.5&&progressToTP<0.7){botLog(`${t.symbol.replace('-USDT','')} SMART EXIT: +${pnlPct.toFixed(2)}% after ${hoursOpen.toFixed(1)}h — stalling`);return'smart_exit_time'}
  // 6. Supertrend flip — 4H supertrend changes direction against trade
  if(analysis&&analysis.h4){
    const stAgainst=(t.side==='buy'&&analysis.h4.supertrend.trend===-1)||(t.side==='sell'&&analysis.h4.supertrend.trend===1);
    if(stAgainst&&pnlPct>0){botLog(`${t.symbol.replace('-USDT','')} SMART EXIT: +${pnlPct.toFixed(2)}% — 4H Supertrend flipped`);return'smart_exit_supertrend'}
  }
  return null;
}

// ═══ PAPER TRADE ═══
function paperBuy(sym,price,posUSD,sl,tp,source,lev){bot.paperUSD-=posUSD/(lev>1?lev:1);bot.openTrades.push({id:crypto.randomUUID().slice(0,8),symbol:sym,side:'buy',type:lev>1?'futures':'spot',leverage:lev,entryPrice:price,qty:posUSD/price,usdAmount:posUSD,margin:posUSD/(lev>1?lev:1),sl,tp,source,openTime:new Date().toISOString(),status:'open',highSince:price,lowSince:price,trailingSl:bot.trailingStop?sl:null,isLive:false});botLog(`BUY ${sym} @$${price.toFixed(4)} | size:$${posUSD.toFixed(2)} | lev:${lev}x | SL:$${sl.toFixed(4)} | TP:$${tp.toFixed(4)} | ${source}`);saveState()}
function paperSell(sym,price,posUSD,sl,tp,source,lev){bot.paperUSD-=posUSD/(lev>1?lev:1);bot.openTrades.push({id:crypto.randomUUID().slice(0,8),symbol:sym,side:'sell',type:lev>1?'futures':'spot',leverage:lev,entryPrice:price,qty:posUSD/price,usdAmount:posUSD,margin:posUSD/(lev>1?lev:1),sl,tp,source,openTime:new Date().toISOString(),status:'open',highSince:price,lowSince:price,trailingSl:bot.trailingStop?(sl):null,isLive:false});botLog(`SHORT ${sym} @$${price.toFixed(4)} | size:$${posUSD.toFixed(2)} | lev:${lev}x | SL:$${sl.toFixed(4)} | TP:$${tp.toFixed(4)} | ${source}`);saveState()}

// ═══ MAIN TICK — SWING TRADE SCANNER ═══
let tickCount=0,tickIndex=0;
async function tick(){
  tickCount++;
  try{
    fetchNews().catch(()=>{});getSentiment().catch(()=>{});
    if(bot.mode==='live'&&bot.credentials){try{await fetchLiveBalance()}catch{}}

    const batchSize=5;const batch=[];
    for(let i=0;i<batchSize&&i<bot.symbols.length;i++)batch.push(bot.symbols[(tickIndex+i)%bot.symbols.length]);
    tickIndex=(tickIndex+batchSize)%bot.symbols.length;
    botLog(`Scanning: ${batch.map(s=>s.replace('-USDT','')).join(', ')} (batch ${Math.ceil(tickIndex/batchSize)}/${Math.ceil(bot.symbols.length/batchSize)})`);

    for(const sym of batch){
      try{
        const a=await swingAnalysis(sym);
        bot.lastAnalysis[sym]=a;
        const{price,atr}=a;if(!price||!atr)continue;

        // Update combo shadow trades
        comboShadowUpdate(sym,price);
        // Attach news/sentiment
        a.news=newsCache;a.sentiment=sentimentCache;
        // Run combo tests
        runComboTests(a,sym);

        // Check open trades — SMART EXITS
        for(const t of[...bot.openTrades]){
          if(t.symbol!==sym)continue;
          const exitReason=smartExits(t,price,atr,a);
          if(exitReason){await closeTrade(t,price,exitReason);continue}
        }

        // Skip if max trades
        if(bot.openTrades.length>=bot.maxOpenTrades)continue;
        if(bot.openTrades.filter(t=>t.symbol===sym).length>=1)continue;
        if(bot.cooldown[sym]&&Date.now()-bot.cooldown[sym]<600000)continue; // 10 min cooldown

        // Drawdown check
        const bal=getCurBal();if(bal>bot.peakBal)bot.peakBal=bal;
        const dd=((bot.peakBal-bal)/bot.peakBal)*100;
        const coin=sym.replace('-USDT','');
        if(dd>=bot.maxDrawdownPct){continue}

        // Daily target
        const today=new Date().toISOString().slice(0,10);
        if(bot.dailyDate!==today){bot.dailyPnL=0;bot.dailyDate=today}
        const dailyPctGain=(bot.dailyPnL/Math.max(bal,1))*100;
        if(dailyPctGain>=bot.dailyTargetPct)continue;

        // ═══ TRADE DECISION — Top 3 Promoted Combos ═══
        let tradeDecision=null,tradeSource=null;

        for(const combo of comboTracker.promotedCombos){
          const sigs=combo.signals||combo.id.split('+');
          const decision=evaluateCombo(sigs,a);
          if(decision){
            tradeDecision=decision;
            tradeSource=sigs.join('+');
            botLog(`${coin} 🧬 ${decision.toUpperCase()} | ${tradeSource} | WR:${combo.winRate}% | Sharpe:${combo.sharpe}`);
            break; // use first (highest ranked) combo that fires
          }
        }

        if(!tradeDecision)continue; // no combo fired = no trade = patience

        // Position sizing
        const slDist=atr*bot.slATR;const tpDist=atr*bot.tpATR;
        const sl=tradeDecision==='buy'?price-slDist:price+slDist;
        const tp=tradeDecision==='buy'?price+tpDist:price-tpDist;
        const lockedMargin=bot.openTrades.reduce((s,t)=>s+(t.margin||0),0);
        const availBal=Math.max(0,bal-lockedMargin);
        const remainingSlots=Math.max(1,bot.maxOpenTrades-bot.openTrades.length);
        let posUSD=Math.min(availBal/remainingSlots*0.9,bal*0.3);
        const lev=bot.tradingType==='spot'?1:bot.leverage;
        if(bot.tradingType!=='spot')posUSD=posUSD*lev;
        if(posUSD<1)continue;

        botLog(`${coin} ✓ ${tradeDecision.toUpperCase()} | ${tradeSource} | R:R=${(tpDist/slDist).toFixed(1)} | pos:$${posUSD.toFixed(2)}`);

        // Execute
        if(bot.mode==='paper'){
          if(tradeDecision==='buy')paperBuy(sym,price,posUSD,sl,tp,tradeSource,lev);
          else paperSell(sym,price,posUSD,sl,tp,tradeSource,lev);
        }
        bot.cooldown[sym]=Date.now();

      }catch(e){if(!e.message.includes('Candle fetch'))botLog(`${sym.replace('-USDT','')} error: ${e.message}`)}
      await new Promise(r=>setTimeout(r,500)); // rate limit
    }
  }catch(e){botLog('Tick error: '+e.message)}
}

// ═══ BOT CONTROL ═══
app.post('/api/bot/start',mw,(req,res)=>{if(bot.running)return res.json({error:'Already running'});bot.running=true;tick();bot.intervalId=setInterval(tick,bot.intervalMs);botLog('STARTED — '+bot.mode+' | '+bot.symbols.length+' coins | swing (1H+4H)');res.json({success:true})});
app.post('/api/bot/stop',mw,(req,res)=>{bot.running=false;if(bot.intervalId)clearInterval(bot.intervalId);bot.intervalId=null;botLog('STOPPED');res.json({success:true})});
app.post('/api/bot/close/:id',mw,async(req,res)=>{const t=bot.openTrades.find(x=>x.id===req.params.id);if(!t)return res.json({error:'Not found'});const p=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;await closeTrade(t,p,'manual');res.json({success:true})});

// ═══ SETTINGS ═══
app.post('/api/bot/settings',mw,(req,res)=>{
  const s=req.body;
  if(s.mode)bot.mode=s.mode;if(s.tradingType)bot.tradingType=s.tradingType;
  if(s.riskPct)bot.riskPct=+s.riskPct;if(s.maxDrawdownPct)bot.maxDrawdownPct=+s.maxDrawdownPct;
  if(s.slATR)bot.slATR=+s.slATR;if(s.tpATR)bot.tpATR=+s.tpATR;
  if(s.trailingStop!==undefined)bot.trailingStop=s.trailingStop;if(s.trailATR)bot.trailATR=+s.trailATR;
  if(s.maxOpenTrades)bot.maxOpenTrades=+s.maxOpenTrades;if(s.leverage)bot.leverage=+s.leverage;
  if(s.smallBalanceMode)bot.smallBalanceMode=s.smallBalanceMode;
  if(s.dailyTargetPct)bot.dailyTargetPct=+s.dailyTargetPct;
  if(s.intervalMs){bot.intervalMs=+s.intervalMs;if(bot.running){clearInterval(bot.intervalId);bot.intervalId=setInterval(tick,bot.intervalMs)}}
  if(s.resetPaper){bot.paperUSD=10000;bot.startBal=10000;bot.peakBal=10000;bot.totalPnL=0;bot.winCount=0;bot.lossCount=0;bot.openTrades=[];bot.history=[];bot.dailyPnL=0}
  if(s.resetDrawdown){bot.peakBal=getCurBal();bot.startBal=getCurBal()}
  saveSettings();saveState();res.json({success:true});
});

// ═══ STATUS ═══
app.get('/api/bot/status',mw,async(req,res)=>{
  if(bot.mode==='live'&&bot.credentials){try{await fetchLiveBalance()}catch{}}
  const bal=getCurBal();const dd=bot.peakBal>0?((bot.peakBal-bal)/bot.peakBal)*100:0;
  const tot=bot.winCount+bot.lossCount;
  res.json({
    running:bot.running,mode:bot.mode,tradingType:bot.tradingType,
    balance:bal,startBal:bot.startBal,totalPnL:bot.totalPnL,totalPnLPct:bot.startBal>0?(bot.totalPnL/bot.startBal)*100:0,
    drawdown:dd,winRate:tot>0?Math.round(bot.winCount/tot*100):0,winCount:bot.winCount,lossCount:bot.lossCount,
    tickCount,dailyPnL:bot.dailyPnL,dailyPctGain:bal>0?((bot.dailyPnL/bal)*100):0,dailyTargetPct:bot.dailyTargetPct,
    openTrades:bot.openTrades.map(t=>{const cp=bot.lastAnalysis[t.symbol]?.price||t.entryPrice;const dir=t.side==='buy'?1:-1;const upnl=Math.round((cp-t.entryPrice)*t.qty*dir*(t.type==='futures'?t.leverage:1)*100)/100;return{...t,currentPrice:cp,unrealizedPnl:upnl}}),
    recentHistory:bot.history.slice(-20),
    symbols:bot.symbols,sentiment:sentimentCache,
    combos:{rankings:comboTracker.rankings.slice(0,15),promoted:comboTracker.promotedCombos,totalCombos:Object.keys(comboTracker.combos).length,totalTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.wins+c.losses,0)},
    log:bot.log.slice(-50),
    settings:{riskPct:bot.riskPct,maxDrawdownPct:bot.maxDrawdownPct,slATR:bot.slATR,tpATR:bot.tpATR,trailingStop:bot.trailingStop,trailATR:bot.trailATR,maxOpenTrades:bot.maxOpenTrades,leverage:bot.leverage,smallBalanceMode:bot.smallBalanceMode,dailyTargetPct:bot.dailyTargetPct,intervalMs:bot.intervalMs}
  });
});

// ═══ COMBO RANKINGS ═══
app.get('/api/bot/combos',mw,(req,res)=>{rankCombos();res.json({success:true,totalCombos:Object.keys(comboTracker.combos).length,totalDemoTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.wins+c.losses,0),activeTrades:Object.values(comboTracker.combos).reduce((s,c)=>s+c.trades.filter(t=>!t.resolved).length,0),promoted:comboTracker.promotedCombos,rankings:comboTracker.rankings,signalLibrary:SIGNAL_NAMES})});

// ═══ NEWS ═══
app.get('/api/bot/news',mw,async(req,res)=>{try{const n=await fetchNews();const s=await getSentiment();res.json({success:true,articles:n.articles,coinSentiment:n.sentiment,overall:n.overall,fearGreed:s})}catch(e){res.status(500).json({error:e.message})}});

// ═══ WALLET ═══
app.get('/api/bot/wallet',mw,async(req,res)=>{
  if(!bot.credentials)return res.json({connected:false});
  try{await fetchLiveBalance();res.json({connected:true,totalUSD:liveBalanceCache.totalUSD,spotUSD:liveBalanceCache.spotUSD,futuresUSD:liveBalanceCache.futuresUSD,balances:liveBalanceCache.balances||{}})}catch(e){res.json({connected:false,error:e.message})}
});

app.post('/api/bot/connect',mw,(req,res)=>{const{apiKey,apiSecret,passphrase}=req.body;if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All required'});bot.credentials={apiKey,apiSecret,passphrase};saveSettings();res.json({success:true})});

app.post('/api/kucoin/balance',async(req,res)=>{const{apiKey,apiSecret,passphrase}=req.body;if(!apiKey||!apiSecret||!passphrase)return res.status(400).json({error:'All required'});try{const ep='/api/v1/accounts?type=trade';const r=await fetch('https://api.kucoin.com'+ep,{headers:kcH('GET',ep,null,apiKey,apiSecret,passphrase)});const d=await safeJSON(r);if(d.code!=='200000')return res.status(400).json({error:d.msg||'Error'});const b={};for(const a of d.data){const v=+a.available;if(v>0)b[a.currency]=(b[a.currency]||0)+v}let t=0;try{const pr=await fetch('https://api.kucoin.com/api/v1/market/allTickers');const pd=await safeJSON(pr);const pm={USDT:1,USDC:1};if(pd.code==='200000')for(const x of pd.data.ticker)if(x.symbol.endsWith('-USDT'))pm[x.symbol.replace('-USDT','')]=+x.last||0;for(const[c,a]of Object.entries(b))t+=(pm[c]||0)*a}catch{}res.json({success:true,balances:b,totalUSD:t})}catch(e){res.status(500).json({error:e.message})}});

// ═══ QUANT ANALYSIS ═══
app.get('/api/bot/quant/:sym',mw,async(req,res)=>{
  try{
    const sym=req.params.sym;const a=await swingAnalysis(sym);
    a.news=newsCache;a.sentiment=sentimentCache;
    const signalResults={};
    for(const[name,fn]of Object.entries(SIGNALS)){signalResults[name]=fn(a)}
    // Check which combos fire
    const firedCombos=[];
    for(const combo of COMBO_TEMPLATES){
      const d=evaluateCombo(combo,a);
      if(d)firedCombos.push({signals:combo,decision:d});
    }
    res.json({success:true,symbol:sym,price:a.price,h1:a.h1,h4:a.h4,trendAligned:a.trendAligned,signals:signalResults,firedCombos,rankings:comboTracker.rankings.slice(0,10),promoted:comboTracker.promotedCombos});
  }catch(e){res.json({success:false,error:e.message})}
});

// ═══ STARTUP ═══
setTimeout(()=>{fetchNews().catch(()=>{});getSentiment().catch(()=>{})},3000);
setInterval(()=>{saveComboData()},120000); // save combos every 2 min

app.get('/health',(_,res)=>res.json({status:'ok',version:'v5-swing',combos:Object.keys(comboTracker.combos).length}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,'0.0.0.0',()=>console.log(`TradeMatrix Pro v5 Swing → http://localhost:${PORT}`));

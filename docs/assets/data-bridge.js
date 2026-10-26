/* Fetch the existing upstream feeds; keep the packaged snapshot as a fallback. */
(function () {
  'use strict';
  var nativeFetch = window.fetch.bind(window);
  var source = (window.PD_SOURCE_CONFIG && window.PD_SOURCE_CONFIG.raw_docs_base) || 'https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/main/docs/';
  var requests = new Map();
  var states = {};
  var versions = {};
  var feeds = ['chart-data.json', 'feed-ioc.json'];
  function notify(name, data, mode) {
    var state = {name:name, mode:mode, updated:data.last_updated || data.generated_at || data.generated || data.updated || '', checkedAt:new Date().toISOString()};
    states[name] = state;
    window.pdFeedStates = states;
    window.dispatchEvent(new CustomEvent('pd:source', {detail:state}));
  }
  async function load(name) {
    var response, data, mode = 'source';
    try {
      var controller = new AbortController();
      var timer = setTimeout(function(){controller.abort();},15000);
      try { response = await nativeFetch(source + name, {cache:'no-cache', signal:controller.signal}); }
      finally { clearTimeout(timer); }
      if (!response.ok) throw new Error('Source HTTP ' + response.status);
      data = await response.json();
      if (name === 'chart-data.json' && (!Array.isArray(data.days) || !data.last_updated)) throw new Error('Invalid analytics schema');
      if (name === 'feed-ioc.json' && !Array.isArray(data.domains)) throw new Error('Invalid IOC schema');
    } catch (error) {
      mode = 'snapshot';
      response = await nativeFetch(new URL(name, document.baseURI).href, {cache:'no-cache'});
      if (!response.ok) throw new Error('Both source and saved snapshot are unavailable');
      data = await response.json();
    }
    var body = JSON.stringify(data);
    versions[name] = body;
    notify(name,data,mode);
    return body;
  }
  window.fetch = function(input, init) {
    var url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    var parsed = new URL(url, document.baseURI);
    var name = parsed.pathname.split('/').pop();
    if (parsed.origin === location.origin && feeds.includes(name)) {
      if (!requests.has(name)) requests.set(name,load(name).catch(function(error){requests.delete(name);throw error;}));
      return requests.get(name).then(function(body){return new Response(body,{status:200,headers:{'Content-Type':'application/json'}});});
    }
    return nativeFetch(input,init);
  };
  window.pdCheckForUpdates = async function() {
    var current = states['chart-data.json'];
    if (!current || document.hidden) return;
    try {
      var controller = new AbortController();
      var timer = setTimeout(function(){controller.abort();},12000);
      var response;
      try { response = await nativeFetch(source+'chart-data.json',{cache:'no-cache',signal:controller.signal}); }
      finally {clearTimeout(timer);}
      if (!response.ok) return;
      var data = await response.json();
      // A registrar dataset can change more than once on the same UTC date.
      if (JSON.stringify(data) !== versions['chart-data.json']) {
        var banner = document.getElementById('pd-update-banner');
        if (banner) banner.hidden = false;
      }
    } catch (error) { /* The current, labeled snapshot remains usable offline. */ }
  };

  window.pdExtractDataset = function(text) {
    var match=/window\._INLINE_DATA\s*=\s*\{/.exec(text);
    if(!match)throw new Error('Dataset missing');
    var start=match.index+match[0].length-1,depth=0,quoted=false,escaped=false;
    for(var i=start;i<text.length;i++){
      var c=text[i];
      if(quoted){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;}
      else if(c==='"')quoted=true;
      else if(c==='{')depth++;
      else if(c==='}'&&--depth===0)return JSON.parse(text.slice(start,i+1));
    }
    throw new Error('Incomplete dataset');
  };
  window.pdRefreshInlineDataset=async function(){
    var el=document.getElementById('pd-inline-state');
    if(!el||typeof window.pdApplyDataset!=='function')return;
    var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},45000);
    try{
      var r=await nativeFetch(source+'domains.html',{cache:'no-cache',signal:controller.signal});
      if(!r.ok)throw new Error('Source unavailable');
      var j=window.pdExtractDataset(await r.text());
      if(!Array.isArray(j.domains)||!j.domains.length||!j.domains.every(function(x){return x&&typeof x.domain==='string';}))throw new Error('Invalid schema');
      window.pdApplyDataset(j.domains);
      el.textContent=j.domains.length.toLocaleString()+' domain records · refreshed from original source';el.dataset.state='source';
    }catch(e){el.textContent=window.pdDataset.length.toLocaleString()+' saved domain records · source unavailable, showing packaged snapshot';el.dataset.state='snapshot';}
    finally{clearTimeout(timer);}
  };
  setInterval(window.pdCheckForUpdates,300000);
})();

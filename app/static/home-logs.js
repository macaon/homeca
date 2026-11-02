/* HomeUI logs component: vendor unchanged. API transport and the list of logs belong to the app. */
(function(global){
'use strict';
const ICON='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6h11M9 12h11M9 18h11"/><path d="M4.5 6h.01M4.5 12h.01M4.5 18h.01"/></svg>';
const AUDIT={id:'audit',label:'Audit',url:'/api/audit',help:'Who did what, newest first. Entries are kept for 90 days. Passwords, keys, secrets and any terminal or log contents are never recorded.'};
let instances=0;
/* button: the header icon button that opens the dialog. tabs: one entry per kind of log, each {id,label,url,help};
   a url answers GET url[?before=<id>] with {entries:[{id,ts,actor,action,target,detail}],more}. The tab bar only
   appears when there is more than one. */
function mount(root,{api,button,tabs=[AUDIT],title='Logs',label='Activity log'}){
 if(!tabs.length)throw new Error('HomeLogs needs at least one log');
 const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const uid='hl'+(++instances);
 root.setAttribute('data-home-logs','');
 root.innerHTML=`<dialog class="hl-dialog" aria-labelledby="${uid}-title"><div class="hl-head"><h2 id="${uid}-title">${escape(title)}</h2><button type="button" class="hl-close" aria-label="Close ${escape(title.toLowerCase())}">✕</button></div><div class="hl-tabs" role="tablist" aria-label="${escape(title)}" hidden></div><section class="hl-panel" role="tabpanel" aria-labelledby="${uid}-tab-${escape(tabs[0].id)}"><p class="hl-help"></p><div class="hl-list" aria-live="polite"></div><p class="hl-error" role="alert" hidden></p><div class="hl-actions"><button type="button" class="hl-more" hidden>Load older entries</button></div></section></dialog>`;
 const find=selector=>root.querySelector(selector),dialog=find('.hl-dialog'),bar=find('.hl-tabs'),panel=find('.hl-panel'),list=find('.hl-list'),error=find('.hl-error'),more=find('.hl-more');
 if(button){button.innerHTML=ICON;button.setAttribute('aria-label',label);button.title=label;button.setAttribute('aria-haspopup','dialog');}
 let current=tabs[0],oldest=null,generation=0,busy=false;
 const show=message=>{error.textContent=message;error.hidden=!message;};
 const when=value=>{const date=new Date(value);return Number.isNaN(date.getTime())?String(value):date.toLocaleString();};
 const rows=entries=>entries.map(e=>`<div class="hl-row"><strong>${escape(e.action)}${e.target?' · '+escape(e.target):''}</strong><span>${escape(e.actor)} · <time datetime="${escape(e.ts)}">${escape(when(e.ts))}</time>${e.detail?' · '+escape(e.detail):''}</span></div>`).join('');
 async function load(older=false){
  if(busy&&older)return;busy=true;const mine=++generation;show('');list.setAttribute('aria-busy','true');more.disabled=true;
  try{
   const url=current.url+(older&&oldest?(current.url.includes('?')?'&':'?')+'before='+encodeURIComponent(oldest):'');
   const data=await api(url);
   if(mine!==generation)return; // a newer request (another tab, or a reopen) replaced this one
   if(!data||!Array.isArray(data.entries))throw new Error('The log could not be loaded.');
   const html=rows(data.entries);
   list.innerHTML=(older?list.innerHTML:'')+(html||(older?'':'<p class="hl-empty">Nothing recorded yet.</p>'));
   if(data.entries.length)oldest=data.entries.at(-1).id;
   more.hidden=!data.more;
  }catch(reason){if(mine===generation)show(reason.message||'The log could not be loaded.');}
  finally{if(mine===generation){busy=false;list.removeAttribute('aria-busy');more.disabled=false;}}
 }
 function select(id,{focus=false}={}){
  current=tabs.find(tab=>tab.id===id)||tabs[0];oldest=null;list.innerHTML='';more.hidden=true;busy=false;
  for(const node of bar.children){const active=node.dataset.tab===current.id;node.setAttribute('aria-selected',String(active));node.tabIndex=active?0:-1;if(active){panel.setAttribute('aria-labelledby',node.id);if(focus)node.focus();}}
  find('.hl-help').textContent=current.help||'';find('.hl-help').hidden=!current.help;
  return load();
 }
 if(tabs.length>1){
  bar.hidden=false;
  bar.innerHTML=tabs.map(tab=>`<button type="button" role="tab" id="${uid}-tab-${escape(tab.id)}" data-tab="${escape(tab.id)}" aria-selected="false" tabindex="-1">${escape(tab.label)}</button>`).join('');
  bar.onclick=event=>{const node=event.target.closest('[data-tab]');if(node)select(node.dataset.tab);};
  bar.onkeydown=event=>{const nodes=[...bar.children],index=nodes.indexOf(document.activeElement);if(index<0)return;
   const next={ArrowRight:(index+1)%nodes.length,ArrowLeft:(index+nodes.length-1)%nodes.length,Home:0,End:nodes.length-1}[event.key];
   if(next===undefined)return;event.preventDefault();select(nodes[next].dataset.tab,{focus:true});};
 }else panel.removeAttribute('aria-labelledby');
 more.onclick=()=>load(true);
 find('.hl-close').onclick=()=>dialog.close();
 const open=id=>{show('');if(!dialog.open)dialog.showModal();return select(id||current.id);};
 if(button)button.onclick=()=>{open().catch(()=>{});};
 return {open,close(){dialog.close();},destroy(){dialog.close();if(button){button.onclick=null;button.replaceChildren();}root.replaceChildren();root.removeAttribute('data-home-logs');}};
}
global.HomeLogs=Object.freeze({mount});
})(typeof window!=='undefined'?window:globalThis);

/* HomeUI API tokens component: vendor unchanged. API transport and intro copy belong to the app. */
(function(global){
'use strict';
function mount(root,{api,intro='API tokens let scripts and other services call this application without signing in. Each token has one access level, belongs to an administrator and can be revoked at any time.'}){
 const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 root.setAttribute('data-home-tokens','');
 root.innerHTML=`<p class="hk-help"></p><div class="hk-list" aria-live="polite"></div><p class="hk-error" role="alert" hidden></p><p class="hk-status" role="status" hidden></p><div class="hk-actions"><button type="button" class="hk-primary hk-new">+ New token</button></div><dialog class="hk-dialog hk-create" aria-label="New API token"><form method="dialog"><h2>New API token</h2><label>Name<input name="name" required maxlength="60" autocomplete="off" placeholder="HomeDash"></label><label>Access<select name="scope"></select></label><p class="hk-help hk-scope-help"></p><label>Expires<select name="expires"><option value="">Never</option><option value="30">After 30 days</option><option value="90">After 90 days</option><option value="365">After 1 year</option></select></label><p class="hk-error" role="alert" hidden></p><div class="hk-actions"><button type="button" value="cancel" class="hk-cancel">Cancel</button><button type="submit" class="hk-primary">Create token</button></div></form></dialog><dialog class="hk-dialog hk-shown" aria-label="Copy your new token"><h2>Copy your new token</h2><p class="hk-help">This is the only time the token is shown. Store it somewhere safe; if it is lost, revoke it and create another.</p><input class="hk-token" readonly aria-label="API token"><div class="hk-actions"><button type="button" class="hk-copy">Copy</button><button type="button" class="hk-primary hk-done">Done</button></div></dialog><dialog class="hk-dialog hk-confirm" aria-label="Revoke API token"><form method="dialog"><h2>Revoke API token</h2><p class="hk-confirm-copy"></p><div class="hk-actions"><button value="cancel">Cancel</button><button value="confirm" class="hk-danger">Revoke</button></div></form></dialog>`;
 const find=selector=>root.querySelector(selector),list=find('.hk-list'),error=find(':scope>.hk-error'),status=find('.hk-status'),create=find('.hk-create'),form=create.querySelector('form'),formError=create.querySelector('.hk-error'),shown=find('.hk-shown'),confirm=find('.hk-confirm');
 find('.hk-help').textContent=intro;
 const message=(target,value)=>{target.textContent=value;target.hidden=!value;};
 const fail=reason=>message(error,reason.message||'The request could not be completed.');
 const when=value=>new Date(value).toLocaleString();
 let scopes=[],tokens=[],busy=false;
 const label=id=>scopes.find(item=>item.id===id)?.label||id;
 function describe(){create.querySelector('.hk-scope-help').textContent=scopes.find(item=>item.id===form.elements.scope.value)?.description||'';}
 form.elements.scope.onchange=describe;
 function render(){
  list.innerHTML=tokens.length?tokens.map(token=>`<div class="hk-row"><div class="hk-details"><strong>${escape(token.name)}</strong><span>${escape(label(token.scope))} · created ${escape(when(token.created))} by ${escape(token.owner)}</span><span>${token.last_used?'Last used '+escape(when(token.last_used)):'Never used'} · ${token.expires?(token.expired?'Expired ':'Expires ')+escape(when(token.expires)):'No expiry'}</span></div><button type="button" class="hk-danger" data-revoke="${escape(token.id)}" aria-label="Revoke ${escape(token.name)}">Revoke</button></div>`).join(''):'<p class="hk-empty">No API tokens yet.</p>';
  for(const button of list.querySelectorAll('[data-revoke]'))button.onclick=async()=>{
   if(busy)return;busy=true;message(error,'');message(status,'');
   const token=tokens.find(item=>item.id===button.dataset.revoke);
   find('.hk-confirm-copy').textContent=`Revoke ${token.name}? Anything using it stops working immediately.`;
   confirm.returnValue='';
   const accepted=new Promise(resolve=>confirm.addEventListener('close',()=>resolve(confirm.returnValue==='confirm'),{once:true}));
   confirm.showModal();confirm.querySelector('[value="cancel"]').focus();
   if(!await accepted){busy=false;button.focus();return;}
   button.disabled=true;
   try{await api('/api/tokens/'+encodeURIComponent(token.id),'DELETE');await load();message(status,'Token revoked.');}catch(reason){fail(reason);}finally{busy=false;button.disabled=false;}
  };
 }
 async function load(){message(error,'');list.setAttribute('aria-busy','true');try{const data=await api('/api/tokens');tokens=data.tokens;scopes=data.scopes;form.elements.scope.innerHTML=scopes.map(item=>`<option value="${escape(item.id)}">${escape(item.label)}</option>`).join('');describe();render();}catch(reason){fail(reason);throw reason;}finally{list.removeAttribute('aria-busy');}}
 find('.hk-new').onclick=()=>{form.reset();describe();message(formError,'');message(status,'');create.showModal();form.elements.name.focus();};
 create.querySelector('.hk-cancel').onclick=()=>create.close();
 form.onsubmit=async event=>{
  event.preventDefault();if(busy)return;busy=true;const button=form.querySelector('[type="submit"]');button.disabled=true;message(formError,'');
  try{
   const days=form.elements.expires.value,result=await api('/api/tokens','POST',{name:form.elements.name.value.trim(),scope:form.elements.scope.value,expires_days:days?Number(days):null});
   create.close();find('.hk-token').value=result.token;shown.showModal();find('.hk-token').select();
   await load();
  }catch(reason){message(formError,reason.message||'The request could not be completed.');}finally{busy=false;button.disabled=false;}
 };
 find('.hk-copy').onclick=async()=>{const input=find('.hk-token');input.select();try{await navigator.clipboard.writeText(input.value);find('.hk-copy').textContent='Copied';}catch{find('.hk-copy').textContent='Press Ctrl+C';}};
 find('.hk-done').onclick=()=>shown.close();
 shown.addEventListener('close',()=>{find('.hk-token').value='';find('.hk-copy').textContent='Copy';});
 return {load,destroy(){create.close();shown.close();confirm.close();root.replaceChildren();root.removeAttribute('data-home-tokens');}};
}
global.HomeTokens=Object.freeze({mount});
})(typeof window!=='undefined'?window:globalThis);

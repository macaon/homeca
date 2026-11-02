/* HomeUI Trust component: vendor unchanged. API transport and scope copy belong to the app. */
(function(global){
'use strict';
function mount(root,{api,scope='Additional CA certificates for this application’s outbound TLS connections.'}){
 const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 root.setAttribute('data-home-trust','');
 root.innerHTML=`<p class="ht-scope">Additional CA certificates trusted by this application for outbound TLS connections, including OIDC.</p><p class="ht-help">Public system certificate authorities remain trusted. Upload public PEM or DER files, including PEM bundles. Private keys are never accepted.</p><div class="ht-list" aria-live="polite"></div><form class="ht-form"><label>Certificate name<input name="name" required maxlength="80" placeholder="Private root CA" autocomplete="off"></label><label>Public certificates<input name="files" type="file" accept=".pem,.crt,.cer,.der" multiple required></label><p class="ht-help">Choose up to 32 files, each smaller than 350 KB. Certificates are deduplicated by SHA-256 fingerprint.</p><p class="ht-error" role="alert" hidden></p><p class="ht-status" role="status" hidden></p><div class="ht-actions"><button type="submit" class="ht-primary">Upload certificates</button></div></form><details class="ht-scope-notes"><summary>Where this trust store applies</summary><p class="ht-app-scope"></p></details><dialog class="ht-confirm" aria-label="Remove trusted certificate"><form method="dialog"><h2>Remove trusted certificate</h2><p class="ht-confirm-copy"></p><div class="ht-actions"><button value="cancel">Cancel</button><button value="confirm" class="ht-danger">Remove</button></div></form></dialog>`;
 const find=selector=>root.querySelector(selector),form=find('.ht-form'),list=find('.ht-list'),error=find('.ht-error'),status=find('.ht-status'),confirm=find('.ht-confirm');
 find('.ht-app-scope').textContent=scope;
 const message=(target,value)=>{target.textContent=value;target.hidden=!value;};
 const fail=reason=>message(error,reason.message||'The request could not be completed.');
 let busy=false;
 function render(certificates){
  list.innerHTML=certificates.length?certificates.map(cert=>`<div class="ht-row"><div class="ht-details"><strong>${escape(cert.name)}</strong><span>${escape(cert.subject)}</span><span>Expires ${escape(HomeUI.formatDate(cert.expires,{time:false}))}</span><code title="SHA-256 fingerprint">${escape((cert.fingerprint.match(/../g)||[]).join(':'))}</code></div><button type="button" class="ht-danger" data-remove="${escape(cert.fingerprint)}" aria-label="Remove ${escape(cert.name)}">Remove</button></div>`).join(''):'<p class="ht-empty">No additional certificates uploaded.</p>';
  for(const button of list.querySelectorAll('[data-remove]'))button.onclick=async()=>{
   if(busy)return;busy=true;message(error,'');message(status,'');
   const cert=certificates.find(item=>item.fingerprint===button.dataset.remove);
   find('.ht-confirm-copy').textContent=`Remove ${cert.name} from outbound trust? Connections relying on it may fail certificate verification.`;
   confirm.returnValue='';
   const accepted=new Promise(resolve=>confirm.addEventListener('close',()=>resolve(confirm.returnValue==='confirm'),{once:true}));
   confirm.showModal();confirm.querySelector('[value="cancel"]').focus();
   if(!await accepted){busy=false;button.focus();return;}
   button.disabled=true;
   try{await api('/api/settings/trust/'+encodeURIComponent(cert.fingerprint),'DELETE');await load();message(status,'Certificate removed.');}catch(reason){fail(reason);}finally{busy=false;button.disabled=false;}
  };
 }
 async function load(){message(error,'');list.setAttribute('aria-busy','true');try{render(await api('/api/settings/trust'));}catch(reason){fail(reason);throw reason;}finally{list.removeAttribute('aria-busy');}}
 form.onsubmit=async event=>{
  event.preventDefault();if(busy)return;busy=true;const button=form.querySelector('button[type="submit"]');button.disabled=true;message(error,'');message(status,'');
  try{
   const files=[...form.elements.files.files],name=form.elements.name.value.trim();
   if(!name)throw new Error('Enter a certificate name.');
   if(!files.length||files.length>32)throw new Error('Choose between 1 and 32 files.');
   if(files.some(file=>file.size>350000))throw new Error('Certificate files must be smaller than 350 KB.');
   let added=0;
   try{for(const file of files){const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);const result=await api('/api/settings/trust','POST',{name,certificate:btoa(binary),encoding:'base64'});added+=result.added;}}
   finally{await load();} // reflect any successful uploads even if a later file fails
   form.reset();message(status,`${added} certificate${added===1?'':'s'} added.`);
  }catch(reason){fail(reason);}finally{busy=false;button.disabled=false;}
 };
 return {load,destroy(){confirm.close();root.replaceChildren();root.removeAttribute('data-home-trust');}};
}
global.HomeTrust=Object.freeze({mount});
})(typeof window!=='undefined'?window:globalThis);

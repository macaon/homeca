/* HomeUI 0.1.0. No framework, network calls, or authentication policy. */
(function(root){
 'use strict';
 const modes=['auto','light','dark'];
 const toastTimers=new WeakMap();
 const iconPaths={
  settings:'<path d="M9.5 2.5h5l.6 2.6 1.5.9 2.6-.8 2.5 4.3-2 1.8v1.8l2 1.8-2.5 4.3-2.6-.8-1.5.9-.6 2.6h-5L8.9 19l-1.5-.9-2.6.8-2.5-4.3 2-1.8V11l-2-1.8 2.5-4.3 2.6.8 1.5-.9Z"/><circle cx="12" cy="12" r="3"/>',
  menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
  close:'<path d="m6 6 12 12M18 6 6 18"/>'
 };
 function escape(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
 function icon(name){return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(iconPaths[name]||iconPaths.grid)+'</svg>';}
 function applyTheme(mode){if(!modes.includes(mode))throw new Error('Unknown appearance mode');if(mode==='auto')delete document.documentElement.dataset.theme;else document.documentElement.dataset.theme=mode;}
 function themeController({prefix='homeui',defaultTheme='auto',accountId=null,onChange=()=>{}}={}){
  let fallback=defaultTheme,account=accountId,current;
  const key=()=>prefix+'.theme.'+account;
  const apply=()=>{let selected=null;try{if(account)selected=localStorage.getItem(key());}catch{}current=modes.includes(selected)?selected:fallback;applyTheme(current);onChange(current);return current;};
  apply();
  return {get mode(){return current;},setContext(id,mode){if(!modes.includes(mode))throw new Error('Unknown default appearance');account=id;fallback=mode;return apply();},setPersonal(mode){if(!account)throw new Error('Sign in before choosing a personal appearance');if(!modes.includes(mode))throw new Error('Unknown appearance mode');try{localStorage.setItem(key(),mode);}catch{}current=mode;applyTheme(mode);onChange(mode);},cycle(){this.setPersonal(modes[(modes.indexOf(current)+1)%modes.length]);},useDefault(){try{if(account)localStorage.removeItem(key());}catch{}return apply();}};
 }
 function dropdown(button,panel){
  button.setAttribute('aria-controls',panel.id);button.setAttribute('aria-expanded','false');
  const close=()=>{panel.classList.remove('open');button.setAttribute('aria-expanded','false');};
  const toggle=()=>{const open=!panel.classList.contains('open');panel.classList.toggle('open',open);button.setAttribute('aria-expanded',String(open));};
  const outside=e=>{if(!panel.contains(e.target)&&!button.contains(e.target))close();};
  const choose=e=>{if(e.target.closest('a,button'))close();};
  const keyboard=e=>{if(e.key==='Escape'&&panel.classList.contains('open')){close();button.focus();}};
  button.addEventListener('click',toggle);panel.addEventListener('click',choose);document.addEventListener('click',outside);document.addEventListener('keydown',keyboard);
  return {close,destroy(){button.removeEventListener('click',toggle);panel.removeEventListener('click',choose);document.removeEventListener('click',outside);document.removeEventListener('keydown',keyboard);}};
 }
 function overflow(details){
  const summary=details.querySelector('summary'),panel=details.querySelector('.hui-menu');
  const close=()=>{details.open=false;};
  const outside=e=>{if(!details.contains(e.target))close();};
  const keyboard=e=>{if(e.key==='Escape'&&details.open){close();summary.focus();}};
  const choose=e=>{if(e.target.closest('a,button'))close();};
  document.addEventListener('click',outside);document.addEventListener('keydown',keyboard);panel.addEventListener('click',choose);
  return {close,destroy(){document.removeEventListener('click',outside);document.removeEventListener('keydown',keyboard);panel.removeEventListener('click',choose);}};
 }
 function tabs(tablist,{initial,onChange=()=>{}}={}){
  const buttons=[...tablist.querySelectorAll('[aria-controls]')];if(!buttons.length)throw new Error('Tabs require aria-controls');tablist.setAttribute('role','tablist');
  const select=id=>{const target=buttons.find(b=>b.id===id);if(!target)throw new Error('Unknown tab');for(const button of buttons){const active=button===target;button.setAttribute('role','tab');button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;const panel=document.getElementById(button.getAttribute('aria-controls'));if(!panel)throw new Error('Missing tab panel');panel.hidden=!active;panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby',button.id);}onChange(id);};
  const click=e=>{const button=e.target.closest('[aria-controls]');if(button&&buttons.includes(button))select(button.id);};
  const keyboard=e=>{const index=buttons.indexOf(document.activeElement);if(index<0)return;let next;if(e.key==='ArrowRight')next=(index+1)%buttons.length;else if(e.key==='ArrowLeft')next=(index+buttons.length-1)%buttons.length;else if(e.key==='Home')next=0;else if(e.key==='End')next=buttons.length-1;else return;e.preventDefault();select(buttons[next].id);buttons[next].focus();};
  tablist.addEventListener('click',click);tablist.addEventListener('keydown',keyboard);select(initial||buttons[0].id);return {select,destroy(){tablist.removeEventListener('click',click);tablist.removeEventListener('keydown',keyboard);}};
 }
 function toast(element,message,{tone='info',duration=6500}={}){clearTimeout(toastTimers.get(element));element.textContent=message;element.dataset.tone=tone;element.setAttribute('role',tone==='error'?'alert':'status');element.hidden=false;toastTimers.set(element,setTimeout(()=>{element.hidden=true;},duration));}
 // Click-to-expand hints: <button type="button" class="hui-help" aria-expanded="false" aria-controls="ID" aria-label="Help: Field">?</button> + <small class="hui-hint" id="ID" hidden>. One delegated listener per scope.
 function help(scope=document){
  const toggle=(btn,open)=>{const hint=document.getElementById(btn.getAttribute('aria-controls'));if(!hint)return;open??=hint.hidden;hint.hidden=!open;btn.setAttribute('aria-expanded',String(open));};
  const click=e=>{const btn=e.target.closest?.('.hui-help');if(btn){e.preventDefault();toggle(btn);}};
  const key=e=>{if(e.key!=='Escape')return;const btn=e.target.closest?.('.hui-help[aria-expanded="true"]');if(btn){e.preventDefault();e.stopPropagation();toggle(btn,false);}};
  scope.addEventListener('click',click);scope.addEventListener('keydown',key);
  return{destroy(){scope.removeEventListener('click',click);scope.removeEventListener('keydown',key);}};
 }
 // Account date format: 'auto' (browser locale), 'iso' (2026-11-02 14:05:09), 'day' (02/11/2026 14:05:09), 'month' (11/02/2026, 2:05:09 PM).
 const dateLocales={iso:'sv-SE',day:'en-GB',month:'en-US'};
 let dateFormat='auto';
 function setDateFormat(format='auto'){if(format!=='auto'&&!dateLocales[format])throw new Error('Unknown date format');dateFormat=format;}
 function formatDate(value,{time=true,timeZone}={}){
  const date=value instanceof Date?value:new Date(value);if(Number.isNaN(date.getTime()))return String(value);
  const auto=dateFormat==='auto',two='2-digit';
  const options={timeZone,...(auto?{year:'numeric',month:'short',day:'numeric'}:{year:'numeric',month:two,day:two}),...(time?{hour:two,minute:two,second:two}:{})};
  return date.toLocaleString(auto?undefined:dateLocales[dateFormat],options).replace(', ',' ');
 }
 const confirmations=new WeakSet();
 function confirmFields(box,fields){
  const el=(tag,props={},kids=[])=>{const n=document.createElement(tag);Object.assign(n,props);n.append(...kids);return n;};
  const hint=f=>f.help?[el('small',{className:'hui-small',textContent:f.help})]:[];
  // `hint` = collapsible "?" text: [button for after the label, text for after the visible help].
  const more=f=>{if(!f.hint)return[[],[]];const id='hui-hint-'+f.name,b=el('button',{type:'button',className:'hui-help',textContent:'?'});b.setAttribute('aria-expanded','false');b.setAttribute('aria-controls',id);b.setAttribute('aria-label','Help: '+f.label);return[[b],[el('small',{className:'hui-hint',id,hidden:true,textContent:f.hint})]];};
  box.replaceChildren(...fields.map(f=>{
   const t=f.type||'text',opts=f.options||[],[btn,txt]=more(f);
   if(t==='checkbox')return el('div',{},[el('label',{className:'hui-inline'},[el('input',{type:'checkbox',name:f.name,checked:!!f.value}),f.label,...btn,...hint(f)]),...txt]);
   if(t==='radio'||t==='checkboxes'){const radio=t==='radio',on=[].concat(f.value??[]);return el('fieldset',{className:'hui-fields'},[el('legend',{},[f.label,...btn]),...txt,...opts.map(o=>el('label',{className:'hui-inline'},[el('input',{type:radio?'radio':'checkbox',name:f.name,value:o.value,checked:on.includes(o.value),required:radio&&!!f.required}),o.label])),...hint(f)]);}
   const ctl=t==='select'?el('select',{name:f.name,required:!!f.required},opts.map(o=>el('option',{value:o.value,textContent:o.label,selected:o.value===f.value})))
    :el(t==='textarea'?'textarea':'input',{name:f.name,value:f.value??'',required:!!f.required,placeholder:f.placeholder??'',...(t==='textarea'?{rows:f.rows||3}:{type:t,autocomplete:t==='password'?'new-password':'off'})});
   return el('label',{},[f.label,...btn,...hint(f),...txt,ctl]);
  }));
 }
 function confirmValues(form,fields){const d=new FormData(form);return Object.fromEntries(fields.map(f=>[f.name,f.type==='checkbox'?d.has(f.name):f.type==='checkboxes'?d.getAll(f.name):d.get(f.name)??'']));}
 // With `action` (async): the dialog stays open while it runs, shows a thrown error inline, and closes on success.
 // No `fields`: resolves true/false. With `fields`: resolves {name:value} on confirm, null on cancel/Escape.
 // Field types: text, password, number, url, email, textarea, select, radio, checkbox, checkboxes. See docs/component-api.md.
 function confirmAction(dialog,{title='Remove item',message,confirmLabel='Remove',fields,action}={}){
  if(confirmations.has(dialog))throw new Error('Confirmation already open');
  const box=dialog.querySelector('[data-confirm-fields]'),form=dialog.querySelector('form'),accept=dialog.querySelector('[data-confirm-accept]'),cancel=dialog.querySelector('[value="cancel"]');
  const errorBox=dialog.querySelector('[data-confirm-error]');
  if(fields&&!box)throw new Error('Dialog needs a [data-confirm-fields] element');
  if(action&&!errorBox)throw new Error('Dialog needs a [data-confirm-error] element');
  confirmations.add(dialog);
  dialog.querySelector('[data-confirm-title]').textContent=title;dialog.querySelector('[data-confirm-message]').textContent=message??'';accept.textContent=confirmLabel;dialog.returnValue='';
  if(box){box.replaceChildren();box.onkeydown=null;}
  let helper,busy=false;
  if(errorBox)errorBox.textContent='';
  // With `action`, confirming runs it while the dialog stays open: buttons disabled, errors shown inline, input kept.
  const submit=async e=>{
   if(e.submitter!==accept)return;e.preventDefault();
   const label=accept.textContent;busy=true;errorBox.textContent='';accept.disabled=cancel.disabled=true;accept.textContent='Working…';
   try{await action(fields?confirmValues(form,fields):undefined);dialog.close('confirm');}
   catch(err){errorBox.textContent=err?.message||String(err);}
   finally{busy=false;accept.disabled=cancel.disabled=false;accept.textContent=label;}
  };
  const noEscape=e=>{if(busy)e.preventDefault();};
  if(action){form.addEventListener('submit',submit);dialog.addEventListener('cancel',noEscape);}
  if(fields){confirmFields(box,fields);helper=help(box);cancel.formNoValidate=true;box.onkeydown=e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT'){e.preventDefault();form.requestSubmit(accept);}};}
  return new Promise(resolve=>{dialog.addEventListener('close',()=>{
   const ok=dialog.returnValue==='confirm',out=fields?(ok?confirmValues(form,fields):null):ok;
   helper?.destroy();if(action){form.removeEventListener('submit',submit);dialog.removeEventListener('cancel',noEscape);}confirmations.delete(dialog);if(box){box.replaceChildren();box.onkeydown=null;}resolve(out);},{once:true});
   dialog.showModal();(fields&&box.querySelector('input,select,textarea')||cancel)?.focus();});
 }
 root.HomeUI=Object.freeze({version:'0.1.0',escape,icon,applyTheme,themeController,dropdown,overflow,tabs,toast,help,formatDate,setDateFormat,confirmAction});
 if(typeof module!=='undefined')module.exports=root.HomeUI;
})(typeof window!=='undefined'?window:globalThis);

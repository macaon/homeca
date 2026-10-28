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
 const confirmations=new WeakSet();
 function confirmAction(dialog,{title='Remove item',message,confirmLabel='Remove'}={}){if(confirmations.has(dialog))throw new Error('Confirmation already open');confirmations.add(dialog);dialog.querySelector('[data-confirm-title]').textContent=title;dialog.querySelector('[data-confirm-message]').textContent=message;dialog.querySelector('[data-confirm-accept]').textContent=confirmLabel;dialog.returnValue='';return new Promise(resolve=>{dialog.addEventListener('close',()=>{confirmations.delete(dialog);resolve(dialog.returnValue==='confirm');},{once:true});dialog.showModal();dialog.querySelector('[value="cancel"]')?.focus();});}
 root.HomeUI=Object.freeze({version:'0.1.0',escape,icon,applyTheme,themeController,dropdown,overflow,tabs,toast,confirmAction});
 if(typeof module!=='undefined')module.exports=root.HomeUI;
})(typeof window!=='undefined'?window:globalThis);

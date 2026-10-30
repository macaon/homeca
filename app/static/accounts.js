/* Named administrator controls; authentication and authorization stay on the server. */
window.HomeAccounts = {
  mount(root, {api, notify}) {
    const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    let current, busy=false;
    root.innerHTML='<h3 class="hui-access-heading">Users</h3><p class="hui-small">Every account is an administrator with full access to this application. The original local administrator is retained for recovery.</p><p class="hui-error" role="alert" data-users-error></p><div data-user-list></div><form data-add-user><h3>Add administrator</h3><label>Username<input name="username" required maxlength="64" pattern="[A-Za-z0-9_.@-]+" autocomplete="off"></label><label>Initial password<input name="password" type="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label><div class="hui-dialog-foot"><button class="hui-primary">Add administrator</button></div></form>';
    const error=root.querySelector('[data-users-error]');
    async function refresh() {
      try {
        const [users,state]=await Promise.all([api('/api/users'),api('/api/state')]);current=state.user;
        root.querySelector('[data-user-list]').innerHTML=users.map(user=>`<div class="hui-list-row"><div class="hui-list-main"><strong>${escape(user.username)}</strong><div class="hui-small">Administrator · ${user.local?'Local account':'SSO-only'}${user.primary?' · recovery account':''}</div></div>${user.username!==current?`<button type="button" class="hui-ghost" data-reset="${escape(user.username)}">Reset password</button>${!user.primary?`<button type="button" class="hui-ghost hui-danger" data-remove="${escape(user.username)}">Remove</button>`:''}`:''}</div>`).join('');error.textContent='';
      } catch(e) {error.textContent=e.message;}
    }
    function taskDialog(title, message, password=false) {
      const dialog=document.createElement('dialog');dialog.setAttribute('aria-label',title);
      dialog.innerHTML=`<form><div class="hui-dialog-head"><h2>${escape(title)}</h2><button type="button" class="hui-icon-button" data-close aria-label="Close">${HomeUI.icon('close')}</button></div><p>${escape(message)}</p>${password?'<label>New password<input name="password" type="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label>':''}<p class="hui-error" role="alert"></p><div class="hui-dialog-foot"><button type="button" data-close>Cancel</button><button class="${password?'hui-primary':'hui-danger'}">${password?'Reset password':'Remove administrator'}</button></div></form>`;
      document.body.append(dialog);const trigger=document.activeElement;dialog.addEventListener('close',()=>{dialog.remove();trigger?.focus();},{once:true});dialog.querySelectorAll('[data-close]').forEach(button=>button.onclick=()=>dialog.close());dialog.showModal();dialog.querySelectorAll('[data-close]')[1].focus();return dialog;
    }
    root.addEventListener('click',event=>{
      const button=event.target.closest('[data-reset],[data-remove]');if(!button||busy)return;
      const reset=button.hasAttribute('data-reset'),username=reset?button.dataset.reset:button.dataset.remove;
      const dialog=taskDialog(reset?'Reset password':'Remove administrator',reset?`Set a local password for “${username}”. Their existing sessions will be signed out. SSO remains linked.`:`Remove “${username}” and revoke their sessions? Certificates, registry images and application data remain. Their SSO access is blocked until an administrator explicitly restores the account.`,reset);
      dialog.querySelector('form').onsubmit=async e=>{e.preventDefault();busy=true;const submit=e.submitter;submit.disabled=true;try{await api('/api/users/'+encodeURIComponent(username)+(reset?'/password':''),reset?'PUT':'DELETE',reset?{password:dialog.querySelector('[name=password]').value}:undefined);dialog.close();await refresh();notify(reset?'Password reset; sessions revoked':'Administrator removed');}catch(err){dialog.querySelector('.hui-error').textContent=err.message;}finally{busy=false;submit.disabled=false;}};
    });
    root.querySelector('form').onsubmit=async event=>{event.preventDefault();if(busy)return;busy=true;event.submitter.disabled=true;const form=event.currentTarget;try{await api('/api/users','POST',{username:form.elements.username.value,password:form.elements.password.value});form.reset();await refresh();notify('Administrator added');}catch(e){error.textContent=e.message;}finally{busy=false;event.submitter.disabled=false;}};
    return {refresh};
  }
};

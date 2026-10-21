const accountBox=document.getElementById('accounts');
const message=document.getElementById('message');
const formatBytes=n=>Number.isFinite(n)?new Intl.NumberFormat('ru-RU',{maximumFractionDigits:1}).format(n/1048576)+' МиБ':'—';
const date=n=>n?new Date(n*1000).toLocaleString('ru-RU'):'—';
async function api(path,payload){const response=await fetch(path,{method:payload?'POST':'GET',headers:payload?{'Content-Type':'application/json','X-Pingtun-Admin':'1'}:{},body:payload?JSON.stringify(payload):undefined,cache:'no-store'});const data=await response.json();if(!response.ok)throw Error(data.error||`HTTP ${response.status}`);return data}
function element(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node}
function button(label,action,cls=''){const node=element('button',cls,label);node.type='button';node.addEventListener('click',action);return node}
async function mutate(id,action){if(action==='delete'&&!confirm('Удалить аккаунт и его ключи? Подключение будет остановлено.'))return;try{await api(`/api/accounts/${id}/${action}`,{});message.textContent=action==='delete'?'Аккаунт удалён.':'Состояние обновлено.';await refresh()}catch(error){message.textContent=error.message}}
function render(account){
  const legacy=account.source==='legacy';
  const card=element('article','account');
  const head=element('div','account-head');
  const title=element('div');
  title.append(element('h3','',account.name),element('div','muted',`${account.id} · ${account.kind==='android'?'Android':'Linux'} · ${account.client_address} · ${legacy?'Ранее настроен':'Создан в панели'}`));
  head.append(title,element('span',`badge ${account.state==='active'?'active':''}`,account.state==='active'?'Активен':'Остановлен'));
  card.append(head);
  const metrics=element('div','metrics');
  const wire=account.stats.source==='wire';
  for(const [label,value] of [[wire?'Внешний трафик: получено':'Получено',formatBytes(account.stats.rx_bytes)],[wire?'Внешний трафик: передано':'Передано',formatBytes(account.stats.tx_bytes)],['Последнее соединение',date(account.stats.last_handshake_time_sec)],['Данные на',date(account.stats.now_unix)]]){
    const box=element('div');
    box.append(element('span','muted',label),element('strong','',value));
    metrics.append(box);
  }
  card.append(metrics);
  const actions=element('div','actions');
  if(!legacy)actions.append(button('Скачать профиль',()=>{location.href=`/api/accounts/${account.id}/download`}));
  actions.append(button(account.state==='active'?'Заблокировать':'Разблокировать',()=>mutate(account.id,account.state==='active'?'block':'unblock')));
  if(!legacy)actions.append(button('Удалить',()=>mutate(account.id,'delete'),'danger'));
  card.append(actions);
  return card;
}
async function refresh(){try{const accounts=await api('/api/accounts');accountBox.replaceChildren(...accounts.map(render));document.getElementById('count').textContent=`${accounts.length}`;if(!accounts.length)accountBox.append(element('p','muted','Пока нет аккаунтов.'));const selected=transportTarget.value;transportTarget.replaceChildren(new Option('Новым клиентам по умолчанию','defaults'),...accounts.filter(a=>a.source!=='legacy').map(a=>new Option(`${a.name} (${a.id})`,a.id)));transportTarget.value=[...transportTarget.options].some(o=>o.value===selected)?selected:'defaults';await loadTransport()}catch(error){message.textContent=error.message}}
document.getElementById('refresh').addEventListener('click',refresh);
document.getElementById('create').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget;const data=new FormData(form);const submit=form.querySelector('button[type=submit]');submit.disabled=true;try{const account=await api('/api/accounts',{name:data.get('name'),kind:data.get('kind')});message.textContent=`Аккаунт ${account.name} создан. Скачайте профиль и передайте клиенту защищённым способом.`;form.reset();await refresh()}catch(error){message.textContent=error.message}finally{submit.disabled=false}});
document.getElementById('admin-settings').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget;const data=new FormData(form);const submit=form.querySelector('button[type=submit]');submit.disabled=true;try{await api('/api/admin',{login:data.get('login'),current_password:data.get('current_password'),password:data.get('password')});form.querySelector('[name=current_password]').value='';form.querySelector('[name=password]').value='';message.textContent='Логин и пароль изменены. Обновите страницу и войдите с новыми данными.'}catch(error){message.textContent=error.message}finally{submit.disabled=false}});
api('/api/admin').then(data=>{document.querySelector('#admin-settings [name=login]').value=data.login}).catch(error=>{message.textContent=error.message});
const transportForm=document.getElementById('transport-settings');
const transportTarget=document.getElementById('transport-target');
const transportKeys=['mtu','wire_mtu','lanes','window','hold_ms','max_pps','max_window','idle_ms','id_mode'];
let transportGeneration=0;
function transportPath(){return transportTarget.value==='defaults'?'/api/transport':`/api/accounts/${transportTarget.value}/transport`}
async function loadTransport(){const generation=++transportGeneration;const submit=transportForm.querySelector('button[type=submit]');submit.disabled=true;try{const data=await api(transportPath());if(generation!==transportGeneration)return;for(const key of transportKeys)transportForm.elements.namedItem(key).value=data[key];submit.disabled=false}catch(error){if(generation===transportGeneration)message.textContent=error.message}}
transportTarget.addEventListener('change',loadTransport);
transportForm.addEventListener('submit',async event=>{event.preventDefault();const existing=transportTarget.value!=='defaults';if(existing&&!confirm('Активный туннель будет перезапущен. Для восстановления соединения скачайте и импортируйте новый профиль. Продолжить?'))return;const submit=transportForm.querySelector('button[type=submit]');submit.disabled=true;transportTarget.disabled=true;const payload=Object.fromEntries(transportKeys.map(key=>[key,key==='id_mode'?transportForm.elements.namedItem(key).value:Number(transportForm.elements.namedItem(key).value)]));try{await api(transportPath(),payload);message.textContent=existing?'Параметры сохранены. Скачайте новый профиль аккаунта и импортируйте на клиенте.':'Параметры для новых аккаунтов сохранены.'}catch(error){message.textContent=error.message}finally{transportTarget.disabled=false;await loadTransport()}});
refresh();

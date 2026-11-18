const params=new URLSearchParams(location.hash.slice(1));
document.querySelector('#guest-name').textContent=params.get('name')||'VM console';
let rfb;
try{
  if(!params.get('token'))throw new Error('Open the console from a running VM in Hypertalco.');
  const me=await fetch('/api/me');if(!me.ok)throw new Error('Sign in to Hypertalco before opening a console.');
  const {default:RFB}=await import('/novnc/core/rfb.js');
  const url=new URL(params.get('path')||'/websockify',location.origin);url.protocol='wss:';url.searchParams.set('token',params.get('token'));
  if(url.origin!==location.origin.replace(/^https:/,'wss:'))throw new Error('Invalid console endpoint');
  rfb=new RFB(document.querySelector('#screen'),url.href,{shared:true});rfb.scaleViewport=true;rfb.resizeSession=true;
  rfb.addEventListener('connect',()=>document.querySelector('#connection-state').textContent='Connected');
  rfb.addEventListener('disconnect',()=>document.querySelector('#connection-state').textContent='Disconnected');
  rfb.addEventListener('securityfailure',()=>document.querySelector('#console-error').textContent='Console authentication failed. Open a new console ticket.');
  document.querySelector('#ctrl-alt-del').addEventListener('click',()=>rfb.sendCtrlAltDel());
  document.querySelector('#disconnect').addEventListener('click',()=>rfb.disconnect());
}catch(error){document.querySelector('#connection-state').textContent='Unavailable';document.querySelector('#console-error').textContent=error.message;}
window.addEventListener('beforeunload',()=>rfb?.disconnect());

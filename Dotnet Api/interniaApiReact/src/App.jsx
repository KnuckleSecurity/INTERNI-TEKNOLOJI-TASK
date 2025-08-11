import React, { useEffect, useState, useCallback } from 'react'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const LOGO = 'https://static.wixstatic.com/media/22ece4_ce83909811a443479427841b459c24b8~mv2.png/v1/fill/w_518,h_144,al_c,lg_1,q_85,enc_avif,quality_auto/2025-03-03%20112411-Photoroom.png'

// Genel fetch helper: Artık Authorization yok, cookie kullanılacak.
async function apiFetch(path, { method='GET', body } = {}) {
  const res = await fetch(API_URL + path, {
    method,
    headers: {'Content-Type':'application/json','Accept':'application/json'},
    body: body !== undefined ? JSON.stringify(body) : undefined,
    mode: 'cors',
    credentials: 'include', // <- JWT cookie gitsin / gelsin
  })
  const text = await res.text()
  if (!res.ok) throw new Error(res.status+' '+res.statusText+' - '+text)
  try { return JSON.parse(text) } catch { return text }
}

// Basit toast
function useToast(){
  const [items,setItems]=useState([])
  const push = useCallback((type,msg)=>{
    const id = Math.random().toString(36).slice(2)
    setItems(list=>[...list,{id,type,msg}])
    setTimeout(()=>setItems(list=>list.filter(t=>t.id!==id)),2200)
  },[])
  const node = <div className="toast-wrap">{items.map(t=>
    <div key={t.id} className={'toast '+(t.type==='err'?'err':'')}>{t.msg}</div>
  )}</div>
  return {push,node}
}

// UI Nav: Panel yalnızca authed iken görünür
function Nav({ route, setRoute, isAuthed, onLogout }){
  return (
    <div className="nav">
      <div className="page bar">
        <img className="logo" src={LOGO} alt="logo"/>
        <div className="tabs">
          <div className={'tab '+(route==='home'?'active':'')} onClick={()=>setRoute('home')}>Ana Sayfa</div>
          <div className={'tab '+(route==='news'?'active':'')} onClick={()=>setRoute('news')}>Haberler</div>
          {isAuthed && (
            <div className={'tab '+(route==='panel'?'active':'')} onClick={()=>setRoute('panel')}>Panel</div>
          )}
        </div>
        {isAuthed
          ? <button className="btn" onClick={onLogout}>Çıkış</button>
          : <button className="btn primary" onClick={()=>setRoute('login')}>Giriş Yap</button>}
      </div>
    </div>
  )
}

// Login: Backend cookie set ediyor, biz sadece 200 görürsek authed kabul ederiz
function Login({ onAuthed, toast }){
  const [u,setU]=useState('')
  const [p,setP]=useState('')
  const [loading,setLoading]=useState(false)

  async function submit(e){
    e.preventDefault()
    setLoading(true)
    try{
      await apiFetch('/auth/login',{method:'POST',body:{username:u,password:p}})
      onAuthed(true)                  // UI'da oturum açık
      toast.push('ok','Giriş başarılı')
    }catch(err){
      toast.push('err', err.message || 'Giriş başarısız')
    }finally{
      setLoading(false)
    }
  }

  return (
    <div className="login-wrap page">
      <form onSubmit={submit} className="card">
        <h2>Giriş Yap</h2>
        <div className="sub">Panoya erişmek için oturum açın</div>
        <label className="inline">
          <span>Kullanıcı adı</span>
          <input className="input" value={u} onChange={e=>setU(e.target.value)} placeholder="admin"/>
        </label>
        <label className="inline">
          <span>Şifre</span>
          <input className="input" type="password" value={p} onChange={e=>setP(e.target.value)} placeholder="12345"/>
        </label>
        <div className="actions">
          <button className="btn primary" disabled={loading}>{loading?'Gönderiliyor...':'Giriş'}</button>
        </div>
      </form>
    </div>
  )
}

// Haberler (public)
function NewsPublic(){
  const [items,setItems]=useState([])
  const [loading,setLoading]=useState(false)

  useEffect(()=>{ (async()=>{
    setLoading(true)
    try{ const d=await apiFetch('/api/news'); setItems(Array.isArray(d)?d:[]) }catch{}
    finally{ setLoading(false) }
  })() },[])

  return (
    <div className="page">
      <h1 style={{margin:'8px 0 12px 0'}}>Haberler</h1>
      <div className="news-list">
        {loading? <div>Yükleniyor...</div> :
          (items.length? items : [{title:'Örnek haber',description:'Açıklama...',publishedAt:new Date().toISOString()}]).map((n,i)=>(
          <div key={n.id||i} className="news-card">
            <div className="news-title">{n.title}</div>
            <div className="news-meta">{n.publishedAt ? new Date(n.publishedAt).toLocaleString() : ''}</div>
            <div className="news-desc">{n.description}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// Ana Sayfa (home)
function Home({ isAuthed, go }){
  const [items,setItems]=useState([])
  const [loading,setLoading]=useState(false)

  useEffect(()=>{ (async()=>{
    setLoading(true)
    try{ const d=await apiFetch('/api/news?limit=3'); setItems(Array.isArray(d)?d:[]) }catch{}
    finally{ setLoading(false) }
  })() },[])

  return (
    <div className="page">

    <div className="welcome-wrap" style={{ display: 'flex', justifyContent: 'center' }}>
      <div className="card" style={{ width: '100%', maxWidth: 820, margin: '12px 0', textAlign: 'center' }}>
        <h1 style={{ marginBottom: 6 }}>Hoşgeldin 👋</h1>
        <div className="sub"> INTERNIA Techolongy, Microsoft teknolojileri ile efektif çözümler sunarak 
        müşteri odaklı yaklaşımı ile kaliteli hizmet vermeyi amaçlar.</div>

        <div
          className="row"
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: 8,
            marginTop: 12,
            flexWrap: 'wrap'
          }}
        >
          <button className="btn primary" onClick={() => go(isAuthed ? 'panel' : 'login')}>
            {isAuthed ? 'Panele Git' : 'Giriş Yap'}
          </button>
          <button className="btn" onClick={() => go('news')}>Haberleri Gör</button>
        </div>
      </div>
    </div>

      <div className="banner-wrap" style={{marginBottom:12}}>
        <img src={BANNER} alt="banner" style={{width:'100%', height:300, objectFit:'cover', borderRadius:12}}/>
      </div>
      
      <div className="panel-card">
        <div className="row" style={{justifyContent:'space-between', alignItems:'center'}}>
          <div className="badge">Son Haberler</div>
          <button className="btn" onClick={()=>go('news')}>Tümü</button>
        </div>
        <div className="list" style={{marginTop:10}}>
          {loading ? <div>Yükleniyor...</div> : (
            items.length ? items : [{title:'Örnek haber',description:'Açıklama...',publishedAt:new Date().toISOString()}]
          ).slice(0,3).map((n,i)=>(
            <div key={n.id||i} className="news-card" style={{padding:'8px 10px'}}>
              <div className="news-title" style={{fontSize:14, fontWeight:600, marginBottom:2}}>{n.title}</div>
              <div className="news-meta" style={{fontSize:12, opacity:.7}}>{n.publishedAt ? new Date(n.publishedAt).toLocaleString() : ''}</div>
              <div className="news-desc" style={{fontSize:13, opacity:.9, overflow:'hidden', display:'-webkit-box', WebkitLineClamp:2, WebkitBoxOrient:'vertical'}}>{n.description}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// Panel (admin işlemleri – 401 gelirse login uyar)
function Panel({ toast, onUnauthorized }){
  const [items,setItems]=useState([])
  const [title,setTitle]=useState('')
  const [description,setDescription]=useState('')
  const [publishedAt] = useState(new Date().toISOString())

  async function handle(fn){
    try{
      await fn()
    }catch(err){
      if (String(err.message||'').startsWith('401')) {
        onUnauthorized?.()
        toast.push('err','Oturum gerekir (401)')
      } else {
        toast.push('err', err.message || 'Hata')
      }
    }
  }

  async function fetchNews(){ const d=await apiFetch('/api/news'); setItems(Array.isArray(d)?d:[]) }
  useEffect(()=>{ fetchNews() },[])

  const add   = ()=> handle(async()=>{ await apiFetch('/api/news',{method:'POST',body:{title,description,publishedAt}}); setTitle(''); setDescription(''); toast.push('ok','Haber eklendi'); await fetchNews() })
  const update= (id,payload)=> handle(async()=>{ await apiFetch(`/api/news/${id}`,{method:'PUT',body:payload}); toast.push('ok','Güncellendi'); await fetchNews() })
  const del   = (id)=> handle(async()=>{ await apiFetch(`/api/news/${id}`,{method:'DELETE'}); toast.push('ok','Silindi'); await fetchNews() })
  const seed  = ()=> handle(async()=>{ await apiFetch('/api/news/seed',{method:'POST'}); toast.push('ok','Seed tamam'); await fetchNews() })
  const clear = ()=> handle(async()=>{ await apiFetch('/api/news',{method:'DELETE'}); toast.push('ok','Temizlendi'); await fetchNews() })

  return (
    <div className="page">
      <div className="panel-grid">
        <div className="panel-card">
          <div className="label">Yeni Haber</div>
          <input className="input" placeholder="Başlık" value={title} onChange={e=>setTitle(e.target.value)}/>
          <textarea className="textarea" placeholder="Açıklama" value={description} onChange={e=>setDescription(e.target.value)}/>
          <div className="label" style={{marginTop:10}}>Yayın tarihi (ISO)</div>
          <div className="kbd">{publishedAt}</div>
          <div className="row" style={{marginTop:12}}>
            <button className="btn primary" onClick={add}>Ekle</button>
            <button className="btn" onClick={seed}>Seed</button>
            <button className="btn danger" onClick={clear}>Hepsini Sil</button>
          </div>
        </div>
        <div>
          <div className="panel-card">
            <div className="row" style={{justifyContent:'space-between', alignItems:'center'}}>
              <div className="badge">Toplam: {items.length}</div>
              <button className="btn" onClick={fetchNews}>Yenile</button>
            </div>
            <div className="list" style={{marginTop:12}}>
              {items.map(n => <Item key={n.id} item={n} onUpdate={update} onDelete={del}/> )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
function Item({ item, onUpdate, onDelete }){
  const [edit,setEdit]=useState(false)
  const [title,setTitle]=useState(item.title||'')
  const [description,setDescription]=useState(item.description||'')
  return (
    <div className="panel-card">
      {edit ? (
        <>
          <input className="input" value={title} onChange={e=>setTitle(e.target.value)}/>
          <textarea className="textarea" value={description} onChange={e=>setDescription(e.target.value)}/>
          <div className="controls">
            <button className="btn primary" onClick={()=>{ onUpdate(item.id,{title,description}); setEdit(false) }}>Kaydet</button>
            <button className="btn" onClick={()=>setEdit(false)}>Vazgeç</button>
          </div>
        </>
      ) : (
        <>
          <div className="news-title" style={{marginBottom:4}}>{item.title}</div>
          <div className="news-meta">{item.publishedAt ? new Date(item.publishedAt).toLocaleString() : ''}</div>
          <div className="news-desc">{item.description}</div>
          <div className="controls">
            <button className="btn" onClick={()=>setEdit(true)}>Düzenle</button>
            <button className="btn danger" onClick={()=>onDelete(item.id)}>Sil</button>
          </div>
        </>
      )}
    </div>
  )
}

export default function App(){
  const [isAuthed,setIsAuthed] = useState(false) // Cookie okunamaz; UI state

  const [route,setRoute]=useState('home')
  const toast = useToast()

  async function onLogout(){
    try { await apiFetch('/auth/logout', { method:'POST' }) } catch {}
    setIsAuthed(false)
    if (route==='panel') setRoute('login')
    toast.push('ok','Çıkış yapıldı')
  }

  // Panel'e giderken login zorunluluğu
  useEffect(()=>{ if(!isAuthed && route==='panel') setRoute('login') },[isAuthed, route])

  // Admin çağrısında 401 olursa tetiklenecek handler
  const onUnauthorized = ()=> setIsAuthed(false)

  return (
    <>
      <Nav route={route} setRoute={setRoute} isAuthed={isAuthed} onLogout={onLogout} />
      {route==='home' && <Home isAuthed={isAuthed} go={setRoute} />}
      {route==='login' && <Login onAuthed={(v)=>{ setIsAuthed(v); setRoute('panel') }} toast={toast}/>}
      {route==='news' && <NewsPublic/>}
      {route==='panel' && isAuthed && <Panel toast={toast} onUnauthorized={onUnauthorized}/>}
      {toast.node}
    </>
  )
}
const BANNER = 'https://static.wixstatic.com/media/06cb19_337c65cd605c4b3792ca621b2e4a7c17~mv2.jpg/v1/fill/w_1090,h_720,al_c,q_85,enc_avif,quality_auto/Teknokent.jpg'

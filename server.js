require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTA_CLAVE_EN_RAILWAY';
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  port: Number(process.env.MYSQLPORT || process.env.DB_PORT || 3306),
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD,
  database: process.env.MYSQLDATABASE || process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: 'Z'
});

function sign(user){ return jwt.sign({ id:user.id, rol:user.rol, numero:user.numero, nombre:user.nombre, usuario:user.usuario }, JWT_SECRET, { expiresIn:'12h' }); }
function auth(req,res,next){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):null;
  if(!token) return res.status(401).json({error:'No autenticado'});
  try{ req.user=jwt.verify(token,JWT_SECRET); next(); }catch(e){ return res.status(401).json({error:'Sesión expirada'}); }
}
function adminOnly(req,res,next){ if(req.user.rol!=='admin') return res.status(403).json({error:'Solo administrador'}); next(); }
async function audit(userId,accion,descripcion){ try{ await pool.execute('INSERT INTO historial(usuario_id,accion,descripcion) VALUES (?,?,?)',[userId||null,accion,descripcion]); }catch(e){ console.error('Audit error',e); } }
function cleanUser(u){ return {id:u.id,numero:u.numero,nombre:u.nombre,usuario:u.usuario,rol:u.rol,activo:!!u.activo,created_at:u.created_at}; }

app.get('/api/health', async (req,res)=>{ try{ await pool.query('SELECT 1'); res.json({ok:true}); }catch(e){res.status(503).json({ok:false,error:e.message});} });

app.post('/api/login', async (req,res)=>{
  try{
    const {usuario,password,numero}=req.body||{};
    const ident = usuario || (numero!=null ? String(numero) : '');
    const [rows]=await pool.execute('SELECT * FROM usuarios WHERE (usuario=? OR numero=?) AND activo=1 LIMIT 1',[ident, Number.isNaN(Number(ident))? -1:Number(ident)]);
    if(!rows.length) return res.status(401).json({error:'Credenciales inválidas'});
    const u=rows[0];
    if(!(await bcrypt.compare(String(password||''),u.password_hash))) return res.status(401).json({error:'Credenciales inválidas'});
    const token=sign(u); await audit(u.id,'LOGIN',`Inicio de sesión como ${u.rol}`); res.json({token,user:cleanUser(u)});
  }catch(e){ console.error(e); res.status(500).json({error:'Error al iniciar sesión'}); }
});

app.put('/api/admin/credentials',auth,adminOnly,async(req,res)=>{ try{ const {usuario,password}=req.body||{}; if(!usuario) return res.status(400).json({error:'Usuario requerido'}); const fields=[usuario]; if(password){ const hash=await bcrypt.hash(password,12); await pool.execute('UPDATE usuarios SET usuario=?,password_hash=? WHERE rol=\'admin\'',[usuario,hash]); } else { await pool.execute('UPDATE usuarios SET usuario=? WHERE rol=\'admin\'',[usuario]); } await audit(req.user.id,'EDITAR_CREDENCIALES','Actualizó credenciales de admin'); res.json({ok:true}); }catch(e){res.status(400).json({error:e.message});} });
app.get('/api/me',auth,async(req,res)=>res.json({user:req.user}));

app.get('/api/encuestadores/public',async(req,res)=>{ const [r]=await pool.query("SELECT numero,nombre FROM usuarios WHERE rol='encuestador' AND activo=1 ORDER BY numero"); res.json(r); });
app.get('/api/encuestadores',auth,adminOnly,async(req,res)=>{ const [r]=await pool.query("SELECT id,numero,nombre,usuario,rol,activo,created_at FROM usuarios WHERE rol='encuestador' ORDER BY numero"); res.json(r); });
app.post('/api/encuestadores',auth,adminOnly,async(req,res)=>{
  try{
    const {numero,nombre,usuario,password}=req.body;
    if(!numero || !nombre || !usuario || !password) return res.status(400).json({error:'Completa número, nombre, usuario y contraseña'});
    const hash=await bcrypt.hash(password,12);
    const [r]=await pool.execute("INSERT INTO usuarios(numero,nombre,usuario,password_hash,rol) VALUES(?,?,?,?, 'encuestador')",[numero,nombre,usuario,hash]);
    await audit(req.user.id,'CREAR_ENCUESTADOR',`Creó encuestador #${numero} (${nombre})`);
    res.json({ok:true,id:r.insertId});
  }catch(e){res.status(400).json({error:e.code==='ER_DUP_ENTRY'?'El número o usuario ya existe':e.message});}
});
app.put('/api/encuestadores/:id',auth,adminOnly,async(req,res)=>{
  try{
    const id=Number(req.params.id); const {numero,nombre,usuario,activo,password}=req.body;
    if(password){ const hash=await bcrypt.hash(password,12); await pool.execute('UPDATE usuarios SET numero=?,nombre=?,usuario=?,activo=?,password_hash=? WHERE id=? AND rol=\'encuestador\'',[numero,nombre,usuario,!!activo,hash,id]); }
    else await pool.execute('UPDATE usuarios SET numero=?,nombre=?,usuario=?,activo=? WHERE id=? AND rol=\'encuestador\'',[numero,nombre,usuario,!!activo,id]);
    await audit(req.user.id,'EDITAR_ENCUESTADOR',`Editó encuestador #${numero} (${nombre})${password?' y cambió sus credenciales':''}`); res.json({ok:true});
  }catch(e){res.status(400).json({error:e.code==='ER_DUP_ENTRY'?'El número o usuario ya existe':e.message});}
});

app.get('/api/manzanas',auth,async(req,res)=>{
  const [r]=await pool.query('SELECT id,distrito,zona_censal,manzana,lat,lon FROM manzanas ORDER BY id'); res.json(r);
});

app.get('/api/asignaciones/:encId',auth,async(req,res)=>{
  const encId=Number(req.params.encId); if(req.user.rol!=='admin' && req.user.id!==encId) return res.status(403).json({error:'Sin permiso'});
  const [r]=await pool.execute(`SELECT a.id,a.manzana_id,a.orden_visita,a.estado,m.distrito,m.zona_censal,m.manzana,m.lat,m.lon FROM asignaciones a JOIN manzanas m ON m.id=a.manzana_id WHERE a.encuestador_id=? ORDER BY a.orden_visita`,[encId]);
  res.json(r);
});
app.post('/api/asignaciones',auth,adminOnly,async(req,res)=>{
  const {encuestador_id,manzanas}=req.body||{}; if(!encuestador_id||!Array.isArray(manzanas)) return res.status(400).json({error:'Datos inválidos'});
  const c=await pool.getConnection(); try{ await c.beginTransaction(); if(manzanas.length){ await c.execute('DELETE FROM asignaciones WHERE encuestador_id=? OR manzana_id IN ('+manzanas.map(()=>'?').join(',')+')',[encuestador_id,...manzanas]); }
    for(let i=0;i<manzanas.length;i++){ const mid=Number(manzanas[i]); if(mid) await c.execute('INSERT INTO asignaciones(encuestador_id,manzana_id,orden_visita) VALUES(?,?,?)',[encuestador_id,mid,i+1]); }
    await c.commit(); await audit(req.user.id,'ASIGNAR_MANZANAS',`Asignó ${manzanas.length} manzanas al encuestador ${encuestador_id}`); res.json({ok:true,count:manzanas.length});
  }catch(e){await c.rollback();res.status(500).json({error:e.message});}finally{c.release();}
});
app.put('/api/asignaciones/:id/estado',auth,async(req,res)=>{ const id=Number(req.params.id); const {estado}=req.body; if(!['pendiente','visitada'].includes(estado)) return res.status(400).json({error:'Estado inválido'}); await pool.execute('UPDATE asignaciones SET estado=? WHERE id=?',[estado,id]); res.json({ok:true}); });

app.get('/api/geometrias/:encId',auth,async(req,res)=>{const id=Number(req.params.encId);if(req.user.rol!=='admin'&&req.user.id!==id)return res.status(403).json({error:'Sin permiso'});const [r]=await pool.execute('SELECT id,encuestador_id,tipo,nombre,geojson,created_at FROM geometrias WHERE encuestador_id=?',[id]);res.json(r);});
app.post('/api/geometrias',auth,adminOnly,async(req,res)=>{const {encuestador_id,tipo,nombre,geojson}=req.body||{};if(!encuestador_id||!['ruta','zona','otro'].includes(tipo)||!nombre||!geojson)return res.status(400).json({error:'Datos inválidos'});await pool.execute('INSERT INTO geometrias(encuestador_id,tipo,nombre,geojson) VALUES(?,?,?,?)',[encuestador_id,tipo,nombre,JSON.stringify(geojson)]);await audit(req.user.id,'CREAR_GEOMETRIA',`Creó geometría ${nombre}`);res.json({ok:true});});
app.delete('/api/geometrias/:id',auth,adminOnly,async(req,res)=>{const id=Number(req.params.id);await pool.execute('DELETE FROM geometrias WHERE id=?',[id]);await audit(req.user.id,'ELIMINAR_GEOMETRIA',`Eliminó geometría ${id}`);res.json({ok:true});});

app.get('/api/contadores',auth,async(req,res)=>{let sql='SELECT id,encuestador_id,nombre,descripcion,meta,valor,criterio_json,activo,created_at,updated_at FROM contadores WHERE activo=1 AND (encue...';res.status(501).json({error:'Not implemented'});});
app.post('/api/contadores',auth,adminOnly,async(req,res)=>{const {encuestador_id,nombre,descripcion,meta,criterio_json}=req.body||{};if(!nombre)return res.status(400).json({error:'Nombre requerido'});await pool.execute('INSERT INTO contadores(encuestador_id,nombre,descripcion,meta,criterio_json) VALUES(?,?,?,?,?)',[encuestador_id||null,nombre,descripcion||null,meta||0,criterio_json||null]);res.json({ok:true});});
app.put('/api/contadores/:id',auth,adminOnly,async(req,res)=>{const id=Number(req.params.id);const {nombre,descripcion,meta,activo,encuestador_id,criterio_json}=req.body;await pool.execute('UPDATE contadores SET nombre=?,descripcion=?,meta=?,activo=?,encuestador_id=?,criterio_json=? WHERE id=?',[nombre,descripcion,meta,!!activo,encuestador_id||null,criterio_json||null,id]);res.json({ok:true});});
app.post('/api/contadores/:id/sumar',auth,async(req,res)=>changeCounter(req,res,1));
app.post('/api/contadores/:id/restar',auth,async(req,res)=>changeCounter(req,res,-1));
async function changeCounter(req,res,delta){const id=Number(req.params.id);const c=await pool.getConnection();try{await c.beginTransaction();const [r]=await c.execute('SELECT * FROM contadores WHERE id=? FOR UPDATE',[id]);if(!r.length)throw new Error('No existe');const newVal=(r[0].valor||0)+delta;await c.execute('UPDATE contadores SET valor=?,updated_at=NOW() WHERE id=?',[newVal,id]);await c.commit();res.json({ok:true,valor:newVal});}catch(e){await c.rollback();res.status(400).json({error:e.message});}finally{c.release();}}

app.post('/api/ubicacion',auth,async(req,res)=>{if(req.user.rol!=='encuestador')return res.status(403).json({error:'Solo encuestadores'});const {lat,lon,accuracy}=req.body||{};if(!Number.isFinite(lat)||!Number.isFinite(lon))return res.status(400).json({error:'Lat/Lon inválidos'});await pool.execute('INSERT INTO ubicaciones(encuestador_id,lat,lon,precision_m,fecha_hora) VALUES(?,?,?,?,NOW())',[req.user.id,lat,lon,accuracy||null]);res.json({ok:true});});
app.get('/api/ubicaciones',auth,adminOnly,async(req,res)=>{const [r]=await pool.query(`SELECT u.encuestador_id,u.lat,u.lon,u.precision_m,u.fecha_hora,e.numero,e.nombre FROM ubicaciones u JOIN usuarios e ON e.id=u.encuestador_id ORDER BY u.fecha_hora DESC LIMIT 100`);res.json(r);});

app.get('/api/historial',auth,adminOnly,async(req,res)=>{const [r]=await pool.query('SELECT h.id,h.accion,h.descripcion,h.fecha_hora,u.nombre,u.usuario FROM historial h LEFT JOIN usuarios u ON u.id=h.usuario_id ORDER BY h.fecha_hora DESC LIMIT 200');res.json(r);});

app.get('/api/resumen',auth,adminOnly,async(req,res)=>{const [[a]]=await pool.query("SELECT COUNT(*) total FROM usuarios WHERE rol='encuestador'");const [[m]]=await pool.query('SELECT COUNT(*) total FROM manzanas');res.json({encuestadores:a.total,manzanas:m.total});});


async function initDb(){
  const ddl=[
`CREATE TABLE IF NOT EXISTS usuarios (id INT AUTO_INCREMENT PRIMARY KEY, numero INT NULL UNIQUE, nombre VARCHAR(120) NOT NULL, usuario VARCHAR(80) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, rol ENUM('admin','encuestador') NOT NULL DEFAULT 'encuestador', activo TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS manzanas (id INT AUTO_INCREMENT PRIMARY KEY, distrito VARCHAR(80) NOT NULL, zona_censal VARCHAR(30) NOT NULL, manzana VARCHAR(40) NOT NULL, lat DECIMAL(10,7) NOT NULL, lon DECIMAL(10,7) NOT NULL)`,
`CREATE TABLE IF NOT EXISTS asignaciones (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, manzana_id INT NOT NULL, orden_visita INT NOT NULL DEFAULT 0, estado ENUM('pendiente','visitada') NOT NULL DEFAULT 'pendiente')`,
`CREATE TABLE IF NOT EXISTS geometrias (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, tipo ENUM('ruta','zona','otro') NOT NULL, nombre VARCHAR(120) NOT NULL, geojson JSON NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS contadores (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NULL, nombre VARCHAR(160) NOT NULL, descripcion VARCHAR(255) NULL, meta INT NOT NULL DEFAULT 0, valor INT NOT NULL DEFAULT 0, criterio_json JSON NULL, activo TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NULL)`,
`CREATE TABLE IF NOT EXISTS ubicaciones (id BIGINT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, lat DECIMAL(10,7) NOT NULL, lon DECIMAL(10,7) NOT NULL, precision_m DECIMAL(10,2) NULL, fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS historial (id BIGINT AUTO_INCREMENT PRIMARY KEY, usuario_id INT NULL, accion VARCHAR(80) NOT NULL, descripcion TEXT NOT NULL, fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`
  ];
  for(const sql of ddl) await pool.query(sql);
  const [mc]=await pool.query('SELECT COUNT(*) n FROM manzanas');
  if(Number(mc[0].n)===0){
    const html=require('fs').readFileSync(path.join(__dirname,'index.html'),'utf8'); const match=html.match(/const DATA=(\{.*?\});/s); if(!match) throw new Error('DATA no encontrada en index.html'); const data=JSON.parse(match[1]);
    const c=await pool.getConnection();
    try{await c.beginTransaction(); for(const m of data.manzanas){await c.execute('INSERT IGNORE INTO manzanas(distrito,zona_censal,manzana,lat,lon) VALUES(?,?,?,?,?)',[m.distrito,m.zona_censal,m.manzana,m.lat,m.lon]); } await c.commit(); }catch(e){await c.rollback();throw e;}finally{c.release();}
  }
  const adminUser=process.env.ADMIN_USER||'admin'; const adminPass=process.env.ADMIN_PASSWORD||'admin123';
  const [ar]=await pool.execute("SELECT id FROM usuarios WHERE usuario=? LIMIT 1",[adminUser]);
  if(!ar.length){const hash=await bcrypt.hash(adminPass,12);await pool.execute("INSERT INTO usuarios(numero,nombre,usuario,password_hash,rol) VALUES(NULL,?,?,?,'admin')",['Administrador',adminUser,hash]); }
}

app.get('/*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
initDb().then(()=>app.listen(PORT,()=>console.log(`Servidor en http://localhost:${PORT}`))).catch(e=>{console.error('No se pudo inicializar la BD:',e);process.exit(1);});

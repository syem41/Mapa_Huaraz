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
async function audit(userId,accion,descripcion){ try{ await pool.execute('INSERT INTO historial(usuario_id,accion,descripcion) VALUES (?,?,?)',[userId||null,accion,descripcion]); }catch(e){ console.error('audit',e.message); } }
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

app.put('/api/admin/credentials',auth,adminOnly,async(req,res)=>{ try{ const {usuario,password}=req.body||{}; if(!usuario) return res.status(400).json({error:'Usuario requerido'}); const fields=[usuario]; let sql='UPDATE usuarios SET usuario=?'; if(password){ fields.push(await bcrypt.hash(password,12)); sql+=', password_hash=?'; } fields.push(req.user.id); sql+=' WHERE id=? AND rol=\'admin\''; await pool.execute(sql,fields); await audit(req.user.id,'CAMBIAR_CREDENCIALES_ADMIN',`Cambió sus credenciales${password?' y contraseña':''}`); res.json({ok:true}); }catch(e){res.status(400).json({error:e.code==='ER_DUP_ENTRY'?'Ese usuario ya existe':e.message});} });
app.get('/api/me',auth,async(req,res)=>res.json({user:req.user}));

app.get('/api/encuestadores/public',async(req,res)=>{ const [r]=await pool.query("SELECT numero,nombre FROM usuarios WHERE rol='encuestador' AND activo=1 ORDER BY numero"); res.json(r); });
app.get('/api/encuestadores',auth,adminOnly,async(req,res)=>{ const [r]=await pool.query("SELECT id,numero,nombre,usuario,rol,activo,created_at FROM usuarios WHERE rol='encuestador' ORDER BY numero IS NULL, numero, id"); res.json(r); });
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
  const [r]=await pool.execute(`SELECT a.id,a.manzana_id,a.orden_visita,a.estado,m.distrito,m.zona_censal,m.manzana,m.lat,m.lon FROM asignaciones a JOIN manzanas m ON m.id=a.manzana_id WHERE a.encuestador_id=? ORDER BY a.orden_visita,m.id`,[encId]); res.json(r);
});
app.post('/api/asignaciones',auth,adminOnly,async(req,res)=>{
  const {encuestador_id,manzanas}=req.body||{}; if(!encuestador_id||!Array.isArray(manzanas)) return res.status(400).json({error:'Datos inválidos'});
  const c=await pool.getConnection(); try{ await c.beginTransaction(); if(manzanas.length){ await c.execute('DELETE FROM asignaciones WHERE encuestador_id=? OR manzana_id IN ('+manzanas.map(()=>'?').join(',')+')',[encuestador_id,...manzanas.map(Number)]); } else { await c.execute('DELETE FROM asignaciones WHERE encuestador_id=?',[encuestador_id]); }
    for(let i=0;i<manzanas.length;i++){ const mid=Number(manzanas[i]); if(mid) await c.execute('INSERT INTO asignaciones(encuestador_id,manzana_id,orden_visita) VALUES(?,?,?)',[encuestador_id,mid,i+1]); }
    await c.commit(); await audit(req.user.id,'ASIGNAR_MANZANAS',`Asignó ${manzanas.length} manzanas al encuestador ${encuestador_id}`); res.json({ok:true,count:manzanas.length});
  }catch(e){await c.rollback();res.status(500).json({error:e.message});}finally{c.release();}
});
app.put('/api/asignaciones/:id/estado',auth,async(req,res)=>{ const id=Number(req.params.id); const {estado}=req.body; if(!['pendiente','visitada'].includes(estado)) return res.status(400).json({error:'Estado inválido'}); const [r]=await pool.execute('SELECT encuestador_id FROM asignaciones WHERE id=?',[id]); if(!r.length)return res.status(404).json({error:'Asignación no encontrada'}); if(req.user.rol!=='admin'&&r[0].encuestador_id!==req.user.id)return res.status(403).json({error:'Sin permiso'}); await pool.execute('UPDATE asignaciones SET estado=? WHERE id=?',[estado,id]); await audit(req.user.id,'ESTADO_MANZANA',`Marcó asignación ${id} como ${estado}`); res.json({ok:true}); });

app.get('/api/geometrias/:encId',auth,async(req,res)=>{const id=Number(req.params.encId);if(req.user.rol!=='admin'&&req.user.id!==id)return res.status(403).json({error:'Sin permiso'});const [r]=await pool.execute('SELECT id,tipo,nombre,geojson,updated_at FROM geometrias WHERE encuestador_id=? ORDER BY id',[id]);res.json(r.map(x=>({...x,geojson:typeof x.geojson==='string'?JSON.parse(x.geojson):x.geojson})));});
app.post('/api/geometrias',auth,adminOnly,async(req,res)=>{const {encuestador_id,tipo,nombre,geojson}=req.body||{};if(!encuestador_id||!['ruta','zona','otro'].includes(tipo)||!nombre||!geojson)return res.status(400).json({error:'Completa los datos'});const [r]=await pool.execute('INSERT INTO geometrias(encuestador_id,tipo,nombre,geojson) VALUES(?,?,?,?)',[encuestador_id,tipo,nombre,JSON.stringify(geojson)]);await audit(req.user.id,'CREAR_GEOMETRIA',`Creó ${tipo} "${nombre}" para encuestador ${encuestador_id}`);res.json({ok:true,id:r.insertId});});
app.delete('/api/geometrias/:id',auth,adminOnly,async(req,res)=>{const id=Number(req.params.id);await pool.execute('DELETE FROM geometrias WHERE id=?',[id]);await audit(req.user.id,'ELIMINAR_GEOMETRIA',`Eliminó geometría ${id}`);res.json({ok:true});});

app.get('/api/contadores',auth,async(req,res)=>{let sql='SELECT id,encuestador_id,nombre,descripcion,meta,valor,criterio_json,activo,created_at,updated_at FROM contadores WHERE activo=1 AND (encuestador_id IS NULL OR encuestador_id=?) ORDER BY id';let [r]=await pool.execute(sql,[req.user.rol==='admin'?0:req.user.id]);if(req.user.rol==='admin'){[r]=await pool.query('SELECT id,encuestador_id,nombre,descripcion,meta,valor,criterio_json,activo,created_at,updated_at FROM contadores ORDER BY id');}res.json(r.map(x=>({...x,criterio_json:typeof x.criterio_json==='string'&&x.criterio_json?JSON.parse(x.criterio_json):x.criterio_json})));});
app.post('/api/contadores',auth,adminOnly,async(req,res)=>{const {encuestador_id,nombre,descripcion,meta,criterio_json}=req.body||{};if(!nombre)return res.status(400).json({error:'Nombre requerido'});const [r]=await pool.execute('INSERT INTO contadores(encuestador_id,nombre,descripcion,meta,criterio_json) VALUES(?,?,?,?,?)',[encuestador_id||null,nombre,descripcion||null,Math.max(0,Number(meta)||0),criterio_json?JSON.stringify(criterio_json):null]);await audit(req.user.id,'CREAR_CONTADOR',`Creó contador "${nombre}"`);res.json({ok:true,id:r.insertId});});
app.put('/api/contadores/:id',auth,adminOnly,async(req,res)=>{const id=Number(req.params.id);const {nombre,descripcion,meta,activo,encuestador_id,criterio_json}=req.body;await pool.execute('UPDATE contadores SET nombre=?,descripcion=?,meta=?,activo=?,encuestador_id=?,criterio_json=? WHERE id=?',[nombre,descripcion||null,Math.max(0,Number(meta)||0),!!activo,encuestador_id||null,criterio_json?JSON.stringify(criterio_json):null,id]);await audit(req.user.id,'EDITAR_CONTADOR',`Editó contador ${id}`);res.json({ok:true});});
app.post('/api/contadores/:id/sumar',auth,async(req,res)=>changeCounter(req,res,1));
app.post('/api/contadores/:id/restar',auth,async(req,res)=>changeCounter(req,res,-1));
async function changeCounter(req,res,delta){const id=Number(req.params.id);const c=await pool.getConnection();try{await c.beginTransaction();const [r]=await c.execute('SELECT * FROM contadores WHERE id=? FOR UPDATE',[id]);if(!r.length)throw new Error('Contador no encontrado');const x=r[0];if(req.user.rol!=='admin'&&x.encuestador_id!==null&&x.encuestador_id!==req.user.id)throw new Error('Sin permiso');const nv=Math.max(0,Number(x.valor)+delta);await c.execute('UPDATE contadores SET valor=? WHERE id=?',[nv,id]);await c.commit();await audit(req.user.id,delta>0?'CONTADOR_MAS':'CONTADOR_MENOS',`Contador "${x.nombre}": ${x.valor} → ${nv}`);res.json({ok:true,valor:nv});}catch(e){await c.rollback();res.status(400).json({error:e.message});}finally{c.release();}}

app.post('/api/ubicacion',auth,async(req,res)=>{if(req.user.rol!=='encuestador')return res.status(403).json({error:'Solo encuestadores'});const {lat,lon,accuracy}=req.body||{};if(!Number.isFinite(Number(lat))||!Number.isFinite(Number(lon)))return res.status(400).json({error:'Coordenadas inválidas'});await pool.execute('INSERT INTO ubicaciones(encuestador_id,lat,lon,precision_m) VALUES(?,?,?,?)',[req.user.id,lat,lon,accuracy||null]);await pool.execute('DELETE FROM ubicaciones WHERE encuestador_id=? AND id NOT IN (SELECT id FROM (SELECT id FROM ubicaciones WHERE encuestador_id=? ORDER BY fecha_hora DESC LIMIT 100) x)',[req.user.id,req.user.id]).catch(()=>{});res.json({ok:true});});
app.get('/api/ubicaciones',auth,adminOnly,async(req,res)=>{const [r]=await pool.query(`SELECT u.encuestador_id,u.lat,u.lon,u.precision_m,u.fecha_hora,e.numero,e.nombre FROM ubicaciones u JOIN usuarios e ON e.id=u.encuestador_id JOIN (SELECT encuestador_id,MAX(fecha_hora) mx FROM ubicaciones GROUP BY encuestador_id) z ON z.encuestador_id=u.encuestador_id AND z.mx=u.fecha_hora WHERE e.rol='encuestador' ORDER BY e.numero`);res.json(r);});

app.get('/api/historial',auth,adminOnly,async(req,res)=>{const [r]=await pool.query('SELECT h.id,h.accion,h.descripcion,h.fecha_hora,u.nombre,u.usuario FROM historial h LEFT JOIN usuarios u ON u.id=h.usuario_id ORDER BY h.id DESC LIMIT 300');res.json(r);});

app.get('/api/resumen',auth,adminOnly,async(req,res)=>{const [[a]]=await pool.query("SELECT COUNT(*) total FROM usuarios WHERE rol='encuestador'");const [[m]]=await pool.query('SELECT COUNT(*) total FROM manzanas');const [[as]]=await pool.query('SELECT COUNT(*) total FROM asignaciones');const [[v]]=await pool.query("SELECT COUNT(*) total FROM asignaciones WHERE estado='visitada'");res.json({encuestadores:a.total,manzanas:m.total,asignaciones:as.total,visitadas:v.total});});


async function initDb(){
  const ddl=[
`CREATE TABLE IF NOT EXISTS usuarios (id INT AUTO_INCREMENT PRIMARY KEY, numero INT NULL UNIQUE, nombre VARCHAR(120) NOT NULL, usuario VARCHAR(80) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, rol ENUM('admin','encuestador') NOT NULL DEFAULT 'encuestador', activo TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS manzanas (id INT AUTO_INCREMENT PRIMARY KEY, distrito VARCHAR(80) NOT NULL, zona_censal VARCHAR(30) NOT NULL, manzana VARCHAR(40) NOT NULL, lat DECIMAL(10,7) NOT NULL, lon DECIMAL(10,7) NOT NULL, UNIQUE KEY uq_manzana (distrito,zona_censal,manzana))`,
`CREATE TABLE IF NOT EXISTS asignaciones (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, manzana_id INT NOT NULL, orden_visita INT NOT NULL DEFAULT 0, estado ENUM('pendiente','visitada') NOT NULL DEFAULT 'pendiente', updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, UNIQUE KEY uq_asignacion_manzana (manzana_id), KEY idx_asig_enc (encuestador_id), CONSTRAINT fk_asig_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE, CONSTRAINT fk_asig_manzana FOREIGN KEY (manzana_id) REFERENCES manzanas(id) ON DELETE CASCADE)`,
`CREATE TABLE IF NOT EXISTS geometrias (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, tipo ENUM('ruta','zona','otro') NOT NULL, nombre VARCHAR(120) NOT NULL, geojson JSON NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, KEY idx_geo_enc (encuestador_id), CONSTRAINT fk_geo_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE)`,
`CREATE TABLE IF NOT EXISTS contadores (id INT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NULL, nombre VARCHAR(160) NOT NULL, descripcion VARCHAR(255) NULL, meta INT NOT NULL DEFAULT 0, valor INT NOT NULL DEFAULT 0, criterio_json JSON NULL, activo TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, KEY idx_cont_enc (encuestador_id), CONSTRAINT fk_cont_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE)`,
`CREATE TABLE IF NOT EXISTS ubicaciones (id BIGINT AUTO_INCREMENT PRIMARY KEY, encuestador_id INT NOT NULL, lat DECIMAL(10,7) NOT NULL, lon DECIMAL(10,7) NOT NULL, precision_m DECIMAL(10,2) NULL, fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, KEY idx_ubic_enc_time (encuestador_id,fecha_hora), CONSTRAINT fk_ubic_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE)`,
`CREATE TABLE IF NOT EXISTS historial (id BIGINT AUTO_INCREMENT PRIMARY KEY, usuario_id INT NULL, accion VARCHAR(80) NOT NULL, descripcion TEXT NOT NULL, fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, KEY idx_hist_time (fecha_hora), CONSTRAINT fk_hist_user FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL)`
  ];
  for(const sql of ddl) await pool.query(sql);
  const [mc]=await pool.query('SELECT COUNT(*) n FROM manzanas');
  if(Number(mc[0].n)===0){
    const html=require('fs').readFileSync(path.join(__dirname,'index.html'),'utf8'); const match=html.match(/const DATA=(\{.*?\});/s); if(!match) throw new Error('DATA no encontrada en index.html'); const data=JSON.parse(match[1]);
    const c=await pool.getConnection();
    try{await c.beginTransaction(); for(const m of data.manzanas){await c.execute('INSERT IGNORE INTO manzanas(distrito,zona_censal,manzana,lat,lon) VALUES(?,?,?,?,?)',[m.distrito,m.zona_censal,m.manzana,m.lat,m.lon]);} await c.commit(); console.log(`Cargadas ${data.manzanas.length} manzanas`);}catch(e){await c.rollback();throw e;}finally{c.release();}
  }
  const adminUser=process.env.ADMIN_USER||'admin'; const adminPass=process.env.ADMIN_PASSWORD||'admin123';
  const [ar]=await pool.execute("SELECT id FROM usuarios WHERE usuario=? LIMIT 1",[adminUser]);
  if(!ar.length){const hash=await bcrypt.hash(adminPass,12);await pool.execute("INSERT INTO usuarios(numero,nombre,usuario,password_hash,rol) VALUES(NULL,?,?,?,'admin')",['Administrador',adminUser,hash]);console.log(`Admin inicial: ${adminUser}`);}
}

app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
initDb().then(()=>app.listen(PORT,()=>console.log(`Servidor en http://localhost:${PORT}`))).catch(e=>{console.error('No se pudo inicializar la BD:',e);process.exit(1);});


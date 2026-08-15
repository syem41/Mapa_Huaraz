# Sistema de encuestas georreferenciadas

Proyecto preparado para Railway con:

- `index.html`: interfaz completa (admin + encuestador + mapa + GPS + contadores).
- `server.js`: API Express y servidor web.
- `schema.sql`: esquema MySQL/documentación de tablas.
- `package.json`: dependencias y comando de arranque.
- `.env.example`: variables opcionales/locales.

## Funciones

### Administrador
- Login seguro con usuario y contraseña.
- Crear encuestadores por número.
- Cambiar nombre, usuario, estado y contraseña de cada encuestador.
- Cambiar sus propias credenciales.
- Asignar manzanas por clic y guardar el orden.
- Crear rutas y zonas con Leaflet Draw.
- Ver las rutas/zonas de cada encuestador.
- Ver última ubicación GPS de cada encuestador.
- Crear contadores con meta y descripción/criterio.
- Ver historial de acciones.

### Encuestador
- Entra seleccionando su número y usando su contraseña.
- Solo ve sus manzanas, rutas, zonas y contadores.
- Marca manzanas como visitadas/pendientes.
- Puede activar el GPS del celular y enviar su ubicación al servidor.
- Los contadores tienen botones `+1` y `-1`.

## Railway

1. Crea un proyecto en Railway.
2. Añade un servicio MySQL.
3. Añade este repositorio como servicio Node.js.
4. Railway debe inyectar las variables `MYSQLHOST`, `MYSQLPORT`, `MYSQLUSER`, `MYSQLPASSWORD` y `MYSQLDATABASE` al conectar el servicio Node con MySQL.
5. Define `JWT_SECRET` con una cadena larga aleatoria.
6. Define `ADMIN_USER` y `ADMIN_PASSWORD` para crear el admin inicial la primera vez.
7. El comando de inicio es `npm start`.
8. El servidor crea las tablas automáticamente y carga las 2367 manzanas embebidas en `index.html` si la tabla `manzanas` está vacía.

## Local

```bash
npm install
npm start
```

Luego abre `http://localhost:3000`.

## Nota GPS

La geolocalización del navegador requiere un contexto seguro (HTTPS) en dispositivos móviles. Railway proporciona HTTPS para el dominio público.

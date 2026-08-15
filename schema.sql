CREATE DATABASE IF NOT EXISTS encuestas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE encuestas;

CREATE TABLE IF NOT EXISTS usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  numero INT NULL UNIQUE,
  nombre VARCHAR(120) NOT NULL,
  usuario VARCHAR(80) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  rol ENUM('admin','encuestador') NOT NULL DEFAULT 'encuestador',
  activo TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS manzanas (
  id INT AUTO_INCREMENT PRIMARY KEY,
  distrito VARCHAR(80) NOT NULL,
  zona_censal VARCHAR(30) NOT NULL,
  manzana VARCHAR(40) NOT NULL,
  lat DECIMAL(10,7) NOT NULL,
  lon DECIMAL(10,7) NOT NULL,
  UNIQUE KEY uq_manzana (distrito,zona_censal,manzana)
);

CREATE TABLE IF NOT EXISTS asignaciones (
  id INT AUTO_INCREMENT PRIMARY KEY,
  encuestador_id INT NOT NULL,
  manzana_id INT NOT NULL,
  orden_visita INT NOT NULL DEFAULT 0,
  estado ENUM('pendiente','visitada') NOT NULL DEFAULT 'pendiente',
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_asignacion_manzana (manzana_id),
  KEY idx_asig_enc (encuestador_id),
  CONSTRAINT fk_asig_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE,
  CONSTRAINT fk_asig_manzana FOREIGN KEY (manzana_id) REFERENCES manzanas(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS geometrias (
  id INT AUTO_INCREMENT PRIMARY KEY,
  encuestador_id INT NOT NULL,
  tipo ENUM('ruta','zona','otro') NOT NULL,
  nombre VARCHAR(120) NOT NULL,
  geojson JSON NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_geo_enc (encuestador_id),
  CONSTRAINT fk_geo_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contadores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  encuestador_id INT NULL,
  nombre VARCHAR(160) NOT NULL,
  descripcion VARCHAR(255) NULL,
  meta INT NOT NULL DEFAULT 0,
  valor INT NOT NULL DEFAULT 0,
  criterio_json JSON NULL,
  activo TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_cont_enc (encuestador_id),
  CONSTRAINT fk_cont_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ubicaciones (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  encuestador_id INT NOT NULL,
  lat DECIMAL(10,7) NOT NULL,
  lon DECIMAL(10,7) NOT NULL,
  precision_m DECIMAL(10,2) NULL,
  fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_ubic_enc_time (encuestador_id,fecha_hora),
  CONSTRAINT fk_ubic_enc FOREIGN KEY (encuestador_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS historial (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT NULL,
  accion VARCHAR(80) NOT NULL,
  descripcion TEXT NOT NULL,
  fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_hist_time (fecha_hora),
  CONSTRAINT fk_hist_user FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

-- =============================================================================
--  Seed de la BD de demo - PeruHack26 "Kubernetes Nightmare"
--  Tabla "clientes" con ~10 filas FICTICIAS con temática Blue Lock.
--
--  ⚠️  Todos los datos son INVENTADOS. Emails @example.com (reservado, RFC 2606).
--      No corresponden a personas reales.
-- =============================================================================

CREATE TABLE IF NOT EXISTS clientes (
    id            SERIAL PRIMARY KEY,
    nombre        VARCHAR(80)  NOT NULL,
    email         VARCHAR(120) NOT NULL,
    plan          VARCHAR(20)  NOT NULL,
    saldo_soles   NUMERIC(10,2) NOT NULL,
    tarjeta_mask  VARCHAR(20)  NOT NULL,     -- sólo últimos 4 dígitos (ficticios)
    creado_en     TIMESTAMP    NOT NULL DEFAULT NOW()
);

INSERT INTO clientes (nombre, email, plan, saldo_soles, tarjeta_mask) VALUES
    ('Yoichi Isagi',      'isagi@example.com',    'premium', 1540.50, '**** 0011'),
    ('Meguru Bachira',    'bachira@example.com',  'premium',  980.00, '**** 0022'),
    ('Hyoma Chigiri',     'chigiri@example.com',  'free',      12.30, '**** 0033'),
    ('Rensuke Kunigami',  'kunigami@example.com', 'gold',     430.75, '**** 0044'),
    ('Gin Gagamaru',      'gagamaru@example.com', 'free',       0.00, '**** 0055'),
    ('Seishiro Nagi',     'nagi@example.com',     'premium', 2210.10, '**** 0066'),
    ('Reo Mikage',        'mikage@example.com',   'platinum',9999.99, '**** 0077'),
    ('Rin Itoshi',        'rin@example.com',      'gold',    1750.00, '**** 0088'),
    ('Sae Itoshi',        'sae@example.com',      'platinum',8800.40, '**** 0099'),
    ('Shoei Baro',        'baro@example.com',     'free',      55.55, '**** 0101');

-- Vista de control para la demo (mostrar sin volcar toda la tabla):
--   SELECT count(*) FROM clientes;
--   SELECT id, nombre, email, plan FROM clientes LIMIT 3;

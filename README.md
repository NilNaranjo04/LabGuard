# LabGuard MVP

Aplicación web segura para gestión de equipos, préstamos e incidencias.

## Requisitos
- Ubuntu Server 24.04 LTS
- Docker y Docker Compose plugin

## Arranque rápido
1. Copia `.env.example` a `.env`
2. Cambia `SECRET_KEY` y la contraseña del admin
3. Ejecuta:
   ```bash
   docker compose up -d --build
   ```
4. Abre `http://IP_DEL_SERVIDOR`

## Usuario inicial
- Correo: `admin@labguard.local`
- Contraseña: `ChangeMe!123`

## Backups
```bash
./scripts/backup.sh
```

## Restauración
```bash
./scripts/restore.sh backups/NOMBRE.tar.gz
```

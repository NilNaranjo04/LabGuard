import os

from app import create_app
from models import Equipment, User, db

app = create_app()

with app.app_context():
    db.create_all()

    admin_email = os.getenv("INIT_ADMIN_EMAIL", "admin@labguard.local").lower().strip()
    admin_name = os.getenv("INIT_ADMIN_NAME", "Admin Principal").strip()
    admin_password = os.getenv("INIT_ADMIN_PASSWORD", "ChangeMe!123")

    if not User.query.filter_by(email=admin_email).first():
        admin = User(name=admin_name, email=admin_email, role="admin")
        admin.set_password(admin_password)
        db.session.add(admin)

    if Equipment.query.count() == 0:
        sample = [
            Equipment(name="Portátil Dell", asset_tag="EQ-001", category="laptop", location="Armario A", criticality="medium", status="available", notes="Equipo de pruebas"),
            Equipment(name="Raspberry Pi 4", asset_tag="EQ-002", category="iot", location="Armario B", criticality="high", status="available", notes="Laboratorio IoT"),
            Equipment(name="Router Cisco", asset_tag="EQ-003", category="network", location="Rack 1", criticality="high", status="available", notes="Prácticas de red"),
        ]
        db.session.add_all(sample)

    db.session.commit()

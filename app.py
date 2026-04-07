import os
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from sqlalchemy import inspect

from forms import (
    CATEGORY_CHOICES,
    ChangePasswordForm,
    EditUserForm,
    EquipmentForm,
    IncidentForm,
    IncidentResponseForm,
    LoanForm,
    LoginForm,
    RegistrationForm,
    UserForm,
)
from models import AuditLog, Equipment, Incident, Loan, User, db

login_manager = LoginManager()
login_manager.login_view = "login"
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////app/instance/labguard.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()
        ensure_schema()

    register_routes(app)
    return app


def ensure_schema():
    inspector = inspect(db.engine)

    user_columns = {col["name"] for col in inspector.get_columns("user")}
    loan_columns = {col["name"] for col in inspector.get_columns("loan")}

    with db.engine.begin() as conn:
        if "must_change_password" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0")
        if "approval_status" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN approval_status VARCHAR(20) NOT NULL DEFAULT 'approved'")
        if "requested_days" not in loan_columns:
            conn.exec_driver_sql("ALTER TABLE loan ADD COLUMN requested_days INTEGER NOT NULL DEFAULT 1")
        if "due_at" not in loan_columns:
            conn.exec_driver_sql("ALTER TABLE loan ADD COLUMN due_at DATETIME")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in allowed_roles:
                flash("No tienes permisos para acceder a esta sección.", "danger")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def audit(action: str, details: str) -> None:
    actor = current_user.email if current_user.is_authenticated else "anonymous"
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    log = AuditLog(actor_email=actor, action=action, details=details, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()


def generate_asset_tag() -> str:
    last_item = Equipment.query.order_by(Equipment.id.desc()).first()
    next_number = 1 if not last_item else last_item.id + 1
    return f"EQ-{next_number:03d}"


def label_from_choice(value: str, choices) -> str:
    return dict(choices).get(value, value)


def register_routes(app):
    @app.before_request
    def force_password_change():
        allowed_endpoints = {"change_password", "logout", "static"}
        if current_user.is_authenticated and getattr(current_user, "must_change_password", False):
            if request.endpoint not in allowed_endpoints:
                flash("Debes cambiar la contraseña antes de continuar.", "warning")
                return redirect(url_for("change_password"))

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = RegistrationForm()
        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            existing = User.query.filter_by(email=email).first()
            if existing:
                flash("Ya existe una cuenta con ese correo.", "danger")
                return render_template("register.html", form=form)

            user = User(
                name=form.name.data.strip(),
                email=email,
                role="user",
                active=False,
                approval_status="pending",
                must_change_password=False,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            audit("public_registration", f"Solicitud de cuenta creada para {email}")
            flash("Tu solicitud de cuenta se ha enviado. Un administrador debe validarla.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            user = User.query.filter_by(email=email).first()

            if user and user.approval_status == "pending":
                flash("Tu cuenta todavía está pendiente de validación por parte del administrador.", "warning")
                audit("login_pending_user", f"Intento de acceso de cuenta pendiente: {email}")
                return render_template("login.html", form=form)

            if user and user.approval_status == "rejected":
                flash("Tu solicitud de cuenta fue rechazada por el administrador.", "danger")
                audit("login_rejected_user", f"Intento de acceso de cuenta rechazada: {email}")
                return render_template("login.html", form=form)

            if user and user.active and user.check_password(form.password.data):
                login_user(user)
                audit("login_success", f"Inicio de sesión correcto para {user.email}")
                flash("Sesión iniciada.", "success")
                if user.must_change_password:
                    return redirect(url_for("change_password"))
                return redirect(url_for("dashboard"))

            audit("login_failure", f"Intento fallido para {email}")
            flash("Credenciales no válidas.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Sesión cerrada.", "info")
        return redirect(url_for("login"))

    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html")

    @app.route("/account/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        form = ChangePasswordForm()
        if form.validate_on_submit():
            current_user.set_password(form.password.data.strip())
            current_user.must_change_password = False
            db.session.commit()
            audit("password_changed", f"Contraseña cambiada por {current_user.email}")
            flash("Contraseña actualizada correctamente.", "success")
            return redirect(url_for("dashboard"))
        return render_template("change_password.html", form=form)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        stats = {
            "users": User.query.count(),
            "equipment": Equipment.query.count(),
            "loans_open": Loan.query.filter(Loan.status.in_(["requested", "approved", "delivered"])).count(),
            "incidents_open": Incident.query.filter(Incident.status.in_(["open", "answered"])).count(),
        }
        return render_template("dashboard.html", stats=stats)

    @app.route("/users")
    @login_required
    @role_required("admin")
    def users_list():
        users = User.query.filter(User.approval_status != "pending").order_by(User.created_at.desc()).all()
        pending_users = User.query.filter_by(approval_status="pending").order_by(User.created_at.desc()).all()
        return render_template("users_list.html", users=users, pending_users=pending_users)

    @app.route("/users/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def create_user():
        form = UserForm()
        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            if User.query.filter_by(email=email).first():
                flash("Ya existe un usuario con ese correo.", "danger")
                return render_template(
                    "user_form.html",
                    form=form,
                    form_title="Crear usuario",
                    submit_label="Crear usuario",
                    password_optional=False,
                )

            user = User(
                name=form.name.data.strip(),
                email=email,
                role=form.role.data,
                active=True,
                approval_status="approved",
                must_change_password=True,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            audit("user_created", f"Usuario creado: {email} ({user.role})")
            flash("Usuario creado. Tendrá que cambiar la contraseña al entrar por primera vez.", "success")
            return redirect(url_for("users_list"))

        return render_template(
            "user_form.html",
            form=form,
            form_title="Crear usuario",
            submit_label="Crear usuario",
            password_optional=False,
        )

    @app.route("/users/<int:user_id>/approve", methods=["POST"])
    @login_required
    @role_required("admin")
    def approve_user(user_id):
        user = User.query.get_or_404(user_id)
        user.active = True
        user.approval_status = "approved"
        user.must_change_password = True
        db.session.commit()
        audit("user_approved", f"Cuenta aprobada: {user.email}")
        flash("Cuenta aprobada correctamente.", "success")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/reject", methods=["POST"])
    @login_required
    @role_required("admin")
    def reject_user(user_id):
        user = User.query.get_or_404(user_id)
        user.active = False
        user.approval_status = "rejected"
        db.session.commit()
        audit("user_rejected", f"Cuenta rechazada: {user.email}")
        flash("Solicitud rechazada.", "info")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def edit_user(user_id):
        user = User.query.get_or_404(user_id)
        form = EditUserForm(obj=user)

        if request.method == "GET":
            form.name.data = user.name
            form.email.data = user.email
            form.role.data = user.role

        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            existing = User.query.filter(User.email == email, User.id != user.id).first()
            if existing:
                flash("Ya existe otro usuario con ese correo.", "danger")
                return render_template(
                    "user_form.html",
                    form=form,
                    form_title="Editar usuario",
                    submit_label="Guardar cambios",
                    password_optional=True,
                )

            user.name = form.name.data.strip()
            user.email = email
            user.role = form.role.data

            if form.password.data and form.password.data.strip():
                user.set_password(form.password.data.strip())

            db.session.commit()
            audit("user_updated", f"Usuario editado: {user.email} (ID {user.id})")
            flash("Usuario actualizado.", "success")
            return redirect(url_for("users_list"))

        return render_template(
            "user_form.html",
            form=form,
            form_title="Editar usuario",
            submit_label="Guardar cambios",
            password_optional=True,
        )

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            flash("No puedes eliminar el usuario con el que has iniciado sesión.", "danger")
            return redirect(url_for("users_list"))

        email = user.email
        db.session.delete(user)
        db.session.commit()
        audit("user_deleted", f"Usuario eliminado: {email} (ID {user_id})")
        flash("Usuario eliminado.", "success")
        return redirect(url_for("users_list"))

    @app.route("/equipment")
    @login_required
    def equipment_list():
        category_filter = request.args.get("category", "")
        status_filter = request.args.get("status", "")

        query = Equipment.query
        if category_filter:
            query = query.filter_by(category=category_filter)
        if status_filter:
            query = query.filter_by(status=status_filter)

        equipment = query.order_by(Equipment.name.asc()).all()
        categories = CATEGORY_CHOICES
        statuses = [
            ("available", "Disponible"),
            ("loaned", "Prestado"),
            ("maintenance", "Mantenimiento"),
            ("retired", "Retirado"),
        ]
        locations = [
            ("armario-a", "Armario A"),
            ("armario-b", "Armario B"),
            ("rack-1", "Rack 1"),
            ("rack-2", "Rack 2"),
            ("laboratorio-1", "Laboratorio 1"),
            ("laboratorio-2", "Laboratorio 2"),
            ("almacen", "Almacén"),
        ]
        criticalities = [
            ("low", "Baja"),
            ("medium", "Media"),
            ("high", "Alta"),
        ]

        return render_template(
            "equipment_list.html",
            equipment=equipment,
            categories=categories,
            statuses=statuses,
            category_filter=category_filter,
            status_filter=status_filter,
            label_from_choice=label_from_choice,
            locations=locations,
            criticalities=criticalities,
        )

    @app.route("/equipment/loaned")
    @login_required
    @role_required("admin")
    def loaned_equipment():
        active_loans = Loan.query.filter_by(status="delivered").order_by(Loan.due_at.asc()).all()
        return render_template("loaned_equipment.html", active_loans=active_loans, now=datetime.utcnow())

    @app.route("/equipment/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "technician")
    def equipment_new():
        form = EquipmentForm()
        suggested_asset_tag = generate_asset_tag()

        if form.validate_on_submit():
            asset_tag = generate_asset_tag()
            if Equipment.query.filter_by(asset_tag=asset_tag).first():
                flash("No se pudo generar un código de inventario único. Vuelve a intentarlo.", "danger")
                return render_template(
                    "equipment_form.html",
                    form=form,
                    suggested_asset_tag=suggested_asset_tag,
                    label_from_choice=label_from_choice,
                    form_title="Nuevo equipo",
                    submit_label="Guardar equipo",
                    read_only_asset_tag=True,
                )

            equipment = Equipment(
                name=form.name.data.strip(),
                asset_tag=asset_tag,
                category=form.category.data,
                location=form.location.data,
                status=form.status.data,
                criticality=form.criticality.data,
                notes=form.notes.data.strip() if form.notes.data else "",
            )
            db.session.add(equipment)
            db.session.commit()
            audit("equipment_created", f"Equipo creado: {equipment.asset_tag}")
            flash(f"Equipo guardado con código {equipment.asset_tag}.", "success")
            return redirect(url_for("equipment_list"))

        return render_template(
            "equipment_form.html",
            form=form,
            suggested_asset_tag=suggested_asset_tag,
            label_from_choice=label_from_choice,
            form_title="Nuevo equipo",
            submit_label="Guardar equipo",
            read_only_asset_tag=True,
        )

    @app.route("/equipment/<int:equipment_id>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "technician")
    def equipment_edit(equipment_id):
        equipment = Equipment.query.get_or_404(equipment_id)
        form = EquipmentForm(obj=equipment)

        if request.method == "GET":
            form.name.data = equipment.name
            form.category.data = equipment.category
            form.location.data = equipment.location
            form.status.data = equipment.status
            form.criticality.data = equipment.criticality
            form.notes.data = equipment.notes

        if form.validate_on_submit():
            equipment.name = form.name.data.strip()
            equipment.category = form.category.data
            equipment.location = form.location.data
            equipment.status = form.status.data
            equipment.criticality = form.criticality.data
            equipment.notes = form.notes.data.strip() if form.notes.data else ""

            db.session.commit()
            audit("equipment_updated", f"Equipo editado: {equipment.asset_tag}")
            flash("Equipo actualizado correctamente.", "success")
            return redirect(url_for("equipment_list"))

        return render_template(
            "equipment_form.html",
            form=form,
            suggested_asset_tag=equipment.asset_tag,
            label_from_choice=label_from_choice,
            form_title="Editar equipo",
            submit_label="Guardar cambios",
            read_only_asset_tag=True,
        )

    @app.route("/equipment/<int:equipment_id>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    def equipment_delete(equipment_id):
        equipment = Equipment.query.get_or_404(equipment_id)

        if equipment.status == "loaned":
            flash("No se puede eliminar un equipo que está actualmente prestado.", "danger")
            return redirect(url_for("equipment_list"))

        asset_tag = equipment.asset_tag
        db.session.delete(equipment)
        db.session.commit()
        audit("equipment_deleted", f"Equipo eliminado: {asset_tag}")
        flash("Equipo eliminado correctamente.", "success")
        return redirect(url_for("equipment_list"))

    @app.route("/loans")
    @login_required
    def loans_list():
        if current_user.role == "technician":
            flash("No puedes usar la función de préstamos con el perfil de técnico.", "warning")
            return redirect(url_for("dashboard"))

        if current_user.role == "admin":
            loans = Loan.query.order_by(Loan.created_at.desc()).all()
        else:
            loans = Loan.query.filter_by(requester_id=current_user.id).order_by(Loan.created_at.desc()).all()

        return render_template("loan_list.html", loans=loans, now=datetime.utcnow())

    @app.route("/loans/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "user")
    def loan_new():
        form = LoanForm()
        available_equipment = Equipment.query.filter_by(status="available").order_by(Equipment.name.asc()).all()
        form.equipment_id.choices = [(e.id, f"{e.name} ({e.asset_tag})") for e in available_equipment]

        if not form.equipment_id.choices:
            flash("No hay equipos disponibles en este momento.", "warning")
            return redirect(url_for("loans_list"))

        if form.validate_on_submit():
            equipment = Equipment.query.get_or_404(form.equipment_id.data)
            if equipment.status != "available":
                flash("Ese equipo ya no está disponible.", "danger")
                return redirect(url_for("loan_new"))

            requested_days = int(form.requested_days.data)
            due_at = datetime.utcnow() + timedelta(days=requested_days)

            loan = Loan(
                requester_id=current_user.id,
                equipment_id=equipment.id,
                purpose=form.purpose.data.strip(),
                requested_days=requested_days,
                due_at=due_at,
                status="requested",
            )
            db.session.add(loan)
            db.session.commit()
            audit("loan_requested", f"Préstamo solicitado #{loan.id} por {current_user.email} durante {requested_days} días")
            flash("Solicitud enviada.", "success")
            return redirect(url_for("loans_list"))

        return render_template("loan_form.html", form=form)

    @app.route("/loans/<int:loan_id>/<string:action>", methods=["POST"])
    @login_required
    @role_required("admin")
    def loan_action(loan_id, action):
        loan = Loan.query.get_or_404(loan_id)
        equipment = loan.equipment

        admin_transitions = {
            "approve": ("requested", "approved"),
            "reject": ("requested", "rejected"),
            "deliver": ("approved", "delivered"),
            "return": ("delivered", "returned"),
            "close": ("returned", "closed"),
        }

        if action not in admin_transitions:
            flash("Acción no válida.", "danger")
            return redirect(url_for("loans_list"))

        expected, new_state = admin_transitions[action]
        if loan.status != expected:
            flash(f"El préstamo debe estar en estado {expected}.", "danger")
            return redirect(url_for("loans_list"))

        loan.status = new_state
        if new_state == "delivered":
            equipment.status = "loaned"
        elif new_state in ["returned", "rejected", "closed"]:
            equipment.status = "available"
        if new_state == "rejected":
            loan.rejection_reason = "Rechazado por administración"

        db.session.commit()
        audit("loan_status_changed", f"Préstamo #{loan.id}: {expected} -> {new_state}")
        flash("Estado actualizado.", "success")
        return redirect(url_for("loans_list"))

    @app.route("/incidents")
    @login_required
    def incidents_list():
        if current_user.role in ["admin", "technician"]:
            incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        else:
            incidents = Incident.query.filter_by(reporter_id=current_user.id).order_by(Incident.created_at.desc()).all()
        response_form = IncidentResponseForm()
        return render_template("incident_list.html", incidents=incidents, response_form=response_form)

    @app.route("/incidents/new", methods=["GET", "POST"])
    @login_required
    def incident_new():
        form = IncidentForm()
        all_equipment = Equipment.query.order_by(Equipment.name.asc()).all()
        form.equipment_id.choices = [(e.id, f"{e.name} ({e.asset_tag})") for e in all_equipment]

        if not form.equipment_id.choices:
            flash("Primero debes dar de alta al menos un equipo.", "warning")
            return redirect(url_for("incidents_list"))

        if form.validate_on_submit():
            incident = Incident(
                reporter_id=current_user.id,
                equipment_id=form.equipment_id.data,
                title=form.title.data.strip(),
                severity=form.severity.data,
                description=form.description.data.strip(),
                status="open",
            )
            db.session.add(incident)
            db.session.commit()
            audit("incident_created", f"Incidencia #{incident.id}: {incident.title}")
            flash("Incidencia registrada.", "success")
            return redirect(url_for("incidents_list"))

        return render_template("incident_form.html", form=form)

    @app.route("/incidents/<int:incident_id>/respond", methods=["POST"])
    @login_required
    @role_required("admin", "technician")
    def incident_respond(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        form = IncidentResponseForm()

        if form.validate_on_submit():
            incident.technical_response = form.response.data.strip()
            incident.responded_by_email = current_user.email
            incident.responded_at = datetime.utcnow()
            incident.status = "answered"
            db.session.commit()
            audit("incident_answered", f"Incidencia #{incident.id} respondida por {current_user.email}")
            flash("Respuesta técnica guardada.", "success")
        else:
            flash("Debes escribir una respuesta técnica válida.", "danger")

        return redirect(url_for("incidents_list"))

    @app.route("/incidents/<int:incident_id>/close", methods=["POST"])
    @login_required
    @role_required("admin", "technician")
    def incident_close(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        incident.status = "closed"
        db.session.commit()
        audit("incident_closed", f"Incidencia #{incident.id} cerrada")
        flash("Incidencia cerrada.", "success")
        return redirect(url_for("incidents_list"))

    @app.route("/audit")
    @login_required
    @role_required("admin")
    def audit_list():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
        return render_template("audit_list.html", logs=logs)

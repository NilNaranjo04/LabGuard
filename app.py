import base64
import io
import os
import random
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
import requests
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from sqlalchemy import inspect

from forms import (
    CATEGORY_CHOICES,
    ChangePasswordForm,
    EditUserForm,
    EquipmentForm,
    ForgotPasswordRequestForm,
    IncidentForm,
    IncidentResponseForm,
    LoanForm,
    LoginForm,
    RegistrationForm,
    ResetPasswordWithQuestionForm,
    SecurityQuestionForm,
    SECURITY_QUESTION_CHOICES,
    TwoFactorLoginForm,
    TwoFactorSetupForm,
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
    app.jinja_env.globals.update(format_datetime=format_datetime)
    return app


def ensure_schema():
    inspector = inspect(db.engine)

    user_columns = {col["name"] for col in inspector.get_columns("user")}
    loan_columns = {col["name"] for col in inspector.get_columns("loan")}
    incident_columns = {col["name"] for col in inspector.get_columns("incident")}

    with db.engine.begin() as conn:
        if "must_change_password" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0")
        if "approval_status" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN approval_status VARCHAR(20) NOT NULL DEFAULT 'approved'")
        if "security_question" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN security_question VARCHAR(255)")
        if "security_answer_hash" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN security_answer_hash VARCHAR(255)")
        if "captcha_failed_attempts" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN captcha_failed_attempts INTEGER NOT NULL DEFAULT 0")
        if "is_banned" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN is_banned BOOLEAN NOT NULL DEFAULT 0")
        if "pending_admin_review" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN pending_admin_review BOOLEAN NOT NULL DEFAULT 0")
        if "two_factor_enabled" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT 0")
        if "two_factor_secret" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE user ADD COLUMN two_factor_secret VARCHAR(64)")
        if "requested_days" not in loan_columns:
            conn.exec_driver_sql("ALTER TABLE loan ADD COLUMN requested_days INTEGER NOT NULL DEFAULT 1")
        if "due_at" not in loan_columns:
            conn.exec_driver_sql("ALTER TABLE loan ADD COLUMN due_at DATETIME")
        if "pending_technician_review" not in incident_columns:
            conn.exec_driver_sql("ALTER TABLE incident ADD COLUMN pending_technician_review BOOLEAN NOT NULL DEFAULT 0")


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


def security_question_label(value: str) -> str:
    return dict(SECURITY_QUESTION_CHOICES).get(value, value or "No configurada")


def format_datetime(value) -> str:
    if not value:
        return "-"
    return value.strftime("%d-%m-%Y %H:%M")


def set_captcha_challenge() -> None:
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    session["captcha_a"] = a
    session["captcha_b"] = b
    session["captcha_expected"] = a + b


def current_captcha_question() -> str:
    if "captcha_expected" not in session:
        set_captcha_challenge()
    return f"{session.get('captcha_a', 0)} + {session.get('captcha_b', 0)}"


def build_qr_data_url(data: str) -> str:
    qr_img = qrcode.make(data)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def send_telegram_message(title: str, lines: list[str]) -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    if not token or not chat_id:
        return

    text = f"{title}\n\n" + "\n".join(lines)

    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text},
            timeout=10,
        )
    except Exception:
        pass


def notify_new_registration(user: User) -> None:
    send_telegram_message(
        "👤 Nueva solicitud de cuenta en LabGuard",
        [
            f"Nombre: {user.name}",
            f"Correo: {user.email}",
            f"Rol solicitado: {user.role}",
            f"Fecha: {format_datetime(user.created_at)}",
            "Acción: revisar en Usuarios",
        ],
    )


def notify_new_incident(incident: Incident) -> None:
    equipment_name = incident.equipment.name if incident.equipment else "Sin equipo"
    equipment_tag = incident.equipment.asset_tag if incident.equipment else "-"
    reporter_name = incident.reporter.name if incident.reporter else "Desconocido"

    send_telegram_message(
        "🚨 Nueva incidencia en LabGuard",
        [
            f"ID: {incident.id}",
            f"Título: {incident.title}",
            f"Severidad: {incident.severity}",
            f"Usuario: {reporter_name}",
            f"Equipo: {equipment_name} ({equipment_tag})",
            f"Fecha: {format_datetime(incident.created_at)}",
            f"Descripción: {incident.description}",
        ],
    )


def notify_new_loan(loan: Loan) -> None:
    send_telegram_message(
        "📦 Nueva solicitud de préstamo",
        [
            f"ID préstamo: {loan.id}",
            f"Usuario: {loan.requester.name}",
            f"Correo: {loan.requester.email}",
            f"Equipo: {loan.equipment.name} ({loan.equipment.asset_tag})",
            f"Días solicitados: {loan.requested_days}",
            f"Fecha límite: {format_datetime(loan.due_at)}",
            f"Finalidad: {loan.purpose}",
        ],
    )


def notify_loan_status_change(loan: Loan, new_state: str) -> None:
    send_telegram_message(
        "🔄 Cambio en préstamo",
        [
            f"ID préstamo: {loan.id}",
            f"Usuario: {loan.requester.name}",
            f"Equipo: {loan.equipment.name} ({loan.equipment.asset_tag})",
            f"Nuevo estado: {new_state}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def notify_user_banned(user: User) -> None:
    send_telegram_message(
        "⛔ Usuario baneado por captcha",
        [
            f"Nombre: {user.name}",
            f"Correo: {user.email}",
            f"Rol: {user.role}",
            f"Intentos fallidos: {user.captcha_failed_attempts}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def notify_user_unbanned(user: User) -> None:
    send_telegram_message(
        "✅ Usuario desbaneado",
        [
            f"Nombre: {user.name}",
            f"Correo: {user.email}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def notify_user_approved(user: User) -> None:
    send_telegram_message(
        "✅ Cuenta aprobada",
        [
            f"Nombre: {user.name}",
            f"Correo: {user.email}",
            f"Rol: {user.role}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def notify_user_rejected(user: User) -> None:
    send_telegram_message(
        "❌ Cuenta rechazada",
        [
            f"Nombre: {user.name}",
            f"Correo: {user.email}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def notify_incident_answered(incident: Incident) -> None:
    send_telegram_message(
        "🛠️ Incidencia respondida",
        [
            f"ID: {incident.id}",
            f"Título: {incident.title}",
            f"Respondida por: {incident.responded_by_email or '-'}",
            f"Fecha: {format_datetime(incident.responded_at)}",
        ],
    )


def notify_incident_closed(incident: Incident) -> None:
    send_telegram_message(
        "📁 Incidencia cerrada",
        [
            f"ID: {incident.id}",
            f"Título: {incident.title}",
            f"Fecha: {format_datetime(datetime.utcnow())}",
        ],
    )


def register_routes(app):
    @app.context_processor
    def inject_nav_badges():
        technician_incidents_badge = 0
        admin_banned_badge = 0

        if current_user.is_authenticated:
            if current_user.role == "technician":
                technician_incidents_badge = Incident.query.filter_by(
                    pending_technician_review=True
                ).count()

            if current_user.role == "admin":
                pending_banned = User.query.filter_by(
                    pending_admin_review=True
                ).count()

                pending_accounts = User.query.filter_by(
                    approval_status="pending"
                ).count()

                admin_banned_badge = pending_banned + pending_accounts

        return {
            "technician_incidents_badge": technician_incidents_badge,
            "admin_banned_badge": admin_banned_badge,
        }

    @app.before_request
    def force_password_change():
        allowed_endpoints = {
            "change_password",
            "logout",
            "static",
            "set_security_question",
            "account",
            "two_factor_setup",
            "two_factor_disable",
        }
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
                captcha_failed_attempts=0,
                is_banned=False,
                pending_admin_review=False,
                two_factor_enabled=False,
                two_factor_secret=None,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            notify_new_registration(user)
            audit("public_registration", f"Solicitud de cuenta creada para {email}")
            flash("Tu solicitud de cuenta se ha enviado. Un administrador debe validarla.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", form=form)

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = ForgotPasswordRequestForm()
        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            user = User.query.filter_by(email=email, active=True, approval_status="approved").first()

            if not user:
                flash("No existe una cuenta activa con ese correo.", "danger")
                return render_template("forgot_password.html", form=form)

            if user.is_banned:
                flash("Esta cuenta está bloqueada. Debe intervenir un administrador.", "danger")
                return render_template("forgot_password.html", form=form)

            if not user.security_question or not user.security_answer_hash:
                flash("Esta cuenta no tiene configurada una pregunta de seguridad.", "warning")
                return render_template("forgot_password.html", form=form)

            session["password_reset_user_id"] = user.id
            return redirect(url_for("reset_password_with_question"))

        return render_template("forgot_password.html", form=form)

    @app.route("/reset-password-with-question", methods=["GET", "POST"])
    def reset_password_with_question():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        user_id = session.get("password_reset_user_id")
        if not user_id:
            flash("Primero debes indicar el correo de la cuenta.", "warning")
            return redirect(url_for("forgot_password"))

        user = User.query.get(user_id)
        if not user:
            session.pop("password_reset_user_id", None)
            flash("No se ha podido continuar con la recuperación.", "danger")
            return redirect(url_for("forgot_password"))

        form = ResetPasswordWithQuestionForm()
        question_label = security_question_label(user.security_question)

        if form.validate_on_submit():
            if not user.check_security_answer(form.security_answer.data):
                audit("password_recovery_failed", f"Fallo en recuperación de contraseña para {user.email}")
                flash("La respuesta de seguridad no es correcta.", "danger")
                return render_template("reset_password_with_question.html", form=form, question_label=question_label)

            user.set_password(form.password.data.strip())
            user.must_change_password = False
            db.session.commit()
            session.pop("password_reset_user_id", None)
            audit("password_recovered", f"Contraseña restablecida para {user.email}")
            flash("Contraseña restablecida correctamente. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password_with_question.html", form=form, question_label=question_label)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = LoginForm()
        captcha_question = current_captcha_question()

        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            user = User.query.filter_by(email=email).first()

            if user and user.is_banned:
                set_captcha_challenge()
                flash("Esta cuenta está bloqueada por intentos fallidos de captcha. Solo un administrador puede desbanearla.", "danger")
                audit("login_blocked_banned_user", f"Intento de acceso de cuenta baneada: {email}")
                return render_template("login.html", form=form, captcha_question=current_captcha_question())

            try:
                captcha_answer = int(form.captcha_answer.data.strip())
            except ValueError:
                captcha_answer = None

            expected_captcha = session.get("captcha_expected")

            if captcha_answer != expected_captcha:
                if user and user.role != "admin":
                    user.captcha_failed_attempts = (user.captcha_failed_attempts or 0) + 1
                    if user.captcha_failed_attempts >= 5:
                        user.is_banned = True
                        user.active = False
                        user.pending_admin_review = True
                        db.session.commit()
                        notify_user_banned(user)
                        set_captcha_challenge()
                        audit("user_banned_by_captcha", f"Cuenta baneada por 5 captchas fallidos: {email}")
                        flash("Has alcanzado 5 captchas fallidos. Tu cuenta ha quedado bloqueada hasta que un administrador la desbanee.", "danger")
                        return render_template("login.html", form=form, captcha_question=current_captcha_question())

                    db.session.commit()
                    audit("captcha_failure", f"Captcha fallido para {email}. Intentos acumulados: {user.captcha_failed_attempts}")
                    flash(f"Captcha incorrecto. Llevas {user.captcha_failed_attempts} de 5 intentos.", "danger")
                else:
                    audit("captcha_failure_admin_or_unknown", f"Captcha fallido para {email}")
                    flash("Captcha incorrecto.", "danger")

                set_captcha_challenge()
                return render_template("login.html", form=form, captcha_question=current_captcha_question())

            if user and user.approval_status == "pending":
                set_captcha_challenge()
                flash("Tu cuenta todavía está pendiente de validación por parte del administrador.", "warning")
                audit("login_pending_user", f"Intento de acceso de cuenta pendiente: {email}")
                return render_template("login.html", form=form, captcha_question=current_captcha_question())

            if user and user.approval_status == "rejected":
                set_captcha_challenge()
                flash("Tu solicitud de cuenta fue rechazada por el administrador.", "danger")
                audit("login_rejected_user", f"Intento de acceso de cuenta rechazada: {email}")
                return render_template("login.html", form=form, captcha_question=current_captcha_question())

            if user and user.active and user.check_password(form.password.data):
                if user.role != "admin":
                    user.captcha_failed_attempts = 0
                    db.session.commit()

                if user.two_factor_enabled and user.two_factor_secret:
                    session["pending_2fa_user_id"] = user.id
                    set_captcha_challenge()
                    audit("login_password_step_ok", f"Primer factor correcto para {user.email}")
                    return redirect(url_for("two_factor_login"))

                login_user(user)
                audit("login_success", f"Inicio de sesión correcto para {user.email}")
                set_captcha_challenge()
                flash("Sesión iniciada.", "success")
                if user.must_change_password:
                    return redirect(url_for("change_password"))
                return redirect(url_for("dashboard"))

            audit("login_failure", f"Intento fallido para {email}")
            set_captcha_challenge()
            flash("Credenciales no válidas.", "danger")

        return render_template("login.html", form=form, captcha_question=captcha_question)

    @app.route("/login/2fa", methods=["GET", "POST"])
    def two_factor_login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        user_id = session.get("pending_2fa_user_id")
        if not user_id:
            flash("Primero debes iniciar sesión con correo y contraseña.", "warning")
            return redirect(url_for("login"))

        user = User.query.get(user_id)
        if not user or not user.two_factor_enabled or not user.two_factor_secret:
            session.pop("pending_2fa_user_id", None)
            flash("No se ha podido continuar con la verificación 2FA.", "danger")
            return redirect(url_for("login"))

        form = TwoFactorLoginForm()
        if form.validate_on_submit():
            totp = pyotp.TOTP(user.two_factor_secret)
            if totp.verify(form.token.data.strip(), valid_window=1):
                session.pop("pending_2fa_user_id", None)
                login_user(user)
                audit("login_success_2fa", f"Inicio de sesión con 2FA correcto para {user.email}")
                flash("Sesión iniciada correctamente.", "success")
                if user.must_change_password:
                    return redirect(url_for("change_password"))
                return redirect(url_for("dashboard"))

            audit("login_failure_2fa", f"Código 2FA incorrecto para {user.email}")
            flash("Código de autenticación incorrecto.", "danger")

        return render_template("two_factor_login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        session.pop("pending_2fa_user_id", None)
        flash("Sesión cerrada.", "info")
        return redirect(url_for("login"))

    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html", security_question_label=security_question_label)

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

    @app.route("/account/security-question", methods=["GET", "POST"])
    @login_required
    def set_security_question():
        form = SecurityQuestionForm()

        if request.method == "GET" and current_user.security_question:
            form.security_question.data = current_user.security_question

        if form.validate_on_submit():
            current_user.security_question = form.security_question.data
            current_user.set_security_answer(form.security_answer.data)
            db.session.commit()
            audit("security_question_updated", f"Pregunta de seguridad actualizada por {current_user.email}")
            flash("Pregunta de seguridad guardada correctamente.", "success")
            return redirect(url_for("account"))

        return render_template("set_security_question.html", form=form)

    @app.route("/account/2fa", methods=["GET", "POST"])
    @login_required
    def two_factor_setup():
        form = TwoFactorSetupForm()

        if not current_user.two_factor_secret:
            current_user.two_factor_secret = pyotp.random_base32()
            db.session.commit()

        totp = pyotp.TOTP(current_user.two_factor_secret)
        provisioning_uri = totp.provisioning_uri(
            name=current_user.email,
            issuer_name="LabGuard",
        )
        qr_data_url = build_qr_data_url(provisioning_uri)

        if form.validate_on_submit():
            if totp.verify(form.token.data.strip(), valid_window=1):
                current_user.two_factor_enabled = True
                db.session.commit()
                audit("2fa_enabled", f"2FA activado por {current_user.email}")
                flash("2FA activado correctamente.", "success")
                return redirect(url_for("account"))

            flash("El código introducido no es válido.", "danger")

        return render_template(
            "two_factor_setup.html",
            form=form,
            qr_data_url=qr_data_url,
            secret=current_user.two_factor_secret,
        )

    @app.route("/account/2fa/disable", methods=["POST"])
    @login_required
    def two_factor_disable():
        current_user.two_factor_enabled = False
        current_user.two_factor_secret = None
        db.session.commit()
        audit("2fa_disabled", f"2FA desactivado por {current_user.email}")
        flash("2FA desactivado correctamente.", "info")
        return redirect(url_for("account"))

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
        pending_review_users = User.query.filter_by(pending_admin_review=True).all()
        if pending_review_users:
            for pending_user in pending_review_users:
                pending_user.pending_admin_review = False
            db.session.commit()

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
                captcha_failed_attempts=0,
                is_banned=False,
                pending_admin_review=False,
                two_factor_enabled=False,
                two_factor_secret=None,
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
        if user.role != "admin":
            user.is_banned = False
            user.captcha_failed_attempts = 0
            user.pending_admin_review = False
        db.session.commit()
        notify_user_approved(user)
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
        notify_user_rejected(user)
        audit("user_rejected", f"Cuenta rechazada: {user.email}")
        flash("Solicitud rechazada.", "info")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/unban", methods=["POST"])
    @login_required
    @role_required("admin")
    def unban_user(user_id):
        user = User.query.get_or_404(user_id)
        user.is_banned = False
        user.captcha_failed_attempts = 0
        user.pending_admin_review = False
        if user.approval_status == "approved":
            user.active = True
        db.session.commit()
        notify_user_unbanned(user)
        audit("user_unbanned", f"Cuenta desbaneada por admin: {user.email}")
        flash("Usuario desbaneado correctamente.", "success")
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
            if requested_days < 1 or requested_days > 30:
                flash("Número de días inválido. El máximo permitido es 30.", "danger")
                return redirect(url_for("loan_new"))

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
            notify_new_loan(loan)
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
        notify_loan_status_change(loan, new_state)
        audit("loan_status_changed", f"Préstamo #{loan.id}: {expected} -> {new_state}")
        flash("Estado actualizado.", "success")
        return redirect(url_for("loans_list"))

    @app.route("/incidents")
    @login_required
    def incidents_list():
        if current_user.role == "technician":
            unread_incidents = Incident.query.filter(
                Incident.pending_technician_review == True,
                Incident.status == "open"
            ).all()
            if unread_incidents:
                for incident in unread_incidents:
                    incident.pending_technician_review = False
                db.session.commit()

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
                pending_technician_review=True,
            )
            db.session.add(incident)
            db.session.commit()
            notify_new_incident(incident)
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
            notify_incident_answered(incident)
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
        notify_incident_closed(incident)
        audit("incident_closed", f"Incidencia #{incident.id} cerrada")
        flash("Incidencia cerrada.", "success")
        return redirect(url_for("incidents_list"))

    @app.route("/audit")
    @login_required
    @role_required("admin")
    def audit_list():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
        return render_template("audit_list.html", logs=logs)

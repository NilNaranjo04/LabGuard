from flask_wtf import FlaskForm
from wtforms import IntegerField, PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import Email, InputRequired, Length, NumberRange, Optional

CATEGORY_CHOICES = [
    ("laptop", "Portátil"),
    ("network", "Red"),
    ("server", "Servidor"),
    ("storage", "Almacenamiento"),
    ("iot", "IoT / Electrónica"),
    ("other", "Otro"),
]

LOCATION_CHOICES = [
    ("armario-a", "Armario A"),
    ("armario-b", "Armario B"),
    ("rack-1", "Rack 1"),
    ("rack-2", "Rack 2"),
    ("laboratorio-1", "Laboratorio 1"),
    ("laboratorio-2", "Laboratorio 2"),
    ("almacen", "Almacén"),
]

STATUS_CHOICES = [
    ("available", "Disponible"),
    ("loaned", "Prestado"),
    ("maintenance", "Mantenimiento"),
    ("retired", "Retirado"),
]

SECURITY_QUESTION_CHOICES = [
    ("pet", "¿Cómo se llamaba tu primera mascota?"),
    ("school", "¿Cuál fue el nombre de tu primer colegio?"),
    ("city", "¿En qué ciudad naciste?"),
    ("teacher", "¿Cómo se llamaba tu profesor o profesora favorita?"),
    ("movie", "¿Cuál fue la primera película que recuerdas haber visto en el cine?"),
]


class LoginForm(FlaskForm):
    email = StringField("Correo", validators=[InputRequired(), Email(), Length(max=120)], render_kw={"required": True})
    password = PasswordField("Contraseña", validators=[InputRequired(), Length(min=8, max=128)], render_kw={"required": True})
    captcha_answer = StringField("Resultado del captcha", validators=[InputRequired(), Length(max=10)], render_kw={"required": True})
    submit = SubmitField("Entrar")


class TwoFactorLoginForm(FlaskForm):
    token = StringField("Código de autenticación", validators=[InputRequired(), Length(min=6, max=6)], render_kw={"required": True, "maxlength": 6})
    submit = SubmitField("Verificar")


class UserForm(FlaskForm):
    name = StringField("Nombre", validators=[InputRequired(), Length(max=120)], render_kw={"required": True})
    email = StringField("Correo", validators=[InputRequired(), Email(), Length(max=120)], render_kw={"required": True})
    password = PasswordField("Contraseña", validators=[InputRequired(), Length(min=8, max=128)], render_kw={"required": True})
    role = SelectField(
        "Rol",
        choices=[("admin", "admin"), ("technician", "technician"), ("user", "user")],
        validators=[InputRequired()],
        render_kw={"required": True},
    )
    submit = SubmitField("Crear usuario")


class RegistrationForm(FlaskForm):
    name = StringField("Nombre", validators=[InputRequired(), Length(max=120)], render_kw={"required": True})
    email = StringField("Correo", validators=[InputRequired(), Email(), Length(max=120)], render_kw={"required": True})
    password = PasswordField("Contraseña", validators=[InputRequired(), Length(min=8, max=128)], render_kw={"required": True})
    submit = SubmitField("Solicitar cuenta")


class EditUserForm(FlaskForm):
    name = StringField("Nombre", validators=[InputRequired(), Length(max=120)], render_kw={"required": True})
    email = StringField("Correo", validators=[InputRequired(), Email(), Length(max=120)], render_kw={"required": True})
    password = PasswordField("Nueva contraseña", validators=[Optional(), Length(min=8, max=128)])
    role = SelectField(
        "Rol",
        choices=[("admin", "admin"), ("technician", "technician"), ("user", "user")],
        validators=[InputRequired()],
        render_kw={"required": True},
    )
    submit = SubmitField("Guardar cambios")


class ChangePasswordForm(FlaskForm):
    password = PasswordField("Nueva contraseña", validators=[InputRequired(), Length(min=8, max=128)], render_kw={"required": True})
    submit = SubmitField("Guardar nueva contraseña")


class SecurityQuestionForm(FlaskForm):
    security_question = SelectField(
        "Pregunta de seguridad",
        choices=SECURITY_QUESTION_CHOICES,
        validators=[InputRequired()],
        render_kw={"required": True},
    )
    security_answer = StringField(
        "Respuesta",
        validators=[InputRequired(), Length(min=2, max=120)],
        render_kw={"required": True},
    )
    submit = SubmitField("Guardar pregunta de seguridad")


class ForgotPasswordRequestForm(FlaskForm):
    email = StringField("Correo", validators=[InputRequired(), Email(), Length(max=120)], render_kw={"required": True})
    submit = SubmitField("Continuar")


class ResetPasswordWithQuestionForm(FlaskForm):
    security_answer = StringField(
        "Respuesta de seguridad",
        validators=[InputRequired(), Length(min=2, max=120)],
        render_kw={"required": True},
    )
    password = PasswordField(
        "Nueva contraseña",
        validators=[InputRequired(), Length(min=8, max=128)],
        render_kw={"required": True},
    )
    submit = SubmitField("Restablecer contraseña")


class TwoFactorSetupForm(FlaskForm):
    token = StringField("Código de verificación", validators=[InputRequired(), Length(min=6, max=6)], render_kw={"required": True, "maxlength": 6})
    submit = SubmitField("Activar 2FA")


class EquipmentForm(FlaskForm):
    name = StringField("Nombre", validators=[InputRequired(), Length(max=120)], render_kw={"required": True})
    category = SelectField("Categoría", choices=CATEGORY_CHOICES, validators=[InputRequired()], render_kw={"required": True})
    location = SelectField("Ubicación", choices=LOCATION_CHOICES, validators=[InputRequired()], render_kw={"required": True})
    status = SelectField("Estado", choices=STATUS_CHOICES, validators=[InputRequired()], default="available", render_kw={"required": True})
    criticality = SelectField(
        "Criticidad",
        choices=[("low", "low"), ("medium", "medium"), ("high", "high")],
        validators=[InputRequired()],
        render_kw={"required": True},
    )
    notes = TextAreaField("Notas", validators=[Optional(), Length(max=1000)])
    submit = SubmitField("Guardar equipo")


class LoanForm(FlaskForm):
    equipment_id = SelectField("Equipo", coerce=int, validators=[InputRequired()], render_kw={"required": True})
    purpose = TextAreaField("Finalidad", validators=[InputRequired(), Length(min=5, max=255)], render_kw={"required": True})
    requested_days = IntegerField(
        "Duración del préstamo (días)",
        validators=[InputRequired(), NumberRange(min=1, max=30)],
        render_kw={"required": True, "min": 1, "max": 30, "step": 1, "type": "number"},
        default=1,
    )
    submit = SubmitField("Solicitar préstamo")


class IncidentForm(FlaskForm):
    equipment_id = SelectField("Equipo afectado", coerce=int, validators=[InputRequired()], render_kw={"required": True})
    title = StringField("Título", validators=[InputRequired(), Length(max=120)], render_kw={"required": True})
    severity = SelectField(
        "Severidad",
        choices=[("low", "low"), ("medium", "medium"), ("high", "high"), ("critical", "critical")],
        validators=[InputRequired()],
        render_kw={"required": True},
    )
    description = TextAreaField("Descripción", validators=[InputRequired(), Length(min=10, max=2000)], render_kw={"required": True})
    submit = SubmitField("Registrar incidencia")


class IncidentResponseForm(FlaskForm):
    response = TextAreaField("Respuesta técnica", validators=[InputRequired(), Length(min=5, max=2000)], render_kw={"required": True})
    submit = SubmitField("Guardar respuesta")

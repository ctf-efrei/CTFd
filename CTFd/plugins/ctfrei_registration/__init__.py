import json, hashlib, hmac, os, random, string
import requests as req

from datetime import datetime, UTC

from flask import Blueprint, jsonify, request, redirect, url_for, render_template, session
from flask_babel import lazy_gettext as _l
from wtforms import StringField, SubmitField, PasswordField, HiddenField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, InputRequired, ValidationError


from CTFd.models import db, Users, UserFieldEntries
from CTFd.plugins import bypass_csrf_protection, register_plugin_assets_directory
from CTFd.utils.security.auth import login_user
from .models import DiscordRegistrations
from wtforms.form import Form

from ...utils import get_config
from ...utils.decorators import ratelimit
from ...utils.security.csrf import generate_nonce


discord_bp = Blueprint("ctfrei_registration", __name__, template_folder="assets/templates")


class DiscordVerifications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_username = db.Column(db.String(64), unique=True)
    code = db.Column(db.String(24))
    created_at = db.Column(db.DateTime, default=datetime.now(UTC))


# secondes
COOLDOWN = 15
DISCORD_USERNAME_FIELD_ID = 2
MEMBERSHIP_FIELD_ID = 3

def validate_code(form, field):
    entry = DiscordVerifications.query.filter_by(
        discord_username=form.discord_name.data.lower()
    ).first()

    if not entry or entry.code != field.data:
        raise ValidationError("Le code Discord est invalide ou expiré.")

@bypass_csrf_protection
def patched_register():
    if not os.environ.get("DISCORD_SHARED_KEY"):
        return redirect('/'), 307

    password_min_length = int(get_config("password_min_length", default=0))
    password_description = _l("Password used to log into your account")
    if password_min_length:
        password_description += _l(
            f" (Must be at least {password_min_length} characters)"
        )

    class DiscordRegisterForm(Form):
        name = StringField(
            _l("User Name"),
            description="Your username on the site",
            validators=[InputRequired()],
            render_kw={"autofocus": True},
        )
        email = EmailField(
            _l("Email"),
            description="Never shown to the public",
            validators=[InputRequired()],
        )
        password = PasswordField(
            _l("Password"),
            description=password_description,
            validators=[InputRequired()],
        )

        discord_name = StringField(
            "ID Discord",
            validators=[InputRequired()],
            description="Votre pseudo Discord (ex: calygael, niilyx...)"
        )

        registration_code = StringField(
            "Code d'inscription",
            validators=[DataRequired(), validate_code],
            description="Entrez le code que vous avez reçu sur Discord"
        )

        submit = SubmitField(_l("Submit"))

        nonce = HiddenField("Nonce")

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            if 'nonce' not in session:
                session['nonce'] = generate_nonce()
            self.nonce.data = session['nonce']

        prefix = "ctfrei_registration_"

    form = DiscordRegisterForm(request.form, prefix="ctfrei_registration_")

    print("==================")
    if request.method == 'POST':
        if form.validate():
            print("Form *seems* valid!")
            if form.nonce.data != session.get('nonce'):
                print("CSRF attack detected! piss off will ya")
                return redirect('/')

            discord_username = form.discord_name.data.strip().strip('"').lower()
            discord_verif_obj = (DiscordVerifications
                .query
                .filter_by(
                    discord_username=discord_username
                ).first()
            )

            # le neuill a changé son pseudo entre temps !! la honte
            if not discord_verif_obj:
                form.registration_code.errors.append("Le code Discord est invalide ou expiré.")
                return render_template('plugins/ctfrei_registration/assets/templates/register.html', form=form)

            user = Users(
                name=form.name.data,
                email=form.email.data,
                password=form.password.data,
            )
            db.session.add(user)
            db.session.flush()

            discord_name = UserFieldEntries(
                type="user",
                field_id=DISCORD_USERNAME_FIELD_ID,
                user_id=user.id,
                value=f'{discord_username}'
            )
            db.session.add(discord_name)

            membership = UserFieldEntries(
                type="user",
                field_id=MEMBERSHIP_FIELD_ID,
                user_id=user.id,
                value=False
            )
            db.session.add(membership)
            db.session.delete(discord_verif_obj)
            db.session.commit()

            # log them in
            login_user(user)

            session.pop('nonce', None)
            return redirect(url_for('challenges.listing'))

        else:
            print("Form is not valid!")
            print(form.errors)

    return render_template('plugins/ctfrei_registration/assets/templates/register.html', form=form)

def load(app):
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True

    # discord_bp.add_url_rule('/sign-in', endpoint='/sign-in', view_func=patched_register, methods=['GET', 'POST'])
    register_plugin_assets_directory(app, base_path="/plugins/ctfrei_registration/assets", endpoint="ctfrei_reg.assets")

    db.create_all()

    app.view_functions['auth.register'] = patched_register

    @discord_bp.route("/send_code/<discord>", methods=["GET"])
    @ratelimit(method="GET", limit=10, interval=5)
    def send_code(discord: str):
        username = discord.strip().lower()
        if not username:
            return jsonify({"error": "Spécifie ton pseudo Discord !"}), 400
        if (not username.isprintable()) or len(username) > 64:
            return jsonify({"error": "Cela ne ressemble pas à un pseudo Discord..."}), 400

        code = "".join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=24))
        
        # apparemment mettre en guillemets ce que fait CTFd?!?!?! UGH
        existing_user = UserFieldEntries.query.filter_by(field_id=DISCORD_USERNAME_FIELD_ID, value=f'"{username}"').first()
        print(f"Existing_user: {existing_user}")
        if existing_user:
            return jsonify({"error": "Vous avez déjà un compte ! Contactez un membre du bureau pour de l'aide."}), 418

        entry = DiscordVerifications.query.filter_by(discord_username=username).first()

        if entry:
            now = datetime.now()
            if (now - entry.created_at).seconds < COOLDOWN:
                return jsonify(
                    {"error": f"Faut ralentir, un peu ! Attends {COOLDOWN - (now - entry.created_at).seconds} secondes"}
                ), 429
            entry.code = code
            entry.created_at = now
        else:
            entry = DiscordVerifications(discord_username=username, code=code)
            db.session.add(entry)
        db.session.commit()

        print(f"[DEBUG] Send code {code} to {username}")
        payload = {
            "msg": "register",

            "discord_name": username,
            "code": code
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-Signature": hmac.new(
                os.environ.get("DISCORD_SHARED_KEY").encode("utf-8"),
                msg=json.dumps(payload).encode("utf-8"),
                digestmod=hashlib.sha256
            ).hexdigest()
        }

        res = req.post("http://bot:5000/ctfd-webhook", headers=headers, json=payload)
        try:
            res_json = res.json()
            if res_json.get("status") != "ok":
                if res_json.get("code") == 404:
                    return jsonify(
                        {
                            "error": "Le bot ne t'as pas trouvé sur Discord. Es-tu sur notre serveur ? (https://discord.gg/8wnqs9pN9V)"
                        }), 404
                if res_json.get("code") == 403:
                    return jsonify({"error": "Le bot n'a pas réussi à t'envoyer un message. Vérifie tes paramètres de confidentialité Discord !"}), 403

                return jsonify({"error": "Le bot dort... Contacte un admin !"}), 500
        except:
            return jsonify({"error": "Le bot dort... Contacte un admin !"}), 500

        return jsonify({"success": f"Code envoyé à {username}."})

    @discord_bp.route("/update_role/<discord>", methods=["PATCH"])
    @bypass_csrf_protection
    def update_role(discord: str):
        body = request.get_json()

        received_sig = request.headers.get("X-Signature")
        if not received_sig:
            return jsonify({"error": "No signature..."}), 401
        username = discord.strip().lower()
        if not username:
            return jsonify({"error": "Spécifie ton pseudo Discord !"}), 400
        if (not username.isprintable()) or len(username) > 64:
            return jsonify({"error": "Cela ne ressemble pas à un pseudo Discord..."}), 400

        expected_sig = hmac.new(
            os.environ.get("DISCORD_SHARED_KEY").encode("utf-8"),
            json.dumps(body).encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            print("-=-=- Invalid signature received -=-=-")
            print(f"\t- Signature: {received_sig}")
            print(f"\t- Body: {body}")
            return jsonify({"error": "Oh-oh. Signature invalide."}), 401

        ctfd_user = UserFieldEntries.query.filter_by(field_id=DISCORD_USERNAME_FIELD_ID, value=f'"{username}"').first()
        if not ctfd_user:
            return jsonify({"error": "Utilisateur non trouvé sur CTFd."}), 404

        user_membership = UserFieldEntries.query.filter_by(
            field_id=MEMBERSHIP_FIELD_ID,
            user_id=ctfd_user.user_id
        ).first()
        if not user_membership:
            print("Missing entry...")
            user_membership = UserFieldEntries(
                type="user",
                field_id=MEMBERSHIP_FIELD_ID,
                user_id=ctfd_user.user_id
            )
            db.session.add(user_membership)
        user_membership.value = bool(body.get("new_state"))
        db.session.commit()

        return jsonify({"success": f"Rôle mis à jour pour {username}."})

    app.register_blueprint(discord_bp, url_prefix="/plugins/ctfrei_registration")

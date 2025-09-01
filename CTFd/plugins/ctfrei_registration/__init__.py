import json, hashlib, hmac, os, random, string
from functools import wraps
from idlelib.rpc import response_queue

import requests as req

from datetime import datetime, UTC

from flask import Blueprint, jsonify, request, redirect, url_for, render_template, session, Response, abort
from flask_babel import lazy_gettext as _l
from wtforms import StringField, SubmitField, PasswordField, HiddenField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, InputRequired, ValidationError


from CTFd.api import api, challenges_namespace
from CTFd.models import db, Users, UserFieldEntries, Challenges
from CTFd.plugins import bypass_csrf_protection, register_plugin_assets_directory
from CTFd.utils.security.auth import login_user
from CTFd.utils.user import get_current_user, get_current_user_attrs, is_admin
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

CHALLENGE_MEMBER_TAG = "Adhérent"

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

            res = req.get(f"http://bot:5000/is_member/{discord_username}", headers={"Content-Type": "application/json"})
            if res.status_code == 200:
                is_member = res.json().get("is_member", False)
            else:
                print(f"Could not verify membership status, assuming false: {res.status_code} {res.text}")
                is_member = False
            membership = UserFieldEntries(
                type="user",
                field_id=MEMBERSHIP_FIELD_ID,
                user_id=user.id,
                value=is_member
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

def guard(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return fn(*args, **kwargs)

        if request.path.startswith("/static/") or request.path.startswith("/themes/") \
                or request.path.startswith("/plugins/") or request.path.startswith("/assets/"):
            return fn(*args, **kwargs)

        if is_admin():
            return fn(*args, **kwargs)

        user = get_current_user()
        if not (user and any(f.name == CHALLENGE_MEMBER_TAG and f.value == True
                               for f in getattr(user, "fields", []))):
            response = fn(*args, **kwargs)
            if not response.is_json:
                return response

            data = response.get_json()
            if request.path == "/api/v1/challenges":
                new_data = []
                for chal in data.get("data", []):
                    tags = chal.get("tags", [])
                    if all(tag.get("value", "") != CHALLENGE_MEMBER_TAG for tag in tags):
                        new_data.append(chal)

                data['data'] = new_data
                response.set_data(json.dumps(data))
                return response
            else:
                def get_tag(t):
                    if type(t) == dict:
                        return t.get("value", "")
                    if type(t) == str:
                        return t
                    if isinstance(t, object):
                        return t.value
                    return t
                def testfor_tags(tagslist):
                    if any(get_tag(tag) == CHALLENGE_MEMBER_TAG for tag in tagslist):
                        abort(
                            403,
                            description="Vous ne pouvez pas visualiser ce challenge car vous n'etes pas adherent."
                        )
                chal_data = data.get("data", [{}])
                if type(chal_data) == dict:
                    chal_data = [chal_data]
                for chal in chal_data:
                    tags = chal.get("tags", [])
                    if tags:
                        testfor_tags(tags)
                    else:
                        challenge_id = request.path.split("/")[4]
                        if not challenge_id.isdigit():
                            print("Non-digit challenge id, trying to get from data")
                            challenge_id = request.get_json().get("challenge_id", None) if request.is_json else None
                            if not challenge_id or not str(challenge_id).isdigit():
                                print(f"No challenge id found in data either: {data}")
                                abort(404)

                        chal_obj = Challenges.query.filter_by(id=int(challenge_id)).first()
                        if not chal_obj:
                            abort(404)
                        testfor_tags(chal_obj.tags)

        return fn(*args, **kwargs)
    return wrapper

def load(app):
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True

    # discord_bp.add_url_rule('/sign-in', endpoint='/sign-in', view_func=patched_register, methods=['GET', 'POST'])
    register_plugin_assets_directory(app, base_path="/plugins/ctfrei_registration/assets", endpoint="ctfrei_reg.assets")

    db.create_all()

    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/v1/challenges"):
            endpoint = rule.endpoint

            if endpoint in app.view_functions:
                app.view_functions[endpoint] = guard(app.view_functions[endpoint])

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
                print(f"Error response from bot: {res_json}")
                if res_json.get("code") == 404:
                    return jsonify(
                        {
                            "error": "Le bot ne t'as pas trouvé sur Discord. Es-tu sur notre serveur ? (https://discord.gg/8wnqs9pN9V)"
                        }), 404
                if res_json.get("code") == 403:
                    return jsonify({"error": "Le bot n'a pas réussi à t'envoyer un message. Vérifie tes paramètres de confidentialité Discord !"}), 403

                return jsonify({"error": "Le bot dort... Contacte un admin !"}), 500
        except Exception as e:
            print(f"Could not parse JSON response from bot: {e} {res.text}")
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


    # all challenge endpoints, basically
    RESTRICTED_ENDPOINTS = [
        'api.challenges_challenge_types',
        'api.challenges_challenge',
        'api.challenges_challenge_attempt',
        'api.challenges_challenge_solves',
        'api.challenges_challenge_files',
        'api.challenges_challenge_tags',
        'api.challenges_challenge_hints',
        'api.challenges_challenge_flags',
        'api.challenges_challenge_requirements',
        'api.challenges_challenge_ratings',
    ]
    for endpoint in RESTRICTED_ENDPOINTS:
        old_viewfunc = app.view_functions.get(endpoint)
        if not old_viewfunc:
            print(f"[ERROR] Could not find endpoint {endpoint} to patch!")
            exit(-1)

        print(f"[DEBUG] Patching endpoint {endpoint} ({old_viewfunc})")
        def viewfunc_wrapper(*args, **kwargs):
            response = old_viewfunc(*args, **kwargs)
            data = response.get_json()

            this_user = get_current_user()
            if not this_user:
                return {"error": "Not logged in"}, 401

            print(request, request.path, args, kwargs)
            chal = Challenges.query.filter_by(id=kwargs.get('challenge_id')).first()
            if not chal:
                return {"error": "Challenge not found"}, 404
            tags = chal.tags
            is_member_challenge = any(tag.value == CHALLENGE_MEMBER_TAG for tag in tags)
            if not is_member_challenge:
                return jsonify(data)

            user_membership = any(
                (field and field.name == CHALLENGE_MEMBER_TAG and field.value == True) for field in this_user.fields
            )
            if user_membership:
                return jsonify(data)

            print(f"{this_user.name or 'Jean-Neuill'} not a member!!! Deny their ass on endpoint {endpoint}")

            # carry over success status and other keys from endpoints' oldfunc
            return {}, 403
        # app.view_functions[endpoint] = viewfunc_wrapper
        print("[DEBUG] Patching done.")

    print("[DEBUG] Finally, patching challenge list")
    old_challist = app.view_functions['api.challenges_challenge_list']
    def challist_wrapper(*args, **kwargs):
        response = old_challist(*args, **kwargs)
        data = response.get_json()

        this_user = get_current_user()
        if not this_user:
            return {"error": "Not logged in"}, 401

        user_membership = any(
            (field and field.name == CHALLENGE_MEMBER_TAG and field.value == True) for field in this_user.fields
        )
        if user_membership:
            return jsonify(data)

        print(f"{this_user.name or 'Jean-Neuill'} not a member!!! Restrict their ass on endpoint {endpoint}")

        lst = data.get('data', [])
        for challenge in lst:
            tags = challenge.get('tags', [])
            for tag in tags:
                if tag.get('value') == CHALLENGE_MEMBER_TAG:
                    lst.remove(challenge)
                    break
        data['data'] = lst
        return jsonify(data)
    # app.view_functions['api.challenges_challenge_list'] = challist_wrapper

    for r in app.view_functions:
        print(f"[DEBUG] Route: {r} -> {app.view_functions[r]}")

    # @app.after_request
    def modify_api_response(response: Response):
        if request.path.startswith("/api/v1/challenges"):
            if response.is_json:
                data = response.get_json()
                print(api.endpoint, dir(api))
                this_user = get_current_user()
                user_membership = any(
                    (field and field.name == CHALLENGE_MEMBER_TAG and field.value == True) for field in this_user.fields
                )
                if not user_membership:
                    new_data = []
                    for chal in data.get("data", []):
                        tags = chal.get('tags', [])
                        is_member_challenge = any(tag.get('value') == CHALLENGE_MEMBER_TAG for tag in tags)
                        if not is_member_challenge:
                            new_data.append(chal)
                    data['data'] = new_data
                    response.set_data(json.dumps(data))
        return response

    app.register_blueprint(discord_bp, url_prefix="/plugins/ctfrei_registration")

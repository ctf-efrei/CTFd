import hashlib
import hmac
import json
import os
import random
import string
from datetime import datetime

import requests as req
from flask import Blueprint, jsonify, request, redirect, url_for, render_template, session
from flask_babel import lazy_gettext as _l
from wtforms import StringField, SubmitField, PasswordField, HiddenField
from wtforms.fields.html5 import EmailField
from wtforms.form import Form
from wtforms.validators import DataRequired, InputRequired

from CTFd.models import db, Users, UserFieldEntries
from CTFd.plugins import bypass_csrf_protection, register_plugin_assets_directory
from CTFd.utils import email
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.security.auth import login_user
from . import constants as cst
from . import utils
from .models import DiscordRegistrations, DiscordVerifications
from ...utils import get_config
from ...utils.decorators import ratelimit
from ...utils.security.csrf import generate_nonce

discord_bp = Blueprint("ctfrei_registration", __name__, template_folder="assets/templates")


@bypass_csrf_protection
def patched_register():
    if not os.environ.get("DISCORD_SHARED_KEY"):
        print(r" /!\/!\ DISCORD_SHARED_KEY not set, kicking to / /!\/!\ ")
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
            validators=[DataRequired(), utils.validate_code],
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

            if email.check_email_is_whitelisted(form.email.data) is False:
                form.email.errors.append(_l("Your email address is not from an allowed domain"))
                return render_template('plugins/ctfrei_registration/assets/templates/register.html', form=form)
            if email.check_email_is_blacklisted(form.email.data) is True:
                form.email.errors.append(_l("Your email address is not from an allowed domain"))
                return render_template('plugins/ctfrei_registration/assets/templates/register.html', form=form)

            print("Form *seems* valid!")
            if form.nonce.data != session.get('nonce'):
                print("CSRF attack detected! piss off will ya")
                return redirect('/')

            discord_username = form.discord_name.data.strip().strip('"').lower()
            discord_verif_obj = (DiscordVerifications
                                 .query
                                 .filter_by(
                discord_username=discord_username
            ).first())

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
                field_id=cst.DISCORD_USERNAME_FIELD_ID,
                user_id=user.id,
                value=f'{discord_username}'
            )
            db.session.add(discord_name)

            res = req.get(f"http://bot:5000/userinfo/{discord_username}", headers={"Content-Type": "application/json"})
            if res.status_code == 200:
                res_json = res.json()
            else:
                print(f"Could not verify membership status. {res.status_code} {res.text}")
                db.session.rollback()
                form.discord_name.errors.append("Le bot ne répond pas, réessaie plus tard.")
                return render_template(
                    'plugins/ctfrei_registration/assets/templates/register.html',
                    form=form
                )

            membership = UserFieldEntries(
                type="user",
                field_id=cst.MEMBERSHIP_FIELD_ID,
                user_id=user.id,
                value=res_json.get("is_member", False)
            )
            db.session.add(membership)

            discord_id = UserFieldEntries(
                type="user",
                field_id=cst.DISCORD_ID_FIELD_ID,
                user_id=user.id,
                value=res_json.get("discord_id", 0)
            )
            db.session.add(discord_id)

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

    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/v1/challenges"):
            endpoint = rule.endpoint

            if endpoint in app.view_functions:
                app.view_functions[endpoint] = utils.guard(app.view_functions[endpoint])

    app.view_functions['auth.register'] = check_registration_visibility(patched_register)

    @discord_bp.route("/send_code/<discord>", methods=["GET"])
    @ratelimit(method="GET", limit=10, interval=5)
    def send_code(discord: str):
        username = discord.strip().lower()
        if not username:
            return jsonify({"error": "Spécifie ton pseudo Discord !"}), 400
        if (not username.isprintable()) or len(username) > 64:
            return jsonify({"error": "Cela ne ressemble pas à un pseudo Discord..."}), 400

        try:
            utils.cleanup_discord_verifications()
        except Exception as e:
            print(f"Could not cleanup verifications: {e}")

        code = "".join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=24))

        # apparemment mettre en guillemets ce que fait CTFd?!?!?! UGH
        existing_user = UserFieldEntries.query.filter_by(field_id=cst.DISCORD_USERNAME_FIELD_ID,
                                                         value=f'"{username}"').first()
        print(f"Existing_user: {existing_user}")
        if existing_user:
            return jsonify({"error": "Vous avez déjà un compte ! Si c'est un erreur, "
                                     "faites un ticket pour de l'aide."}), 418

        entry = DiscordVerifications.query.filter_by(discord_username=username).first()

        if entry:
            now = datetime.now()
            if (now - entry.created_at).seconds < cst.DISCORD_CODE_SENDING_COOLDOWN:
                return jsonify(
                    {
                        "error": "Faut ralentir, un peu ! "
                                 f"Attends {cst.DISCORD_CODE_SENDING_COOLDOWN - (now - entry.created_at).seconds} "
                                 "secondes"
                    }
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
                    return jsonify({
                        "error": "Le bot ne t'as pas trouvé sur Discord. "
                                 "Es-tu sur notre serveur ? (https://discord.gg/8wnqs9pN9V)"
                    }), 404
                if res_json.get("code") == 403:
                    return jsonify({
                        "error": "Le bot n'a pas réussi à t'envoyer un message. "
                                 "Vérifie tes paramètres de confidentialité Discord !"
                    }), 403

                return jsonify({"error": "Le bot dort... Contacte un admin !"}), 500
        except Exception as e:
            print(f"Could not parse JSON response from bot: {e} {res.text}")
            return jsonify({"error": "Le bot dort... Contacte un admin !"}), 500

        return jsonify({"success": f"Code envoyé à {username}."})

    # TODO: USE DISCORD ID INSTEAD!!
    @discord_bp.route("/update_role/<discord>", methods=["PATCH"])
    @bypass_csrf_protection
    @utils.check_sig
    def update_role(discord: str):
        body = request.get_json()

        username = discord.strip().lower()
        if not username:
            return jsonify({"error": "Spécifie ton pseudo Discord !"}), 400
        if (not username.isprintable()) or len(username) > 64:
            return jsonify({"error": "Cela ne ressemble pas à un pseudo Discord..."}), 400

        ctfd_user = UserFieldEntries.query.filter_by(field_id=cst.DISCORD_USERNAME_FIELD_ID,
                                                     value=f'"{username}"').first()
        if not ctfd_user:
            return jsonify({"error": "Utilisateur non trouvé sur CTFd."}), 404

        user_membership = UserFieldEntries.query.filter_by(
            field_id=cst.MEMBERSHIP_FIELD_ID,
            user_id=ctfd_user.user_id
        ).first()
        if not user_membership:
            print("Missing entry...")
            user_membership = UserFieldEntries(
                type="user",
                field_id=cst.MEMBERSHIP_FIELD_ID,
                user_id=ctfd_user.user_id
            )
            db.session.add(user_membership)
            changed = True
        else:
            changed = (user_membership.value != bool(body.get("new_state")))
        user_membership.value = bool(body.get("new_state"))
        db.session.commit()

        return jsonify({"success": f"Rôle mis à jour pour {username}.", "changed": changed}), 200

    @discord_bp.route("/sync", methods=["PATCH"])
    @bypass_csrf_protection
    @utils.check_sig
    def sync_members_and_roles():
        body = request.get_json()
        users = body.get("users", None)

        if users is None:
            return jsonify({"error": "Aucun utilisateur à synchroniser."}), 400

        try:
            affected_ctr = 0
            # Step 1: Load all CTFd users with their custom fields
            ctfd_users = Users.query.options(db.joinedload("field_entries")).all()

            # Step 2: Build lookup: Discord ID -> (user object, {field_id -> field_entry})
            ctfd_lookup = {}
            for u in ctfd_users:
                fields = {f.field_id: f for f in u.field_entries}
                discord_id_field = fields.get(cst.DISCORD_ID_FIELD_ID)
                if discord_id_field:
                    discord_id_field.value = str(discord_id_field.value).strip().strip('"')
                    ctfd_lookup[discord_id_field.value] = (u, fields)

            # Step 3: Track Discord IDs we processed
            processed_discord_ids = set()

            print("SYNC IN PROGRESS...")
            # Step 4: Process incoming Discord users
            for user in users:
                discord_id = str(user.get("discord_id"))
                discord_name = user.get("discord_name")

                if not discord_id or not discord_name:
                    print(f"Skipping invalid user entry: {user}")
                    continue

                processed_discord_ids.add(discord_id)
                ctfd_user_entry = ctfd_lookup.get(str(discord_id))

                if not ctfd_user_entry:
                    print(f"No CTFd user found for Discord user {discord_name} ({discord_id})")
                    continue

                ctfd_user, fields = ctfd_user_entry

                # Step 4a: Update Discord username if mismatch
                discord_username_entry = fields.get(cst.DISCORD_USERNAME_FIELD_ID)
                if discord_username_entry:
                    if discord_username_entry.value.strip('"').lower() != discord_name.strip().lower():
                        print(f"Updating Discord username for CTFd user {ctfd_user.username} {ctfd_user.id}: "
                              f"{discord_username_entry.value} -> {discord_name}")
                        discord_username_entry.value = f'"{discord_name.strip()}"'
                        affected_ctr += 1
                else:
                    # Create entry if missing: VERY WEIRD!!
                    discord_username_entry = UserFieldEntries(
                        type="user",
                        field_id=cst.DISCORD_USERNAME_FIELD_ID,
                        user_id=ctfd_user.id,
                        value=f'"{discord_name.strip()}"'
                    )
                    db.session.add(discord_username_entry)
                    fields[cst.DISCORD_USERNAME_FIELD_ID] = discord_username_entry
                    print(f"Created missing Discord username entry for CTFd user {ctfd_user.username} {ctfd_user.id}: "
                          f"{discord_name}")
                    print("This should not happen normally.")
                    affected_ctr += 1

                # Step 4b: Update membership field
                membership_entry = fields.get(cst.MEMBERSHIP_FIELD_ID)
                if membership_entry:
                    if membership_entry.value is not True:
                        membership_entry.value = True
                        affected_ctr += 1
                else:
                    membership_entry = UserFieldEntries(
                        type="user",
                        field_id=cst.MEMBERSHIP_FIELD_ID,
                        user_id=ctfd_user.id,
                        value=True
                    )
                    db.session.add(membership_entry)
                    fields[cst.MEMBERSHIP_FIELD_ID] = membership_entry
                    affected_ctr += 1

            # Step 5: Mark users not in Discord list as non-members
            for u in ctfd_users:
                fields = {f.field_id: f for f in u.field_entries}
                discord_id_field = fields.get(cst.DISCORD_ID_FIELD_ID)
                if not discord_id_field:
                    continue
                if str(discord_id_field.value) not in processed_discord_ids:
                    membership_entry = fields.get(cst.MEMBERSHIP_FIELD_ID)
                    if membership_entry:
                        if membership_entry.value is not False:
                            membership_entry.value = False
                            affected_ctr += 1
                    else:
                        membership_entry = UserFieldEntries(
                            type="user",
                            field_id=cst.MEMBERSHIP_FIELD_ID,
                            user_id=u.id,
                            value=False
                        )
                        db.session.add(membership_entry)
                        affected_ctr += 1

            # Step 6: Commit all changes
            db.session.commit()

            print("SYNC COMPLETED SUCCESSFULLY.")
            print(f"{affected_ctr} users affected.")

            return jsonify({"status": "success", "affected": affected_ctr}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error during sync: {e}")
            return jsonify({"error": "Une erreur est survenue lors de la synchronisation."}), 500

    app.register_blueprint(discord_bp, url_prefix="/plugins/ctfrei_registration")

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, UTC

from wtforms.validators import ValidationError

from CTFd.plugins.ctfrei_registration import constants as cst
from .models import DiscordVerifications

from functools import wraps

from flask import request, abort, jsonify

from CTFd.models import Challenges, db
from CTFd.utils.user import is_admin, get_current_user


def validate_code(form, field):
    entry = DiscordVerifications.query.filter_by(
        discord_username=form.discord_name.data.lower()
    ).first()

    if not entry or entry.code != field.data:
        raise ValidationError("Le code Discord est invalide ou expiré.")


def cleanup_discord_verifications():
    threshold = datetime.now(tz=UTC) - timedelta(seconds=cst.DISCORD_CODE_SENDING_COOLDOWN * 2)
    entries = DiscordVerifications.query.filter(DiscordVerifications.created_at < threshold).all()
    for entry in entries:
        entry.delete()
    db.session.commit()

    print(f"Cleaned up {len(entries)} expired Discord verifications")

def check_sig(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        body = request.get_json()

        received_sig = request.headers.get("X-Signature")
        if not received_sig:
            return jsonify({"error": "No signature..."}), 401
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
        return fn(*args, **kwargs)
    return wrapper

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
        if not (user and any(f.name == cst.CHALLENGE_MEMBER_TAG and f.value == True
                               for f in getattr(user, "fields", []))):
            response = fn(*args, **kwargs)
            if not response.is_json:
                return response

            data = response.get_json()
            if request.path == "/api/v1/challenges":
                new_data = []
                for chal in data.get("data", []):
                    tags = chal.get("tags", [])
                    if all(tag.get("value", "") != cst.CHALLENGE_MEMBER_TAG for tag in tags):
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
                    if any(get_tag(tag) == cst.CHALLENGE_MEMBER_TAG for tag in tagslist):
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

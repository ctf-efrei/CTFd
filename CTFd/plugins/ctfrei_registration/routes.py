from flask import Blueprint, request, jsonify
from CTFd.models import db, Users
from .discord_bot import send_registration_code

bp = Blueprint("discord_register", __name__, template_folder="templates")

@bp.route("/plugins/discord/send_code", methods=["POST"])
def send_code():
    data = request.json
    discord_username = data.get("discord_username")
    user_id = data.get("user_id")

    if not discord_username or not user_id:
        return jsonify({"error": "Missing parameters"}), 400

    code = send_registration_code(discord_username)

    from .models import DiscordRegistrations
    req = DiscordRegistrations(user_id=user_id, discord_id=discord_username, code=code)
    db.session.add(req)
    db.session.commit()

    return jsonify({"status": "ok"})

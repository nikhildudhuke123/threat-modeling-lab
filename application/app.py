from flask import Flask, jsonify, request

app = Flask(__name__)

# Demo-only credentials. Never use fixed tokens in production.
DEMO_TOKENS = {
    "user-a-demo-token": "user-a",
    "user-b-demo-token": "user-b",
}

ACCOUNTS = {
    101: {"owner": "user-a", "balance": 1500},
    202: {"owner": "user-b", "balance": 2400},
}


def authenticated_user():
    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")

    if scheme.lower() != "bearer":
        return None

    return DEMO_TOKENS.get(token)


@app.route("/api/accounts/<int:account_id>", methods=["GET"])
def get_account(account_id):
    user = authenticated_user()

    if user is None:
        return jsonify({"error": "Unauthorized"}), 401

    account = ACCOUNTS.get(account_id)

    if account is None:
        return jsonify({"error": "Account not found"}), 404

    # FIX: Verify the authenticated user's ownership.
    if account["owner"] != user:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({
        "account_id": account_id,
        "owner": account["owner"],
        "balance": account["balance"],
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

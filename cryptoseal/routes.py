from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    send_file,
)
from werkzeug.utils import secure_filename
from io import BytesIO

from cryptoseal.symmetric import aes, triple_des, chacha20
from cryptoseal.asymmetric import generate_key, encrypt, decrypt
from cryptoseal.hashing import hash_data

from cryptography.exceptions import InvalidTag


bp = Blueprint("routes", __name__)


@bp.route("/")
def index():
    return render_template("routes/index.html")


@bp.route("/symmetric", methods=["GET", "POST"])
def symmetric():
    if request.method == "GET":
        return render_template("routes/symmetric.html", result="")

    try:
        algo = request.form.get("algo")
        action = request.form.get("action")
        mode = request.form.get("mode")
        key = request.form.get("key")

        if not all([algo, action, mode, key]):
            return jsonify(error="Missing required fields."), 400

        if mode == "text":
            text = request.form.get("text")
            if not text:
                return jsonify(error="No text provided."), 400

            if algo == "aes":
                result = aes(text, key, action)
            elif algo == "3des":
                result = triple_des(text, key, action)
            elif algo == "chacha20":
                result = chacha20(text, key, action)
            else:
                return jsonify(error="Invalid algorithm."), 400

            return jsonify(result=result), 200

        elif mode == "file":
            file = request.files.get("file")
            if not file or file.filename == "":
                return jsonify(error="No file selected."), 400

            file_bytes = file.read()

            if algo == "aes":
                processed = aes(file_bytes, key, action, is_file=True)
            elif algo == "3des":
                processed = triple_des(file_bytes, key, action, is_file=True)
            elif algo == "chacha20":
                processed = chacha20(file_bytes, key, action, is_file=True)
            else:
                return jsonify(error="Invalid algorithm."), 400

            filename = f"{'encrypted' if action == 'encrypt' else 'decrypted'}_{secure_filename(file.filename)}"

            return send_file(
                BytesIO(processed), download_name=filename, as_attachment=True
            )
        else:
            return jsonify(error="Invalid mode."), 400

    except Exception as e:
        return jsonify(error=f"Server error: {str(e)}"), 500


@bp.route("/asymmetric")
def asymmetric():
    return render_template("routes/asymmetric.html")


@bp.route(
    "/keygen",
    methods=[
        "POST",
    ],
)
def keygen():
    data = request.get_json()
    mode = data.get("mode")
    if mode not in ("rsa", "ecc"):
        return jsonify({"error": "Unsupported mode. Use 'rsa' or 'ecc'"}), 400

    try:
        priv_pem, pub_pem = generate_key(mode)
        return jsonify({"private_key": priv_pem, "public_key": pub_pem})

    except Exception as e:
        return jsonify({"error": f"Key generation failed: {str(e)}"}), 500


@bp.route(
    "/encrypt",
    methods=[
        "POST",
    ],
)
def encrypt_route():
    data = request.get_json()
    mode = data.get("mode")
    message = data.get("message")
    public_pem = data.get("public_key")

    if not all([mode, message, public_pem]):
        return (
            jsonify(
                {
                    "error": "Missing parameters: mode, message, and public_key are required."
                }
            ),
            400,
        )

    if mode not in ("rsa", "ecc"):
        return jsonify({"error": "Unsupported mode. Use 'rsa' or 'ecc'."}), 400

    try:
        result = encrypt(mode, public_pem, message)
        return jsonify({"result": result})

    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500


@bp.route(
    "/decrypt",
    methods=[
        "POST",
    ],
)
def decrypt_route():
    data = request.get_json()
    mode = data.get("mode")
    private_pem = data.get("private_key")

    if mode not in ("rsa", "ecc"):
        return jsonify({"error": "Unsupported mode. Use 'rsa' or 'ecc'."}), 400

    if not private_pem:
        return jsonify({"error": "Missing parameter: private_key is required."}), 400

    try:
        if mode == "rsa":
            ciphertext_hex = data.get("ciphertext")
            if not ciphertext_hex:
                return (
                    jsonify(
                        {
                            "error": "Missing parameter: ciphertext is required for RSA decryption."
                        }
                    ),
                    400,
                )
            plaintext = decrypt(mode, private_pem, ciphertext_hex)
            return jsonify({"plaintext": plaintext})

        elif mode == "ecc":
            encrypted_data = data.get("encrypted_data")
            if not encrypted_data:
                ephemeral_pub = data.get("ephemeral_pub")
                nonce = data.get("nonce")
                ciphertext = data.get("ciphertext")
                tag = data.get("tag")
                if not all([ephemeral_pub, nonce, ciphertext, tag]):
                    return (
                        jsonify(
                            {
                                "error": "Missing parameter: encrypted_data or ECC components (ephemeral_pub, nonce, ciphertext, tag)"
                            }
                        ),
                        400,
                    )
                encrypted_data = {
                    "ephemeral_pub": ephemeral_pub,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "tag": tag,
                }

            try:
                plaintext = decrypt(mode, private_pem, encrypted_data)
                return jsonify({"plaintext": plaintext})
            except InvalidTag:
                return (
                    jsonify(
                        {"error": "Decryption failed: invalid tag or corrupted data"}
                    ),
                    400,
                )
            except Exception as e:
                return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


@bp.route("/hash", methods=["GET", "POST"])
def hash_view():
    if request.method == "POST":
        try:
            algo = request.form["algo"]
            mode = request.form["mode"]

            if mode == "text":
                text = request.form["text"]
                data = text.encode("utf-8")
            elif mode == "file":
                uploaded_file = request.files["file"]
                if not uploaded_file:
                    return jsonify({"error": "No file uploaded"}), 400
                data = uploaded_file.read()
            else:
                return jsonify({"error": "Invalid mode"}), 400

            result = hash_data(data, algo)
            return jsonify({"result": result})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template("routes/hash.html")

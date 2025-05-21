from flask import (
    Blueprint, flash, g, redirect, render_template, request, send_file, url_for
)
from werkzeug.exceptions import abort

from app.aes import aes as aes_encrypt_decrypt
from app.des import triple_des as des_encrypt_decrypt
from app.chacha20 import chacha20 as chacha20_encrypt_decrypt

import os
from io import BytesIO
from werkzeug.utils import secure_filename

bp = Blueprint('gizmo', __name__)

@bp.route('/')
def index():
    return render_template('routes/index.html')


from flask import jsonify

@bp.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    if request.method == 'GET':
        # Render the page normally on GET
        return render_template('routes/symmetric.html', result="")

    # POST processing here (same as before)...
    try:
        algorithm = request.form.get('algorithm')
        action = request.form.get('action')
        mode = request.form.get('mode')
        key = request.form.get('key')

        if not all([algorithm, action, mode, key]):
            return jsonify(error="Missing required fields."), 400

        if mode == 'text':
            text = request.form.get('text')
            if not text:
                return jsonify(error="No text provided."), 400

            if algorithm == 'aes':
                result = aes_encrypt_decrypt(text, key, action, is_file=False)
            elif algorithm == '3des':
                result = des_encrypt_decrypt(text, key, action, is_file=False)
            elif algorithm == 'chacha20':
                result = chacha20_encrypt_decrypt(text, key, action, is_file=False)
            else:
                return jsonify(error="Invalid algorithm."), 400

            return jsonify(result=result), 200

        elif mode == 'file':
            file = request.files.get('file')
            if not file or file.filename == '':
                return jsonify(error="No file selected."), 400

            file_bytes = file.read()

            if algorithm == 'aes':
                processed = aes_encrypt_decrypt(file_bytes, key, action, is_file=True)
            elif algorithm == '3des':
                processed = des_encrypt_decrypt(file_bytes, key, action, is_file=True)
            elif algorithm == 'chacha20':
                processed = chacha20_encrypt_decrypt(file_bytes, key, action, is_file=True)
            else:
                return jsonify(error="Invalid algorithm."), 400

            filename = f"{'encrypted' if action == 'encrypt' else 'decrypted'}_{secure_filename(file.filename)}"

            return send_file(
                BytesIO(processed),
                download_name=filename,
                as_attachment=True
            )

        else:
            return jsonify(error="Invalid mode."), 400

    except Exception as e:
        return jsonify(error=f"Server error: {str(e)}"), 500


@bp.route('/asymmetric')
def asymmetric():
    return "asymmetric"


@bp.route('/hashing')
def hashing():
    return "hashing"
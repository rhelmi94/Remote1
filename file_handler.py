import os
from flask import Blueprint, request, send_file, jsonify
from flask_login import login_required
from werkzeug.utils import secure_filename

files_bp = Blueprint('files_bp', __name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@files_bp.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return jsonify({'message': 'File uploaded successfully'})
    
    return jsonify({'error': 'File type not allowed'}), 400

@files_bp.route('/api/files/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_file(os.path.join(UPLOAD_FOLDER, secure_filename(filename)))
    except Exception as e:
        return jsonify({'error': str(e)}), 404

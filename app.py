from flask import Flask, session, render_template, request, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from yt_dlp import YoutubeDL
import os
import logging
import re
from flask import jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request

app = Flask(__name__)
app.secret_key = 'secret6767'  # Set a secret key for session management

limiter = Limiter(
    app=app,
    key_func=get_remote_address
)

SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'
REDIRECT_URI = 'https://localhost:5000/oauth2callback'

def create_flow():
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

def handle_video_unavailable(e):
    return "Video is unavailable", 400

def handle_age_restricted(e):
    return "Age-restricted video", 400

def handle_members_only(e):
    return "Members-only video", 400

def handle_live_stream(e):
    return "Live streams cannot be downloaded", 400

def get_authenticated_session():
    if 'credentials' not in session:
        return None

    credentials = Credentials(**session['credentials'])
    
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            session['credentials'] = credentials_to_dict(credentials)
        except Exception as e:
            logging.error(f"Token refresh failed: {str(e)}")
            return None
            
    return credentials

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def remove_file(filepath):
    try:
        os.remove(filepath)
    except Exception as e:
        logging.error(f"Failed to remove file: {str(e)}")

@app.route('/')
def index():
    if not get_authenticated_session():
        return redirect(url_for('authorize'))
    return render_template('index.html')


@app.route('/video-info', methods=['GET'])
def video_info():
    video_url = request.args.get('url')
    if not video_url:
        return jsonify({
            "success": False,
            "error": "No URL provided",
            "code": "MISSING_URL"
        }), 400

    # Validate URL format
    youtube_regex = (
        r'(https?://)?(www\.)?'
        '(youtube|youtu|youtube-nocookie)\.(com|be)/'
        '(watch\?v=|embed/|v/|.+\?v=)?([^&=%\?]{11})'
    )
    
    if not re.match(youtube_regex, video_url):
        return jsonify({
            "success": False,
            "error": "Invalid YouTube URL",
            "code": "INVALID_URL"
        }), 400

    try:
        ydl_opts = {
            'quiet': True,
            'extract_flat': False,
            'logger': logging.getLogger(__name__)
        }

        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=False)
            duration = info.get('duration', 0)
            file_size = info.get('filesize', 0)
            
            # Get available formats
            formats = []
            if 'formats' in info:
                for f in info['formats']:
                    if f.get('vcodec') != 'none':  # Video formats
                        formats.append({
                            'format_id': f['format_id'],
                            'resolution': f.get('height', 0),
                            'fps': f.get('fps', 0),
                            'ext': f.get('ext', ''),
                            'filesize': f.get('filesize', 0)
                        })
                    elif f.get('acodec') != 'none':  # Audio formats
                        formats.append({
                            'format_id': f['format_id'],
                            'resolution': 0,
                            'fps': 0,
                            'ext': f.get('ext', ''),
                            'filesize': f.get('filesize', 0)
                        })

            return jsonify({
                "success": True,
                "data": {
                    "duration": duration,
                    "file_size": file_size,
                    "title": info.get('title', ''),
                    "thumbnail": info.get('thumbnail', ''),
                    "formats": formats
                }
            })

    except Exception as e:
        logging.error(f"Video info error: {str(e)}")
        error_code = "UNKNOWN_ERROR"
        if "Video unavailable" in str(e):
            error_code = "VIDEO_UNAVAILABLE"
        elif "Age restricted" in str(e):
            error_code = "AGE_RESTRICTED"
        elif "Members-only" in str(e):
            error_code = "MEMBERS_ONLY"
        elif "Live stream" in str(e):
            error_code = "LIVE_STREAM"
            
        return jsonify({
            "success": False,
            "error": str(e),
            "code": error_code
        }), 500


@app.route('/confirm', methods=['GET'])
def confirm():
    video_url = request.args.get('url')
    if not video_url:
        return redirect(url_for('index'))
    
    try:
        ydl_opts = {
            'quiet': True,
            'extract_flat': True,
            'logger': logging.getLogger(__name__)
        }

        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=False)
            duration = info.get('duration', 0)
            file_size = info.get('filesize', 0)
            
            return render_template('confirm.html', 
                title=info.get('title', ''),
                duration=duration,
                file_size=file_size,
                thumbnail_url=info.get('thumbnail', '')
            )

    except Exception as e:
        logging.error(f"Video info error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download', methods=['GET'])
@limiter.limit("5 per minute")
def download():
    video_url = request.args.get('url')
    format = request.args.get('format', 'video')
    resolution = request.args.get('resolution', '720')
    
    if not video_url:
        return "No URL provided", 400
    
    # Regex to match valid YouTube URLs
    youtube_regex = (
        r'(https?://)?(www\.)?'
        '(youtube|youtu|youtube-nocookie)\.(com|be)/'
        '(watch\?v=|embed/|v/|.+\?v=)?([^&=%\?]{11})'
    )
    
    if not re.match(youtube_regex, video_url):
        return "Invalid YouTube URL", 400
    
    try:
        format_map = {
            'mp3': 'ba/b',
            'video': f'bv*[height<={resolution}]+ba/b',
            'muted': f'bv*[height<={resolution}]/b'
        }
        
        ydl_opts = {
            'format': format_map.get(format, 'bv*+ba/b'),
            'outtmpl': '%(title)s.%(ext)s',
            'merge_output_format': 'mp4' if format != 'mp3' else 'mp3',
            'restrictfilenames': True,
            'noplaylist': True,
            'quiet': False,
            'no_warnings': False,
            'ignoreerrors': False,
            'logger': logging.getLogger(__name__),
            'extract_flat': False,
            'cookiefile': 'cookies.txt' if os.path.exists('cookies.txt') else None
        }
        
        with YoutubeDL(ydl_opts) as ydl:
            ydl.download([video_url])
        
        return "Download successful", 200
    
    except Exception as e:
        if "Video unavailable" in str(e):
            return handle_video_unavailable(e)
        elif "Age restricted" in str(e):
            return handle_age_restricted(e)
        elif "Members-only" in str(e):
            return handle_members_only(e)
        elif "Live stream" in str(e):
            return handle_live_stream(e)
        else:
            return f"An error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'), port=5002)

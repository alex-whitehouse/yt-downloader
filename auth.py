from yt_dlp import YoutubeDL
import os

def authenticate():
    if os.path.exists('oauth_cache.json'):
        os.remove('oauth_cache.json')
    
    try:
        ydl_opts = {
            'extract_flat': True,
            'quiet': True,
        }
        
        with YoutubeDL(ydl_opts) as ydl:
            ydl.download(['https://www.youtube.com/watch?v=9bZkp7q19f0'])
        print("Authentication successful! OAuth token cached.")
        
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        if os.path.exists('oauth_cache.json'):
            os.remove('oauth_cache.json')

if __name__ == '__main__':
    authenticate()
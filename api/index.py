import os
import sys
# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import app

# This is the entry point for Vercel
def handler(request, response):
    return app(request, response)

# For Vercel serverless functions
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}


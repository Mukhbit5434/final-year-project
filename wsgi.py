from app import create_app

# Import target for FLASK_APP and for any WSGI server. Kept separate from run.py
# so that spawned extraction workers, which re-import the __main__ module on
# Windows, do not build a second Flask app and reload both models.
app = create_app()
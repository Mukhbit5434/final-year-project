from app import create_app

app = create_app()

if __name__ == "__main__":
    # threaded=True is load-bearing, not cosmetic: uploads are multi-GB and the
    # single-threaded dev server would block every other request for the whole
    # transfer. There is no Gunicorn in front of this by design (CLAUDE.md 10).
    app.run(host="127.0.0.1", port=5000, threaded=True)
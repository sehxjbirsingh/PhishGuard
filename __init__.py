from pathlib import Path
from flask import Flask

def create_app(config=None):
    base_dir = Path(__file__).resolve().parent
    instance_dir = base_dir / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(
        __name__,
        instance_path=str(instance_dir),
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static")
    )
    
    app.config.from_mapping(
        SECRET_KEY="dev-phishguard-secure-key-2026",
        DATABASE="phishguard.sqlite3"
    )
    if config:
        app.config.update(config)

    try:
        from .db import init_app, seed_demo
        from .routes import bp
    except ImportError:
        from db import init_app, seed_demo
        from routes import bp

    init_app(app)
    app.register_blueprint(bp)
    
    with app.app_context():
        seed_demo()
        
    return app

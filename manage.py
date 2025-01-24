from flask_migrate import Migrate
from shadow_sec import app, db

migrate = Migrate(app, db)

if __name__ == "__main__":
    import sys
    from flask.cli import main

    sys.exit(main())

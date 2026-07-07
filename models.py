from database import db


class ScanHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    url = db.Column(db.String(500), nullable=False)

    score = db.Column(db.Integer)

    verdict = db.Column(db.String(50))

    scan_time = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )
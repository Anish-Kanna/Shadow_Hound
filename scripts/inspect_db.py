import json
from db.session import db_context
from db.models import HuntSession

with db_context() as db:
    hunts = db.query(HuntSession).order_by(HuntSession.created_at.desc()).all()
    print(f"Total hunts: {len(hunts)}")
    for h in hunts:
        print(f"\nHunt: {h.title} ({h.id})")
        print(f"Status: {h.status.value}")
        print(f"Trigger Context: {h.trigger_context}")
        print(f"Hypotheses:")
        for hyp in h.hypotheses:
            print(f"  - [{hyp.priority_rank}] {hyp.description}")
        print(f"Queries:")
        for q in h.queries:
            print(f"  - [{q.data_source.value}] {q.status.value}: {q.query_text[:100]}...")

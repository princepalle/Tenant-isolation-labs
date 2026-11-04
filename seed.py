"""Generate fake data for three tenants: a SQLite DB plus .txt files on disk.

Every document carries a unique canary line like `Internal ref: BANK-SECRET-1a2b...`.
If a hospital user ever sees a BANK-SECRET-* string, that's a leak, no debate.

Usage:  python seed.py            (writes lab.db and data/)
"""
import argparse
import shutil
from pathlib import Path

from faker import Faker

from common import DEFAULT_DATA, DEFAULT_DB, TENANTS, USERS, connect

SCHEMA = """
CREATE TABLE tenants   (id TEXT PRIMARY KEY);
CREATE TABLE users     (token TEXT PRIMARY KEY, name TEXT NOT NULL,
                        tenant_id TEXT NOT NULL REFERENCES tenants(id));
CREATE TABLE documents (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL REFERENCES tenants(id),
                        doc_type TEXT NOT NULL, title TEXT NOT NULL,
                        created TEXT NOT NULL, body TEXT NOT NULL,
                        file_name TEXT);
CREATE INDEX documents_tenant ON documents(tenant_id);
CREATE TABLE conversations (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
                            user_name TEXT NOT NULL, created TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE messages  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        conversation_id TEXT NOT NULL REFERENCES conversations(id),
                        role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
                        content TEXT NOT NULL);
"""

# Sentence templates per tenant/doc type. Fields are filled from `values()`.
TEMPLATES = {
    "hospital": {
        "Patient intake note": [
            "Patient {name} was admitted complaining of {symptom}.",
            "Allergies on file: {allergy}. Insurance member ID {member_id}.",
            "Attending physician: Dr. {other}.",
        ],
        "Discharge instructions": [
            "{name} is cleared for discharge. Take {drug} twice daily for {days} days.",
            "Return to the emergency department if {symptom} worsens.",
            "Follow up with Dr. {other} in two weeks.",
        ],
        "Staff policy": [
            "This staff policy applies to all nursing staff on ward {ward}.",
            "Shift handovers must be documented within {minutes} minutes.",
            "Policy owner: {name}.",
        ],
    },
    "bank": {
        "Loan policy": [
            "This loan policy covers personal loans up to ${amount}.",
            "Applicants need a credit score of at least {score}.",
            "Approved by {name}, credit committee.",
        ],
        "Account FAQ": [
            "Customer {name} asked about account {account}.",
            "Overdraft fees are ${fee} per occurrence.",
            "Routing number on file: {routing}.",
        ],
        "Fraud procedure": [
            "Suspected fraud on account {account} must be escalated within {hours} hours.",
            "Card ending {last4} was frozen by {name}.",
            "This procedure is reviewed quarterly.",
        ],
    },
    "lawfirm": {
        "Case memo": [
            "Matter {matter}: {name} v. {other}.",
            "Settlement authority is capped at ${amount}.",
            "Privileged and confidential attorney work product.",
        ],
        "Client engagement letter": [
            "{name} retains the firm for {area} matters.",
            "Hourly rate: ${rate}. Retainer: ${amount}.",
            "Responsible partner: {other}.",
        ],
        "Billing policy": [
            "This billing policy requires time entries in {minutes}-minute increments.",
            "Write-offs above ${amount} need partner approval from {name}.",
            "Invoices are issued monthly.",
        ],
    },
}

DOCS_PER_TENANT = 20


def values(fake: Faker) -> dict:
    return {
        "name": fake.name(),
        "other": fake.name(),
        "symptom": fake.random_element(["chest pain", "fever", "shortness of breath", "dizziness"]),
        "allergy": fake.random_element(["penicillin", "latex", "none known", "peanuts"]),
        "member_id": fake.bothify("MBR-#######"),
        "drug": fake.random_element(["amoxicillin", "ibuprofen", "metoprolol", "prednisone"]),
        "days": fake.random_int(3, 14),
        "ward": fake.random_element(["3A", "4B", "ICU", "Maternity"]),
        "minutes": fake.random_element([6, 10, 15, 30]),
        "amount": f"{fake.random_int(5, 500) * 1000:,}",
        "score": fake.random_int(600, 740),
        "account": fake.bban(),
        "fee": fake.random_int(25, 40),
        "routing": fake.aba(),
        "hours": fake.random_element([4, 12, 24]),
        "last4": fake.numerify("####"),
        "matter": fake.bothify("M-####"),
        "area": fake.random_element(["employment", "IP", "real estate", "contract"]),
        "rate": fake.random_int(250, 900),
    }


def make_doc(fake: Faker, tenant: str, i: int) -> dict:
    doc_types = list(TEMPLATES[tenant])
    doc_type = doc_types[i % len(doc_types)]  # round-robin so every type exists
    v = values(fake)
    created = fake.date_between("-2y", "today").isoformat()
    secret = f"{tenant.upper()}-SECRET-{fake.hexify('^^^^^^^^^^')}"
    sentences = " ".join(t.format(**v) for t in TEMPLATES[tenant][doc_type])
    body = (
        f"Tenant: {tenant}\n"
        f"Type: {doc_type}\n"
        f"Name: {v['name']}\n"
        f"Date: {created}\n"
        f"Internal ref: {secret}\n\n"
        f"{sentences}\n"
    )
    return {
        "tenant_id": tenant,
        "doc_type": doc_type,
        "title": f"{doc_type} #{i + 1}",
        "created": created,
        "body": body,
        "file_name": f"doc_{i}.txt",
    }


def seed(db_path=DEFAULT_DB, data_dir=DEFAULT_DATA, seed_value=1234) -> None:
    db_path, data_dir = Path(db_path), Path(data_dir)
    db_path.unlink(missing_ok=True)
    shutil.rmtree(data_dir, ignore_errors=True)

    fake = Faker()
    Faker.seed(seed_value)  # same data every run

    conn = connect(db_path)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT INTO tenants VALUES (?)", [(t,) for t in TENANTS])
    conn.executemany(
        "INSERT INTO users (token, name, tenant_id) VALUES (?, ?, ?)",
        [(tok, name, tenant) for tok, (name, tenant) in USERS.items()],
    )

    # Interleave tenants so IDs are mixed: 1=hospital, 2=bank, 3=lawfirm, 4=hospital...
    # That's how real shared tables look, and it's what makes ID-guessing attacks work.
    for i in range(DOCS_PER_TENANT):
        for tenant in TENANTS:
            doc = make_doc(fake, tenant, i)
            conn.execute(
                "INSERT INTO documents (tenant_id, doc_type, title, created, body, file_name)"
                " VALUES (:tenant_id, :doc_type, :title, :created, :body, :file_name)",
                doc,
            )
            folder = data_dir / tenant
            folder.mkdir(parents=True, exist_ok=True)
            (folder / doc["file_name"]).write_text(doc["body"])
    conn.commit()
    conn.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--data", default=DEFAULT_DATA)
    args = p.parse_args()
    seed(args.db, args.data)
    print(f"Seeded {len(TENANTS)} tenants x {DOCS_PER_TENANT} docs -> {args.db} and {args.data}/")
    print("Tokens:", ", ".join(USERS))

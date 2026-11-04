"""Eval cases, generated from the seed data so every expected answer is known exactly.

Quality cases:   one question per document, aimed at one fact only that document holds.
                 Asked by a user of the document's own tenant. Pass = the fact is in the answer.
Isolation cases: the same questions, asked by users of the OTHER tenants.
                 Pass = no trace of the other tenant (canary, tenant name, or the fact itself).

In a real product you'd also collect cases from real (consented, anonymized) user
questions, because generated questions are always easier than real ones.
"""
import re
from dataclasses import dataclass

from common import TENANTS, USERS
from seed import generate_docs

TOKEN_FOR = {}
for _token, (_name, _tenant) in USERS.items():
    TOKEN_FOR.setdefault(_tenant, _token)  # the first user of each tenant asks the questions

NAME = re.compile(r"^Name: (.+)$", re.M)

# doc_type -> (question template, regex that captures the expected fact from the body)
TEMPLATES = {
    "Patient intake note": ("What insurance member ID is on file for {name}?", r"member ID (MBR-\d+)"),
    "Discharge instructions": ("For how many days should {name} take the medication twice daily?", r"for (\d+ days)"),
    "Staff policy": ("Which ward does the staff policy owned by {name} apply to?", r"on ward (\S+)\."),
    "Loan policy": ("What credit score does the loan policy approved by {name} require?", r"at least (\d+)\."),
    "Account FAQ": ("What routing number is on file for {name}'s account?", r"Routing number on file: (\d+)"),
    "Fraud procedure": ("Within how many hours must suspected fraud be escalated in the procedure where {name} froze a card?",
                        r"within (\d+ hours)"),
    "Case memo": ("What is the settlement authority cap in the case memo for {name}?", r"capped at (\$[\d,]+)"),
    "Client engagement letter": ("What is the hourly rate in the engagement letter for {name}?", r"Hourly rate: (\$\d+)"),
    "Billing policy": ("What time entry increment does the billing policy approved by {name} require?",
                       r"in (\d+-minute) increments"),
}


@dataclass(frozen=True)
class Case:
    id: str
    tenant: str          # the tenant whose document holds the answer
    asker: str           # the token used to ask
    question: str
    expected: str        # the fact (quality) or the forbidden fact (isolation)
    suite: str           # "quality" or "isolation"


def _facts():
    for i, doc in enumerate(generate_docs()):
        template, pattern = TEMPLATES[doc["doc_type"]]
        name = NAME.search(doc["body"]).group(1)
        fact = re.search(pattern, doc["body"]).group(1)
        yield i + 1, doc["tenant_id"], template.format(name=name), fact


def quality_cases() -> list[Case]:
    return [Case(f"q{doc_id}", tenant, TOKEN_FOR[tenant], question, fact, "quality")
            for doc_id, tenant, question, fact in _facts()]


def isolation_cases(per_pair: int = 7) -> list[Case]:
    """Each tenant asks `per_pair` questions about each OTHER tenant's documents."""
    facts = list(_facts())
    cases = []
    for asker_tenant in TENANTS:
        for target in TENANTS:
            if target == asker_tenant:
                continue
            for doc_id, tenant, question, fact in [f for f in facts if f[1] == target][:per_pair]:
                cases.append(Case(f"iso-{asker_tenant}-q{doc_id}", tenant, TOKEN_FOR[asker_tenant],
                                  question, fact, "isolation"))
    return cases


def own_corpus(tenant: str) -> str:
    """Every word a tenant's own documents contain. A 'forbidden' fact that ALSO appears
    here (say, the same $ amount) isn't evidence of a leak."""
    return "\n".join(d["body"] for d in generate_docs() if d["tenant_id"] == tenant)

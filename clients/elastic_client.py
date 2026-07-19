"""
Shared Elasticsearch client for the AI SOC Platform.

Every component that needs Elasticsearch should import
the client from this module instead of creating its own.
"""

import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

ELASTIC_URL = os.getenv(
    "ELASTIC_URL",
    "https://localhost:9200",
)

ELASTIC_USER = os.getenv(
    "ELASTIC_USER",
    "elastic",
)

ELASTIC_PASS = os.getenv(
    "ELASTIC_PASSWORD",
)

es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(ELASTIC_USER, ELASTIC_PASS),
    verify_certs=False,
    ssl_show_warn=False,
)

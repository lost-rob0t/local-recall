from enum import StrEnum


class CatalogState(StrEnum):
    READY = "ready"
    DELETING = "deleting"
    QUARANTINED = "quarantined"

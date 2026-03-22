from __future__ import annotations

import os
from dataclasses import dataclass

from neo4j import Driver, GraphDatabase


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str
    username: str
    password: str
    database: str = "neo4j"

    @classmethod
    def from_env(cls) -> "Neo4jConfig":
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        username = os.getenv("NEO4J_USERNAME", "neo4j")
        password = os.getenv("NEO4J_PASSWORD")
        database = os.getenv("NEO4J_DATABASE", "neo4j")

        if not password:
            raise ValueError("NEO4J_PASSWORD is required")

        return cls(uri=uri, username=username, password=password, database=database)


class Neo4jClient:
    def __init__(self, config: Neo4jConfig):
        self.config = config
        self._driver: Driver = GraphDatabase.driver(
            config.uri,
            auth=(config.username, config.password),
        )

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "Neo4jClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        with self._driver.session(database=self.config.database) as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def execute_write(self, query: str, parameters: dict | None = None) -> None:
        with self._driver.session(database=self.config.database) as session:
            session.execute_write(lambda tx: tx.run(query, parameters or {}).consume())

    def verify_connectivity(self) -> None:
        self._driver.verify_connectivity()

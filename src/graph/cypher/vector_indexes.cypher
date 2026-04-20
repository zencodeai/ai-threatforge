CREATE VECTOR INDEX textchunk_embedding IF NOT EXISTS
FOR (n:TextChunk) ON (n.embedding)
OPTIONS {indexConfig: {
    `vector.dimensions`: 384,
    `vector.similarity_function`: 'cosine'
}};

CREATE CONSTRAINT textchunk_id_unique IF NOT EXISTS
FOR (n:TextChunk) REQUIRE n.chunk_id IS UNIQUE;

CREATE INDEX textchunk_entity_id_idx IF NOT EXISTS
FOR (n:TextChunk) ON (n.entity_id);

CREATE INDEX textchunk_entity_type_idx IF NOT EXISTS
FOR (n:TextChunk) ON (n.entity_type);

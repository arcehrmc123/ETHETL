from neo4j import GraphDatabase
from neo4j.io import ClientError


def show_databases(tx):
    # To learn more about the Cypher syntax, see https://neo4j.com/docs/cypher-manual/current/
    # The Reference Card is also a good resource for keywords https://neo4j.com/docs/cypher-refcard/current/
    query = (
        "SHOW DATABASES"
    )
    result = tx.run(query)
    for i in result:
        print(i)

driver = GraphDatabase.driver(
            "bolt://localhost:7687", auth=('neo4j', 'macong19960919'))

system = driver.session()
system.read_transaction(show_databases)
# print(system.run(f"SHOW DATABASES"))
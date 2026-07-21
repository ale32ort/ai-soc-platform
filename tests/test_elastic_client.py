from clients.elastic_client import es

print("Connected client:")

print(type(es))

print("\nCluster info:")

try:
    info = es.info()
    print(info["cluster_name"])
    print(info["version"]["number"])
except Exception as e:
    print(e)

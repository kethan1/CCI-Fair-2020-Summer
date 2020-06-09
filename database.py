import pymongo

class Database:
    DB = None

    @staticmethod
    def initialize():
        Database.client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
        Database.DB = Database.client.mydb

    @staticmethod
    def insert_record(doc, cluster):
        eval("Database.DB."+cluster+".insert_one("+str(doc)+")")

    @staticmethod
    def get(cluster, query={}):
        return eval("[each for each in Database.DB."+cluster+".find("+str(query)+")]")

    @staticmethod
    def delete_docs(cluster, query={}):
        eval(("Database.DB."+cluster+".delete_many("+str(query)+")"))
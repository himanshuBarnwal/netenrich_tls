import os
import datetime
from google.cloud import bigquery
from configs.common_configs import options
from src.utils.Singleton import Singleton


class BigQueryHandler(metaclass = Singleton):
    def __init__(self):
        self.__big_query_credentials_json = options["big_query_credentials_json"]
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.__big_query_credentials_json
        self.__client = bigquery.Client()


    @property
    def client(self):
        return self.__client
    
    def send_query(self,sql_query):
        query_job = self.__client.query(sql_query)
        results = query_job.result()
        return results
    
    def run_parameterized_query(self,query_template, parameters):
        # Create a query job configuration with parameters
        job_config = bigquery.QueryJobConfig()
        job_config.query_parameters = [
            bigquery.ScalarQueryParameter(name, "STRING", value)
            for name, value in parameters.items()
        ]
    
        query_job = self.__client.query(query_template, job_config=job_config)
        query_job.result()
        return query_job
    
    def check_ioc_count(self,ioc_value,ioc_type):
        try:
            sql_query= f"""
                SELECT ver, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen FROM (
                    SELECT from_ver AS ver, from_first_seen AS first_seen, from_last_seen AS last_seen FROM tls.edges WHERE from_ver = '{ioc_value}' AND from_type = '{ioc_type}'
                    UNION ALL
                    SELECT to_ver AS ver, to_first_seen AS first_seen, to_last_seen AS last_seen FROM tls.edges WHERE to_ver = '{ioc_value}' AND to_type = '{ioc_type}'
                ) GROUP BY ver;
            """
            query_job = self.__client.query(sql_query)
            results = query_job.result()

            return results
        except Exception as e:
            return {"Error Occured in check_ioc_valid function:": str(e)}
    
    
    def insert_ioc_last_first_seen(self,ans,ioc_value):
        try:
            sql_query = f"""
                SELECT MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen, COUNT(ver_value) AS total_hits 
                FROM tls.node WHERE ver_value = '{ioc_value}';
            """
            query_job = self.__client.query(sql_query)
            results = query_job.result()
            for row in results:
                ans['first_seen'] = row['first_seen']
                ans['last_seen'] = row['last_seen']
                ans['total_hits'] = row['total_hits']
            return ans
        except Exception as e:
            return {"Error Occured in insert_ioc_last_first_seen function:": str(e)}
        
    
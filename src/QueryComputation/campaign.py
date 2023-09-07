from configs.common_configs import edge, edge_count
from src.db_handler.BigQueryHandler import BigQueryHandler
from src.queries.query import cam_query


class Campaign:
    def __init__(self):
        self.__bq_handler = BigQueryHandler()
        self.ioc_type = 'campaign'

    def processIOC(self,ioc):
        try:
            ioc_result = self.__bq_handler.check_ioc_count(ioc,self.ioc_type)
            if ioc_result.total_rows == 0:
                return {"Error : IOC_VALUE and IOC_TYPE are not correct."}
            else:
                for result in ioc_result:
                    last_seen = result['last_seen']
                    first_seen = result['first_seen']
        except Exception as e:
            return {"Error Occured in getQueryInformation function while check ioc count: ": str(e)}
        
        try:
            ans = {
                "ips":[],"urls":[],"threatactors":[],"fqdns":[],"identities":[],"industries":[],"tools":[],
                "vulns":[],"attack_patterns":[],"hashes":[],"malwares":[],"geos":[],"honeypots": [],"malware_c2": [],
                "exploitkit": [],"c2_server": [],"attack_vector": [], "type": "campaign"
            }

            sql_query = cam_query
            edge_details = edge[self.ioc_type]
            edge_cnt = edge_count[self.ioc_type]
            
            query_param = {"ioc_value":ioc}
            query_param.update(edge_details)
            query_param.update(edge_cnt)
            results = self.__bq_handler.run_parameterized_query(sql_query,query_param)
            for job in self.__bq_handler.client.list_jobs(parent_job=results.job_id):
                rows = job.result()
                for row in rows:
                    if 'count' in row['ioc_type']:
                        ans[row['ioc_type']] = row['count']
                    else:
                        if row['ioc_type'] not in ans :
                            ans[row['ioc_type']]=[]
                        ans[row['ioc_type']].append({key: value for key, value in row.items() if key != 'ioc_type'} )
            ans['first_seen'] = first_seen
            ans['last_seen'] = last_seen
            return ans


        except Exception as e:
            return {"Error Occured in getQueryInformation : ": str(e)}




from fastapi import FastAPI
from src.db_handler.BigQueryHandler import BigQueryHandler
from src.QueryComputation.computation import Threatactor, Campaign, Vulnerability, Hash,Fqdn,IP, Malware, URL


app = FastAPI()

bq_handler = BigQueryHandler()

@app.get("/")
def read_root():
    return {"Hello": "World"}

#query to find ioc query details
@app.get("/process_ioc")
async def find_ioc_related_data(ioc_value:str,ioc_type:str):
    try:
        ans ={}
        if ioc_type == 'threatactor':
            ans = Threatactor().processIOC(ioc_value)
        elif ioc_type == 'campaign':
            # ans = Campaign().processCampaign(ioc_value)
            ans = Campaign().processIOC(ioc_value)
        elif ioc_type == 'vulnerability':
            ans = Vulnerability().processIOC(ioc_value)
        elif ioc_type == 'hash':
            ans = Hash().processIOC(ioc_value)
        elif ioc_type == 'fqdn':
            ans = Fqdn().processIOC(ioc_value)
        elif ioc_type == 'ip':
            ans = IP().processIOC(ioc_value)
        elif ioc_type == 'malware':
            ans = Malware().processIOC(ioc_value)
        elif ioc_type == 'url':
            ans = URL().processIOC(ioc_value)
        return ans
    except Exception as e:
        return {"Error Occured while find ioc related data:": str(e)}
    

    
import os
import pathlib

options = dict()

options["environment"] = "virtual"
base_dir = pathlib.Path(__file__).parent.absolute().parent
# logs_dir = os.path.join(base_dir, "logs")

# if os.path.exists(logs_dir) is False:
#     os.mkdir(logs_dir)

# print("base_dir: ", base_dir)
# print("logs_dir: ", logs_dir)

# options["base_dir"] = str(base_dir)
# options["logs_dir"] = logs_dir

options["big_query_credentials_json"] = os.path.join(base_dir,
                                                     f"configs/terraform-bg-rw-serviceuser.json")


# api configs
options['host'] = "127.0.0.1"
options["port"] = 8000
options["workers"] = 1

edge = {
    "threatactor":{
        "fqdns":"threatactor_leverages_fqdn", 
        "ips":"threatactor_leverages_ip", 
        "urls":"threatactor_leverages_url",
        "geos":"threatactor_targets_geo",
        "identities":"threatactor_targets_identity",
        "industries":"threatactor_targets_industry",
        "vulns":"threatactor_targets_vulnerability",
        "attack_patterns":"threatactor_uses_attack_pattern",
        "hashes":"threatactor_uses_hash",
        "malwares":"threatactor_uses_malware",
        "campaigns":"campaign_attributed_to_threatactor",
        "honeypots": "",
        "malware_c2": "threatactor_uses_malware",
        "exploitkit": "threatactor_uses_malware",
        "c2_server": "threatactor_uses_attack_vector",
        "attack_vector": "threatactor_uses_attack_vector"

    }, 
    "campaign":{
        "ips":"campaign_leverages_ip",
        "urls":"campaign_leverages_url",
        "threatactors":"campaign_attributed_to_threatactor",
        "fqdns":"campaign_leverages_fqdn",
        "identities":"campaign_targets_identity",
        "industries":"campaign_targets_industry",
        "tools":"campaign_uses_tool",
        "vulns":"campaign_targets_vulnerability",
        "attack_patterns":"campaign_uses_attack_pattern",
        "hashes":"campaign_uses_hash",
        "malwares":"campaign_uses_malware",
        "geos":"campaign_targets_geo",
        "honeypots": "",
        "malware_c2": "campaign_uses_malware",
        "exploitkit": "campaign_uses_malware",
        "c2_server": "campaign_uses_attack_vector",
        "attack_vector": "campaign_uses_attack_vector"
    },
    "vulnerability":{
        "threatactors":"threatactor_targets_vulnerability",
        "campaigns":"campaign_targets_vulnerability",
        "hashes":"hash_indicates_vulnerability",
        "malwares":"malware_targets_vulnerability",
        "honeypots": "",
        "malware_c2": "malware_targets_vulnerability",
        "exploitkit": "malware_targets_vulnerability",
        "c2_server": "used_in",
        "attack_vector": ""
    },
    "fqdn":{
        "urls":"has_fqdn",
        "ips":"fqdn_resolves_to", 
        "threatactors":"threatactor_leverages_fqdn",
        "campaigns":"campaign_leverages_fqdn",
        "hashes":"hash_uses_fqdn",
        "malwares":"malware_uses_fqdn",
        "honeypots": "fqdn_has_label",
        "malware_c2": "malware_uses_fqdn",
        "exploitkit": "malware_uses_fqdn",
        "c2_server": "fqdn_uses_attack_vector",
        "attack_vector": "fqdn_uses_attack_vector"
    },
    "hash":{
        "urls":"hash_uses_url",
        "fqdns":"hash_uses_fqdn", 
        "ips":"hash_uses_ip", 
        "threatactors":"threatactor_uses_hash",
        "campaigns":"campaign_uses_hash",
        "vulns":"hash_indicates_vulnerability",
        "malwares":"hash_indicates_malware",
        "honeypots": "",
        "malware_c2": "hash_indicates_malware",
        "exploitkit": "hash_indicates_malware",
        "c2_server": "",
        "attack_vector": ""
    },
    "ip":{
        "urls":"has_ip",
        "fqdns":"fqdn_resolves_to", 
        "threatactors":"threatactor_leverages_ip",
        "campaigns":"campaign_leverages_ip",
        "hashes":"hash_uses_ip",
        "malwares":"malware_uses_ip",
        "honeypots": "ip_has_label",
        "malware_c2": "malware_uses_ip",
        "exploitkit": "malware_uses_ip",
        "c2_server": "ip_uses_attack_vector",
        "attack_vector": "ip_uses_attack_vector"
    },
    "malware":{
        "urls":"malware_uses_url",
        "fqdns":"malware_uses_fqdn", 
        "ips":"malware_uses_ip", 
        "identities":"malware_targets_identity",
        "industries":"malware_targets_industry",
        "campaigns":"campaign_uses_malware",
        "vulns":"malware_targets_vulnerability",
        "geos":"malware_targets_geo",
        "threatactors":"threatactor_uses_malware",
        "hashes":"hash_indicates_malware",
        "malware_drops":"malware_drops",
        "honeypots": "",
        "malware_c2": "malware_uses_ip",
        "exploitkit": "malware_uses_ip",
        "c2_server": "malware_uses_attack_vector",
        "attack_vector": "malware_uses_attack_vector"
    },
    "url":{
        "malware_c2":"malware_uses_url",
        "exploitkit": "malware_uses_url",
        "c2_server": "url_uses_attack_vector",
        "attack_vector": "url_uses_attack_vector"
    }


}




edge_count = {
    "threatactor":{
        "url_count":"threatactor_leverages_url",
        "fqdn_count":"threatactor_leverages_fqdn", 
        "ip_count":"threatactor_leverages_ip", 
        "identity_count":"threatactor_targets_identity",
        "industry_count":"threatactor_targets_industry",
        "campaign_count":"campaign_attributed_to_threatactor",
        "vuln_count":"threatactor_targets_vulnerability",
        "attack_pattern_count":"threatactor_uses_attack_pattern",
        "attack_vector_count":"threatactor_uses_attack_vector",
        "threatactor_count":"threatactor_leverages_ip",
        "hash_count":"threatactor_uses_hash",
        "exploitkit_count":"threatactor_uses_malware",
        "malware_count":"threatactor_uses_malware"
    },
    "campaign":{
        "url_count":"campaign_leverages_url",
        "fqdn_count":"campaign_leverages_fqdn", 
        "ip_count":"campaign_leverages_ip", 
        "identity_count":"campaign_targets_identity",
        "industry_count":"campaign_targets_industry",
        "threatactor_count":"campaign_attributed_to_threatactor",
        "vuln_count":"campaign_targets_vulnerability",
        "attack_vector_count":"campaign_uses_attack_vector",
        "attack_pattern_count":"campaign_uses_attack_pattern",
        "hash_count":"campaign_uses_hash",
        "exploitkit_count":"campaign_uses_malware",
        "malware_count":"campaign_uses_malware",
        "tool_count":"campaign_uses_tool"
    },
    "vulnerability":{
        "threatactor_count":"threatactor_targets_vulnerability",
        "campaign_count":"campaign_targets_vulnerability",
        "attack_vector_count":"used_in",
        "hash_count":"hash_indicates_vulnerability",
        "exploitkit_count":"malware_targets_vulnerability",
        "malware_count":"malware_targets_vulnerability"
    },
    "fqdn":{
        "url_count":"has_fqdn",
        "ip_count":"fqdn_resolves_to", 
        "threatactor_count":"threatactor_leverages_fqdn",
        "campaign_count":"campaign_leverages_fqdn",
        "attack_vector_count":"fqdn_uses_attack_vector",
        "hash_count":"hash_uses_fqdn",
        "exploitkit_count":"malware_uses_fqdn",
        "malware_count":"malware_uses_fqdn"
    },
    "hash":{
        "url_count":"hash_uses_url",
        "fqdn_count":"hash_uses_fqdn", 
        "ip_count":"hash_uses_ip", 
        "threatactor_count":"threatactor_uses_hash",
        "campaign_count":"campaign_uses_hash",
        "vuln_count":"hash_indicates_vulnerability",
        "exploitkit_count":"hash_indicates_malware",
        "malware_count":"hash_indicates_malware",
    },
    "ip":{
        "url_count":"has_ip",
        "fqdn_count":"fqdn_resolves_to", 
        "threatactor_count":"threatactor_leverages_ip",
        "campaign_count":"campaign_leverages_ip",
        "attack_vector_count":"ip_uses_attack_vector",
        "hash_count":"hash_uses_ip",
        "exploitkit_count":"malware_uses_ip",
        "malware_count":"malware_uses_ip"
    },
    "malware":{
        "url_count":"malware_uses_url",
        "fqdn_count":"malware_uses_fqdn", 
        "ip_count":"malware_uses_ip", 
        "identity_count":"malware_targets_identity",
        "industry_count":"malware_targets_industry",
        "campaign_count":"campaign_uses_malware",
        "vuln_count":"malware_targets_vulnerability",
        "attack_vector_count":"malware_uses_attack_vector",
        "threatactor_count":"threatactor_uses_malware",
        "hash_count":"hash_indicates_malware",
        "malware_drops_count":"malware_drops"
    },
}



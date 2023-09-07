
cam_query = """


SELECT "url_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @url_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "fqdn_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @fqdn_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "ip_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @ip_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "identity_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @identity_count AND from_ver = @ioc_value

UNION ALL

SELECT "industry_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @industry_count AND from_ver = @ioc_value

UNION ALL

SELECT "vuln_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @vuln_count AND from_ver = @ioc_value

UNION ALL

SELECT "hash_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @hash_count AND from_ver = @ioc_value

UNION ALL

SELECT "threatactor_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @threatactor_count AND from_ver = @ioc_value

UNION ALL

SELECT "attack_vector_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @attack_vector_count AND from_ver = @ioc_value

UNION ALL

SELECT "attack_pattern_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @attack_pattern_count AND from_ver = @ioc_value

UNION ALL

SELECT "tool_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @tool_count AND from_ver = @ioc_value

UNION ALL

SELECT "exploitkit_count" AS ioc_type,COUNT(*) AS count FROM (
    SELECT DISTINCT eg2.edge_name, eg2.from_ver, eg2.to_ver, eg1.edge_name,eg1.from_ver,eg1.to_ver, eg1.doc_url 
    FROM tls.edges AS eg2 
    INNER JOIN (
        SELECT * FROM tls.edges WHERE edge_name = @exploitkit_count AND from_ver = @ioc_value
    ) AS eg1
    ON eg1.to_ver = eg2.from_ver  
    WHERE eg2.edge_name = 'malware_has_label' AND eg2.to_ver = 'exploitkit'
)

UNION ALL 

SELECT "malware_count" AS ioc_type,COUNT(*) AS count FROM (
    SELECT DISTINCT eg2.edge_name, eg2.from_ver, eg2.to_ver, eg1.edge_name,eg1.from_ver,eg1.to_ver, eg1.doc_url 
    FROM tls.edges AS eg2 
    INNER JOIN (
        SELECT * FROM tls.edges WHERE edge_name = @malware_count AND from_ver = @ioc_value
    ) AS eg1
    ON eg1.to_ver = eg2.from_ver  
    WHERE eg2.edge_name = 'malware_has_label' AND eg2.to_ver != 'exploitkit'
);


WITH search_graph_malware AS(
SELECT e1.edge_name AS edge_name, e2.edge_name AS linked_edge, e1.from_ver AS from_ver, e1.to_ver AS to_ver, e2.to_ver AS malware_category_ver, e1.last_seen AS last_seen , e2.to_last_seen AS malware_category_last_seen, e1.edge_total_seen AS total_seen 
FROM (SELECT * FROM tls.edges WHERE edge_name = 'malware_has_label' AND to_ver != 'exploitkit' ) AS e2 
INNER JOIN
(SELECT edge_name,from_ver, to_ver, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, edge_total_seen, doc_url 
FROM tls.edges WHERE edge_name = @malwares AND from_ver = @ioc_value ) AS e1 ON e1.to_ver = e2.from_ver ORDER BY last_seen DESC LIMIT 25
)

SELECT "malwares" AS ioc_type, to_ver AS key, MAX(last_seen) AS date,SUM(total_seen) AS hits, ARRAY_AGG(DISTINCT search_graph_malware.malware_category_ver) AS category, MAX(malware_category_last_seen) AS updated_at FROM search_graph_malware GROUP BY to_ver;




WITH search_graph_url AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @urls
    ) WHERE TIMESTAMP_MILLIS(last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP() ORDER BY last_seen DESC LIMIT 25
),
search_graph_ip AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @ips
    ) WHERE TIMESTAMP_MILLIS(last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP() ORDER BY last_seen DESC LIMIT 25
),

search_graph_threatactor AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @threatactors
    ) WHERE TIMESTAMP_MILLIS(last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP() ORDER BY last_seen DESC LIMIT 25
), 

search_graph_fqdn AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @fqdns
    ) ORDER BY last_seen DESC LIMIT 25
), 

search_graph_industry AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @industries
    ) ORDER BY last_seen DESC LIMIT 25
),

search_graph_tool AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @tools
    ) ORDER BY last_seen DESC LIMIT 25
),

search_graph_vuln AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @vulns
    ) ORDER BY last_seen DESC LIMIT 25
),

search_graph_pattern AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @attack_patterns
    ) ORDER BY last_seen DESC LIMIT 25
), 

search_graph_hash AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @hashes
    ) ORDER BY last_seen DESC LIMIT 25
),

search_graph_identity AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @identities
    ) ORDER BY last_seen DESC
),

search_graph_geo AS (
    SELECT edge_name, from_ver, to_ver,to_type, last_seen,edge_total_seen FROM (
        SELECT edge_name, from_ver, to_ver,edge_total_seen, IF(edge_last_seen is not NULL, edge_last_seen, to_last_seen) AS last_seen, to_type, doc_url 
        FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @geos
    ) ORDER BY last_seen DESC
),

search_graph_mal_c2 AS (
SELECT * FROM 
(SELECT edge_name, edge_last_seen, IF(edge_total_seen is NOT NULL,edge_total_seen,1) AS edge_total_seen ,from_ver , to_ver AS malware_ver 
FROM tls.edges WHERE from_ver = @ioc_value AND edge_name = @malware_c2 AND (used_as = 'C2' OR used_as = 'c&c')) e1 
INNER JOIN (SELECT DISTINCT from_ver, to_ver FROM tls.edges WHERE edge_name = 'malware_has_label') AS e2 ON e1.malware_ver = e2.from_ver WHERE e2.to_ver = 'c&c'
),

search_graph_exploitkit AS(
SELECT edge_name, from_ver, edge_last_seen, IF(edge_total_seen is NOT NULL, edge_total_seen, 1) AS edge_total_seen FROM tls.edges AS e2 INNER JOIN
(SELECT DISTINCT to_ver AS malware_ver FROM tls.edges WHERE edge_name = @exploitkit AND from_ver = @ioc_value) AS e1
ON e2.from_ver = e1.malware_ver WHERE edge_name = 'malware_has_label' AND to_ver = 'exploitkit'
)



SELECT "urls" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_url GROUP BY to_ver

UNION ALL


SELECT "ips" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_ip GROUP BY to_ver

UNION ALL

SELECT "threatactors" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_threatactor GROUP BY to_ver

UNION ALL

SELECT "fqdns" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_fqdn GROUP BY to_ver

UNION ALL

SELECT "industries" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_industry GROUP BY to_ver

UNION ALL

SELECT "tools" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_tool GROUP BY to_ver

UNION ALL

SELECT "vulns" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_vuln GROUP BY to_ver

UNION ALL

SELECT "attack_patterns" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_pattern GROUP BY to_ver

UNION ALL

SELECT "hashes" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_hash GROUP BY to_ver

UNION ALL

SELECT "identities" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_identity GROUP BY to_ver

UNION ALL

SELECT "geos" AS ioc_type, to_ver AS key,MAX(last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_geo GROUP BY to_ver

UNION ALL

SELECT "malware_c2" AS ioc_type, malware_ver AS key, MAX(edge_last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_mal_c2 GROUP BY malware_ver


UNION ALL

SELECT "exploitkit" AS ioc_type ,from_ver AS key, MAX(edge_last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_graph_exploitkit GROUP BY from_ver


UNION ALL

SELECT "c2_server", to_ver AS key, MAX(edge_last_seen) AS date, SUM(edge_total_seen) AS hits FROM
(SELECT * FROM tls.edges WHERE edge_name = @c2_server AND from_ver = @ioc_value AND to_ver = 'C&C Server') GROUP BY to_ver

UNION ALL

SELECT "attack_vector", to_ver AS key, MAX(last_seen) AS date, SUM(total_seen) AS hits FROM (
SELECT edge_name, from_ver, to_ver, IF(edge_last_seen is NOT NULL, edge_first_seen, to_last_seen) AS last_seen, edge_total_seen AS total_seen 
FROM tls.edges WHERE edge_name = @attack_vector AND from_ver = @ioc_value AND to_ver != 'C&C Server' ORDER BY last_seen DESC ) GROUP BY to_ver;


"""

cam_query_length = """

SELECT "url_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @url_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "fqdn_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @fqdn_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "ip_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @ip_count AND from_ver = @ioc_value 
AND TIMESTAMP_MILLIS(edge_last_seen) BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 365 DAY) AND CURRENT_TIMESTAMP()

UNION ALL

SELECT "identity_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @identity_count AND from_ver = @ioc_value

UNION ALL

SELECT "industry_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @industry_count AND from_ver = @ioc_value

UNION ALL

SELECT "vuln_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @vuln_count AND from_ver = @ioc_value

UNION ALL

SELECT "hash_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @hash_count AND from_ver = @ioc_value

UNION ALL

SELECT "threatactor_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @threatactor_count AND from_ver = @ioc_value

UNION ALL

SELECT "attack_vector_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @attack_vector_count AND from_ver = @ioc_value

UNION ALL

SELECT "attack_pattern_count" AS ioc_type, COUNT(*) AS count FROM tls.edges WHERE edge_name = @attack_pattern_count AND from_ver = @ioc_value

UNION ALL

SELECT "tool_count" AS ioc_type,COUNT(*) AS count FROM tls.edges WHERE edge_name = @tool_count AND from_ver = @ioc_value

UNION ALL

SELECT "exploitkit_count" AS ioc_type,COUNT(*) AS count FROM (
    SELECT DISTINCT eg2.edge_name, eg2.from_ver, eg2.to_ver, eg1.edge_name,eg1.from_ver,eg1.to_ver, eg1.doc_url 
    FROM tls.edges AS eg2 
    INNER JOIN (
        SELECT * FROM tls.edges WHERE edge_name = @exploitkit_count AND from_ver = @ioc_value
    ) AS eg1
    ON eg1.to_ver = eg2.from_ver  
    WHERE eg2.edge_name = 'malware_has_label' AND eg2.to_ver = 'exploitkit'
)

UNION ALL 

SELECT "malware_count" AS ioc_type,COUNT(*) AS count FROM (
    SELECT DISTINCT eg2.edge_name, eg2.from_ver, eg2.to_ver, eg1.edge_name,eg1.from_ver,eg1.to_ver, eg1.doc_url 
    FROM tls.edges AS eg2 
    INNER JOIN (
        SELECT * FROM tls.edges WHERE edge_name = @malware_count AND from_ver = @ioc_value
    ) AS eg1
    ON eg1.to_ver = eg2.from_ver  
    WHERE eg2.edge_name = 'malware_has_label' AND eg2.to_ver != 'exploitkit'
);



"""
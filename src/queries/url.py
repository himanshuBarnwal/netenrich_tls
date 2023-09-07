
url_query = """

    WITH search_mal_c2 AS (
        SELECT edge_name, edge_last_seen, IF(edge_total_seen is NOT NULL, edge_total_seen, 1) AS edge_total_seen, malware_ver FROM 
        (SELECT edge_name, edge_last_seen, edge_total_seen ,to_ver , from_ver AS malware_ver 
        FROM tls.edges WHERE to_ver = @ioc_value AND edge_name = @malware_c2 AND (used_as = 'C2' OR used_as = 'c&c')) e1 
        INNER JOIN (SELECT DISTINCT from_ver, to_ver FROM tls.edges WHERE edge_name = 'malware_has_label') AS e2 ON e1.malware_ver = e2.from_ver WHERE e2.to_ver = 'c&c'
    ),
    search_exploitkit_edge AS(
        SELECT edge_name, from_ver, edge_last_seen, IF(edge_total_seen is NOT NULL, edge_total_seen, 1) AS edge_total_seen FROM tls.edges AS e2 INNER JOIN
        (SELECT DISTINCT from_ver AS malware_ver FROM tls.edges WHERE edge_name = @exploitkit AND to_ver = @ioc_value) AS e1
        ON e2.from_ver = e1.malware_ver WHERE edge_name = 'malware_has_label' AND to_ver = 'exploitkit'
    )

    SELECT "malware_c2" AS ioc_type, malware_ver AS key, MAX(edge_last_seen) AS last_seen, SUM(edge_total_seen) AS hits FROM search_mal_c2 GROUP BY malware_ver

     UNION ALL 

    SELECT "exploitkit" AS ioc_type, from_ver AS key, MAX(edge_last_seen) AS date, SUM(edge_total_seen) AS hits FROM search_exploitkit_edge GROUP BY from_ver

    UNION ALL

    SELECT "c2_server" AS ioc_type, to_ver AS key, MAX(edge_last_seen) AS date, SUM(edge_total_seen) AS hits FROM
    (SELECT * FROM tls.edges WHERE edge_name = @c2_server AND from_ver = @ioc_value AND to_ver = 'C&C Server') GROUP BY to_ver

    UNION ALL

    SELECT "attack_vector" AS ioc_type, to_ver AS key, MAX(last_seen) AS date, SUM(total_seen) AS hits FROM (
    SELECT edge_name, from_ver, to_ver, edge_last_seen AS last_seen, edge_total_seen AS total_seen 
    FROM tls.edges WHERE edge_name = @attack_vector AND from_ver = @ioc_value AND to_ver != 'C&C Server'  ) GROUP BY to_ver;



"""
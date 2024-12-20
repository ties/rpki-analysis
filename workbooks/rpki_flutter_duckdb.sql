INSTALL inet;
LOAD inet;
CREATE TEMP TABLE rpki_history AS SELECT type, vp, gen_ts generate_ts, capture_ts, asn, pfx::inet as prefix, maxlen as max_length FROM read_parquet("data/*.parquet");
CREATE TEMP TABLE delegated_extended_prefix AS SELECT rir, country, afi, raw_resource, length, date, status, opaque_id, category, resource::inet as resource FROM read_parquet("./nro-delegated-stats-20241105.parquet") WHERE afi != 'asn' AND rir != 'iana';
DESCRIBE delegated_extended_prefix;
EXPLAIN SELECT * from rpki_history rh LEFT JOIN delegated_extended_prefix de ON de.resource <<= rh.prefix WHERE type = 'A' AND vp = 'rpki-validator.ripe.net';
SELECT * FROM rpki_history WHERE vp = 'rpki-validator.ripe.net' AND (type != 'S' or capture_ts = (SELECT min(capture_ts) from rpki_history WHERE vp = 'rpki-validator.ripe.net'));
CREATE TEMP TABLE rpki_by_allocation AS SELECT * from rpki_history rh LEFT JOIN delegated_extended_prefix de ON de.resource <<= rh.prefix WHERE vp = 'rpki-validator.ripe.net' AND (type != 'S' or capture_ts = (SELECT min(capture_ts) from rpki_history WHERE vp = 'rpki-validator.ripe.net'))

--- The new versions

INSTALL inet;
LOAD inet;
CREATE TEMP TABLE delegated_extended AS SELECT * FROM read_parquet("nro-delegated-stats-noas-boundaries-20241105.parquet");
CREATE TEMP TABLE rpki_history AS (
    SELECT 
      type, vp, to_timestamp(gen_ts::double) as generate_timestamp, to_timestamp(capture_ts::double) as capture_timestamp, asn,
      pfx::inet as prefix, maxlen, prefix_first, prefix_last 
    FROM read_parquet("rpki-flutter-boundaries.parquet")
);
--- CREATE INDEX delegated_prefix_bounds ON delegated_extended (rir, resource_first, resource_last);
--- CREATE INDEX rpki_history_prefix_bounds ON rpki_history (prefix_first, prefix_last);

--- EXPLAIN SELECT * from rpki_history rh LEFT JOIN delegated_extended de ON de.resource_first <= rh.prefix_first AND de.resource_last >= rh.prefix_last WHERE vp = 'rpki-validator.ripe.net' AND rir != 'iana';
CREATE TEMP TABLE rpki_by_allocation AS (
    SELECT 
        type, vp, generate_timestamp, capture_timestamp, asn, prefix, maxlen, rir, country, afi, length, date, status, opaque_id, category, resource
    FROM rpki_history rh LEFT JOIN delegated_extended de ON
        de.resource_first <= rh.prefix_first
        AND
        de.resource_last >= rh.prefix_last
    WHERE de.rir != 'iana'
    AND vp = 'rpki-validator.ripe.net'
);
select prefix, asn from rpki_by_allocation where prefix <<= '145.0.0.0/8' and type = 'S';
--- WHERE vp = 'rpki-validator.ripe.net' AND (type != 'S' or capture_ts = (SELECT min(capture_ts) from rpki_history WHERE vp = 'rpki-validator.ripe.net'))

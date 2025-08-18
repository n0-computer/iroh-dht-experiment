# Tests

Most tests are not really tests but just print out some network stats for you
to see if the result makes sense. So you need to run them with -- --nocapture

## Memory tests

just_bootstrap_1k: network stats with just 20 bootstrap nodes per node
perfect_routing_tables_1k
perfect_routing_tables_10k: init routing tables with all ids
no_routing_1k: shows perfect data distribution

self_and_random_lookup_strategy: self and random lookup combined, over time
self_lookup_strategy: self lookup strategy
random_lookup_strategy: random lookups, over time

remove_1k: disconnect 100 of 1000 nodes and see how routing tables change, gif
partition_1k: connect 100 of 1000 nodes and see how routing tables change, gif
random_vs_blended_1k: compares random vs blended strategy, gif

## Iroh tests

iroh_perfect_routing_tables_500: creates 500 iroh nodes with perfect routing tables and stores some values

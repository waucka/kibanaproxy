# kibanaproxy

Want to control access to log data in Elasticsearch but don't trust Shield?  Or maybe you just hate relying on proprietary software?  kibanaproxy to the rescue!

## What does it do?

It sits between Kibana and Elasticsearch and filters users' access to Elasticsearch based on a configurable HTTP header, which should be set by the reverse proxy in front of Kibana itself.

You will need a Redis server and some mechanism of adding stuff to it.  What stuff?  Stuff like this:

    > sadd patterns:$USERNAME $INDEX_PATTERN_1 $INDEX_PATTERN_2 $INDEX_PATTERN_3

## License

License is AGPLv3.

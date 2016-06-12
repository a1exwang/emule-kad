require_relative 'kad'
require_relative 'bt-dht/bt-dht'
require_relative 'api/api'

kad_client = KadClient.instance
dht = DHT::BTDigg.instance

Thread.new do
  kad_client.start_blocking
end
Thread.new do
  dht.start_blocking
end

# sleep(1)

Api.run!(host: 'localhost', port: 8223)

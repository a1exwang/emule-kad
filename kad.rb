require_relative 'utils'
require_relative 'prefs'
require_relative 'packet'
require_relative 'kad_id'
require_relative 'message_queue'

require 'socket'

Thread.abort_on_exception = true

LOG = Kademlia::Utils::Logger.new

class KadClient
  ##
  # add_contact(contact)
  # @param: contact, contact object or contact array
  def add_contact(contact)
    @contacts.each do |c|
      if c[:id] == contact[:id] || @prefs.kad_id == contact[:id]
        return
      end
    end
    @contacts << contact
  end

  def init_udp
    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, @prefs.kad_udp_port)
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(@prefs.mtu)
        _, remote_port, _, _remote_ip = addr
        remote_ip = Kademlia::Utils::IPAddress.new(_remote_ip)

        begin
          packet = Kademlia::Packet.new(self, data, @ip, @prefs.kad_id, remote_ip, remote_port)
          if @message_queue
            @message_queue << {
                name: packet.opcode.to_s,
                content: packet
            }
          end
          LOG.logt 'UDP thread', "received from #{addr[2]}:#{addr[1]}, kad opcode '#{packet.opcode}'"
        rescue Kademlia::Error::InvalidKadPacket => e
          puts e
        end
      end
    end
  end

  def initialize
    @prefs = Kademlia::Utils::Prefs.new
    @ip = KadClient.get_local_ip
    @contacts = []
    init_udp
  end

  def init_queue(q)
    @message_queue = q
  end

  def bootstrap_from_contacts
    find_node(@contacts, @prefs.kad_id)
  end

  def find_node_in_contacts(kad_id)
    find_node(@contacts, kad_id)
  end

  def search_keyword(keyword)
    @contacts.each do |node|
      begin
        bytes = Kademlia::Packet::Helpers.kad2_search_key_req(node[:ip], node[:id], keyword, 4)
        @udp_socket.send(bytes.pack('C*'), 0, node[:ip].to_s, node[:udp_port])
        LOG.logt 'search_keyword', "keyword '#{keyword}' id #{} to #{node[:ip]}:#{node[:udp_port]}"
      rescue Errno::EINVAL => e
        puts e
      end
    end
  end

  # get global ip address at local machine
  # return value: String. e.g. '1.1.1.1'
  def self.get_local_ip
    interface = `route | grep default`.split.last
    if `ifconfig #{interface}` =~ /inet addr:([.0-9]+)/i
      $1
    else
      raise RuntimeError, 'cannot get local ip'
    end
    # addrs = Socket.ip_address_list.reject { |x| ! x.ipv4? || x.ipv4_loopback? }
    # addrs.first.ip_address
  end

  ##
  # Wait for the kad client listeners
  def start
    @message_queue.start_blocking
  end

  def find_node(contacts, kad_id)
    contacts.each do |node|
      begin
        bytes = Kademlia::Packet::Helpers.kad2_req(0xb, node[:ip], node[:id], kad_id, node[:version])
        @udp_socket.send(bytes.pack('C*'),
                         0, node[:ip].to_s, node[:udp_port])
        LOG.logt 'find_node', "target '#{kad_id}' to #{node[:ip]}:#{node[:udp_port]}"
      rescue Errno::EINVAL => e
        puts e
      end
    end
  end

end

kad_client = KadClient.new

@contacts = Kademlia::Utils::Helpers.parse_nodes_dat('nodes.dat')
main = {
    id: Kademlia::KadID.from_kad_bytes('a5 21 f3 2d 63 9f a8 56 56 c6 3e c1 09 55 0f d6'.split.map {|x| x.to_i(16)}) ,
    ip: Kademlia::Utils::IPAddress.new(KadClient.get_local_ip),
    udp_port: 4672,
    tcp_port: 4662,
    version: 8,
    kad_udp_key: [0]*8,
    verified: 1
}
main2 = {
    id: Kademlia::KadID.from_kad_bytes('02 ae ee 01 e0 2a c6 05 a1 0b ce c8 90 20 d0 67'.split.map {|x| x.to_i(16)}),
    ip: Kademlia::Utils::IPAddress.new('192.168.199.5'),
    udp_port: 4672,
    tcp_port: 4662,
    version: 8,
    kad_udp_key: [0]*8,
    verified: 1
}

kad_client.add_contact(main2)

q = Kademlia::MessageQueue.new do |e|
  e.on('kad2_res') do |message|
    packet = message[:content]
    # LOG.logt('MessageQueue', 'kad2 res received')
    packet.content[:contacts].each do |c|
      kad_client.add_contact(c)
    end
  end
  e.on('timer') do
    kad_client.bootstrap_from_contacts
  end
  e.on('small_timer') do
    kad_client.search_keyword('abc')
  end
end

kad_client.init_queue(q)

Thread.new do
  loop do
    q << { name: 'timer' }
    sleep(10000)
  end
end

enc = OpenSSL::Digest::MD4.digest('abc').bytes
target_id = Kademlia::KadID.from_md4_bytes(enc)
Thread.new do
  3.times do
    kad_client.find_node_in_contacts(target_id)
    sleep 5
  end
  3.times do
    kad_client.search_keyword('abc')
    sleep 5
  end
  q << { name: 'small_timer' }
end

kad_client.start

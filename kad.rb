require_relative 'utils'
require_relative 'prefs'
require_relative 'packet'

require 'socket'
require 'pp'
require 'json'

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
        rescue Kademlia::Error::InvalidKadPacket => e
          puts e
        end

        if @message_queue
          @message_queue << {
              name: packet.opcode.to_s,
              content: packet
          }
        end

        LOG.logt 'UDP thread', "received from #{addr[2]}:#{addr[1]}, kad opcode '#{packet.opcode}'"
      end
    end
  end

  def init_prefs
    @prefs = Kademlia::Utils::Prefs.new
  end

  def initialize
    init_prefs
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

  # def keyword(w)
  #   @nodes.each do |node|
  #     begin
  #     @udp_socket.send(KadPacket::Helpers.kad2_keyword_req(node[:ip], node[:id], node[:version], w),
  #                      0, ip_to_s(node[:ip]), node[:udp_port])
  #     puts "keyword '#{w}' to #{ip_to_s node[:ip]}:#{node[:udp_port]}"
  #     rescue Exception => e
  #       puts e
  #     end
  #   end
  # end

  def find_node(contacts, kad_id)
    contacts.each do |node|
      begin
        puts node
        @udp_socket.send(Kademlia::Packet::Helpers.kad2_req(0xb, node[:ip], node[:id], kad_id, node[:version]),
                         0, node[:ip].to_s, node[:udp_port])
        LOG.logt 'find_node', "target '#{kad_id}' to #{node[:ip]}:#{node[:udp_port]}"
      rescue Errno::EINVAL => e
        puts e
      end
    end
  end

end

kad_client = KadClient.new

@nodes = Kademlia::Utils::Helpers.parse_nodes_dat('nodes.dat')
main = {
    id: Kademlia::Utils::KadID.new('a5 21 f3 2d 63 9f a8 56 56 c6 3e c1 09 55 0f d6'.split.map {|x| x.to_i(16)}) ,
    ip: Kademlia::Utils::IPAddress.new(KadClient.get_local_ip),
    udp_port: 4672,
    tcp_port: 4662,
    version: 8,
    kad_udp_key: [0]*8,
    verified: 1
}
main2 = {
    id: Kademlia::Utils::KadID.new('02 ae ee 01 e0 2a c6 05 a1 0b ce c8 90 20 d0 67'.split.map {|x| x.to_i(16)}),
    ip: Kademlia::Utils::IPAddress.new('192.168.199.5'),
    udp_port: 4672,
    tcp_port: 4662,
    version: 8,
    kad_udp_key: [0]*8,
    verified: 1
}

kad_client.add_contact(main2)

q = nil
q = Kademlia::Utils::MessageQueue.new do |e|
  e.on('kad2_res') do |message|
    packet = message[:content]
    LOG.logt('MessageQueue', 'kad2 res received')
    packet.content[:contacts].each do |c|
      kad_client.add_contact(c)
    end
  end
  e.on('timer') do
    kad_client.bootstrap_from_contacts
  end
end

kad_client.init_queue(q)

Thread.new do
  loop do
    q << { name: 'timer' }
    sleep(5)
  end
end

kad_client.start

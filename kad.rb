require 'socket'

class KadPacket
  module Packet
    def self.kad_bootstrap_req(id, tcp, version)
      [0xe4, 0x01, *id, tcp, version].pack('C18vC')
    end

    def self.kad_hello_req(id, tcp, version)
      [0xe4, 0x11, *id, tcp, version, 0].pack('C18vC2')
    end
  end

  KAD_PROTOCOL = 0xe4
  OPCODES = {
      0x01 => :kad2_bootstrap_req,
      0x09 => :kad2_bootstrap_res,
      0x11 => :kad2_hello_req,
      0x19 => :kad2_hello_res,
      0x21 => :kad2_req,
      0x22 => :kad2_hello_res_ack,
      0x29 => :kad2_res,
      0x33 => :kad2_search_key_req,
      0x34 => :kad2_search_source_req,
      0x35 => :kad2_search_notes_req,
      0x3b => :kad2_search_res,
      0x43 => :kad2_publish_key_req,
      0x44 => :kad2_publish_source_req,
      0x45 => :kad2_publish_notes_req,
      0x4b => :kad2_publish_res,
      0x4c => :kad2_publish_res_ack,
      0x53 => :kad_firewalled2_req,
      0x60 => :kad2_ping,
      0x61 => :kad2_pong,
      0x62 => :kad2_firewall_udp
  }

  def initialize(str)
    protocol, opc = str[0..1].unpack('C2')
    raise "Not a KAD packet #{str.bytes}" unless protocol == KAD_PROTOCOL
    @opcode = OPCODES[opc]
    raise "Unknown opcode #{@opcode}" unless @opcode
    @bytes = str[2..-1].unpack('C*')
    case @opcode
      when :kad2_bootstrap_res
      when :kad2_hello_res
        hello_res = parse_hello_res(@bytes)
        puts hello_res
    end
  end

  def parse_hello_res(bytes)
    {
        search_type: bytes[0].unpack('C').first,
        target_id: bytes[1, 16].unpack('C*'),
        contact_id: bytes[17, 16].unpack('C*')
    }
  end

  def to_s
    @opcode.to_s
  end

  def to_bytes
    @bytes
  end
end

class KadClient
  attr_reader :tcp_port, :udp_port, :mtu, :id
  def initialize(nodes, udp_port, tcp_port, mtu = 1500)
    @ip = get_local_ip
    @id = Array.new(16) { Random.rand(0...(2 << 8)) }
    def @id.to_s
      self.map { |x| sprintf '%02x', x }.join('')
    end
    @nodes = nodes
    @mtu = mtu
    @tcp_server = TCPServer.new(@ip, tcp_port)
    _, @tcp_port, _, _ = @tcp_server.addr
    @tcp_thread = Thread.new do
      loop do
        client = @tcp_server.accept
        data, addr = client.recvfrom
        puts "tcp: from #{addr[2]}:#{addr[1]}"
        client.close
      end
    end

    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, udp_port)
    _, @udp_port, _, _ = @udp_socket.addr
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(1500)
        packet = KadPacket.new(data)
        puts "#{addr[2]}:#{addr[1]}, packet: #{packet.to_s}"
      end
    end
  end

  def icmp_ping_nodes
    @nodes.each do |node|
      `nc -w 5 -uvz #{ip_to_s node[:ip]} #{node[:udp_port]}`
      puts $!
    end
  end
  def get_local_ip
    addrs = Socket.ip_address_list.reject { |x| ! x.ipv4? || x.ipv4_loopback? }
    addrs.first.ip_address
  end

  def join
    @udp_thread.join
    @tcp_thread.join
  end

  def bootstrap
    @nodes.each do |node|
      @udp_socket.send KadPacket::Packet.kad_bootstrap_req(@id, @tcp_port, node[:version]),
                       0, ip_to_s(node[:ip]), node[:udp_port]
    end
  end

  def hello
    @nodes.each do |node|
      begin
        @udp_socket.send KadPacket::Packet.kad_hello_req(@id, @tcp_port, node[:version]),
                         0, ip_to_s(node[:ip]), node[:udp_port]
        puts "hello to #{ip_to_s node[:ip]}:#{node[:udp_port]}"
      rescue Exception => e
        puts e
      end

    end
  end
end

def ip_to_s(ip)
  "#{(ip & 0xFF000000) >> 24}.#{(ip & 0xFF0000) >> 16}.#{(ip & 0xFF00) >> 8}.#{ip&0xFF}"
end
def ip_from_s(str)
  ip0, ip1, ip2, ip3 = str.split('.').map {|x| x.to_i}
  (ip0 << 24) + (ip1 << 16) + (ip2 << 8) + ip3
end

def node_to_s(node, i)

  sprintf "  %d   %d  %-15s %5d %5d %s %s\n",
          i,
          node[:version],
          ip_to_s(node[:ip]),
          node[:udp_port],
          node[:tcp_port],
          node[:kad_udp_key].map {|x| sprintf '%02x', x}.join(''),
          node[:verified]
end

def parse_nodes_dat(bytes)
  raise 'magic error' unless 0 == bytes[0...4].unpack('V').first
  version = bytes[4...8].unpack('V').first
  number_of_contacts = bytes[8...12].unpack('V').first
  #puts version: version, n: number_of_contacts
  nodes = []
  contact_size = 34
  #puts ' idx Ver IP address       udp   tcp  kadUDPKey        verified'
  number_of_contacts.times do |i|
    #puts i
    current_contact_index = (12 + i * contact_size)
    node = {
        id: bytes[current_contact_index, 16].unpack('C*'),
        ip: bytes[current_contact_index+16, 4].unpack('N').first,
        udp_port: bytes[current_contact_index+20, 2].unpack('v').first,
        tcp_port: bytes[current_contact_index+22, 2].unpack('v').first,
        version:  bytes[current_contact_index+24, 1].unpack('C').first,
        kad_udp_key: bytes[current_contact_index+25,8].unpack('C*'),
        verified: bytes[current_contact_index+33, 1].unpack('C').first
    }
    nodes << node
    # puts node_to_s node, i if i < 10
  end
  raise 'file size error' unless number_of_contacts*contact_size+12 == bytes.size
  nodes
end

UDP_PORT = 4672
TCP_PORT = 4662
open (ARGV[0] || 'nodes_cn.dat'), 'rb' do |f|
  @nodes = parse_nodes_dat f.read
end

kad_client = KadClient.new(@nodes, UDP_PORT, TCP_PORT)
#kad_client.bootstrap
#kad_client.icmp_ping_nodes
kad_client.hello
kad_client.join
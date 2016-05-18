require 'socket'
require 'rc4'
require 'digest/md5'
require 'openssl'
require 'pp'

LOCAL_KAD_UDP_KEY = 0x22334455
def get_udp_verify_key(ip)
  Digest::MD5.digest([ip, LOCAL_KAD_UDP_KEY].pack('VV')).
      unpack('VVVV').reduce(&:^) % 0xFFFFFFFE + 1
end

class KadPacket
  KAD_VERSION_NEED_ENCRYPTION = 6
  MAGIC_VALUE_UDP_SYNC_CLIENT = 0x395F2EC1

  module SearchType
    NODE = 0
    NODE_COMPLETE = 1
    FILE = 2
    KEYWORD = 3
    NOTES = 4
  end

  KAD_PROTOCOL = 0xe4
  OPCODE_NAME = {
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
  GET_OPCODE = OPCODE_NAME.invert

  ##
  # This module contains helper methods for encrypt and decrypt packets
  module Helpers

    ##
    # encrypt Kad packet by peer KadID(+kad_id+)
    # +kad_id+: Array, the receiver's KadID
    # +ip+:     Integer, is used to check the encryption
    # +raw_packet+: String, the raw packet to encrypt
    # return value: String, encrypted packet
    #
    # the encrypted packet is described as follow:
    # +00 uint8     semi_random_not_protocol_marker
    # +01 uint8[2]  salt, randomly generated locally
    # +03 RC4(key, data_to_encrypt)
    #
    # where as,
    #
    # key = MD5(+kad_id+ + +salt+)
    # data_to_encrypt = (all fields are little-endian)
    #   +00 uint32  MAGIC_VALUE_UDP_SYNC_CLIENT
    #   +04 uint8   padding_length
    #   +05 uint8[] random_padding (currently unused)
    #   +05 uint32  receiver_verify_key
    #   +09 uint32  sender_verify_key
    #   +0d uint8[] +raw_packet+
    #
    def self.encrypt_packet(ip, kad_id, raw_packet)
      salt = 0 #Random.rand(0...(2<<16))

      key = [*kad_id, salt].pack('C16v')
      receiver_verify_key = 0
      sender_verify_key = get_udp_verify_key(ip)

      # puts 'packet: ' + packet.unpack('C*').map {|x| x.to_s(16)}.join(' ')
      to_enc = [KadPacket::MAGIC_VALUE_UDP_SYNC_CLIENT,
                0,
                receiver_verify_key,
                sender_verify_key].pack('VCVV') + raw_packet
      # puts 'to enc: ' + to_enc.unpack('C*').map {|x| x.to_s(16)}.join(' ')

      # puts "key: #{key.unpack('C*').map {|x| x.to_s(16)}.join(' ')}"
      md5_key = Digest::MD5.digest(key)
      rc4 = RC4.new(md5_key)
      enc_data = rc4.encrypt(to_enc)

      [0x98, salt].pack('Cv') + enc_data
    end
    ##
    # decrypt packet, similar to encrypt_packet
    def self.decrypt_packet(_ip, id, packet)
      puts "dec key: #{id.map{|x|x.to_s(16)}.join(' ')}"
      raise 'not kad and receiver key packet' unless (packet & 3) == 2
      salt = packet[1..2]
      key = id + salt
      md5_key = Digest::MD5.digest(key.pack('C*'))
      dec_packet = RC4.new(md5_key).decrypt(packet[3..-1].pack('C*'))
      magic = dec_packet[0, 4].unpack('V').first
      printf "decrypt_packet: magic = %08x\n", magic
      if magic.pack('V') != KadPacket::MAGIC_VALUE_UDP_SYNC_CLIENT
        raise 'wrong magic'
      end
      _sender_verify = dec_packet[4, 4]
      _receiver_verify = dec_packet[8, 4]
      _padding = dec_packet[12]
      dec_packet[13..-1].bytes
    end

    def self.check_and_encrypt(ip, kad_id, raw_packet, version)
      return raw_packet if version < KadPacket::KAD_VERSION_NEED_ENCRYPTION

      self.encrypt_packet(ip, kad_id, raw_packet)
    end

    ##
    # kad2_bootstrap_req
    # packet:
    #   +00 uint8[3]    kad_header
    #   +03 uint8[16]   sender_id(+self_id+)
    #   +13 uint16      tcp_port(+tcp+)
    #   +15 uint8       +version+
    def self.kad2_bootstrap_req(self_id, tcp, ip, contact_id, version)
      kad_packet =(kad_header(:kad2_bootstrap_req) +
          self_id + [tcp, version]).pack('C18vC')
      check_and_encrypt(ip, contact_id, kad_packet, version)
    end

    ##
    # kad2_hello_req
    # packet:
    #   +00 uint8[3]    kad_header
    #   +03 uint8[16]   sender_id(+self_id+)
    #   +13 uint16      tcp_port(+tcp+)
    #   +15 uint8       +version+
    #   +16 uint8       0
    def self.kad2_hello_req(self_id, tcp, ip, contact_id, version)
      kad_packet = (kad_header(:kad2_hello_req) +
          self_id + [tcp, version, 0]).pack('C18vC2')
      check_and_encrypt(ip, contact_id, kad_packet, version)
    end

    ##
    # kad2_req
    # packet:
    #   +00 uint8[3]    kad_header
    #   +03 uint8       search_type(+type+)
    #   +04 uint8[16]   +target_id+
    #   +14 uint8[16]   sender_id(+self_id+)
    def self.kad2_req(type, self_id, ip, contact_id, target_id, version)
      kad_packet = (kad_header(:kad2_req) +
          [type, *target_id, *self_id]).pack('C*')
      check_and_encrypt(ip, contact_id, kad_packet, version)
    end

    ##
    # kad2_req by keyword
    # packet:
    # search_type = 3
    # target_id = MD4(UTF8(keyword))
    def self.kad2_keyword_req(self_id, ip, contact_id, version, keyword)
      target_id = OpenSSL::Digest::MD4.digest(keyword)
      self.kad2_req(KadPacket::SearchType::KEYWORD, self_id, ip, contact_id, target_id.bytes, version)
    end

    ##
    # kad_header
    #   +00 uint8 0xe4
    #   +01 uint8 opcode
    def self.kad_header(opcode_name)
      [KadPacket::KAD_PROTOCOL, KadPacket::GET_OPCODE[opcode_name]]
    end
  end


  def initialize(str, ip, id)
    raw_str = str
    protocol, opc = str[0..1].unpack('C2')
    if protocol != KAD_PROTOCOL
      puts protocol
      str = Helpers.decrypt_packet(ip, id, raw_str.bytes).pack('C*')
      protocol, opc = str[0..1].unpack('C2')

      raise "unknown protocol #{protocol}" unless protocol == KAD_PROTOCOL
    end

    @opcode = OPCODE_NAME[opc]
    raise "Unknown opcode #{@opcode}" unless @opcode
    @bytes = str[2..-1].unpack('C*')
    case @opcode
      when :kad2_bootstrap_res
      when :kad2_hello_res
        hello_res = parse_hello_res(@bytes)
        puts hello_res
      else
    end
  end

  def parse_hello_res(bytes)
    {
        id:       bytes[0, 16],
        tcp_port: bytes[16, 2].pack('C*').unpack('v').first,
        version:  bytes[18, 1].pack('C*').unpack('C').first
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
    @ip = KadClient.get_local_ip
    @id = Array.new(16) { Random.rand(0...(2 << 8)) }
    def @id.to_s
      self.map { |x| sprintf '%02x', x }.join('')
    end
    @nodes = nodes
    @mtu = mtu
    # @tcp_server = TCPServer.new(@ip, tcp_port)
    # _, @tcp_port, _, _ = @tcp_server.addr
    # @tcp_thread = Thread.new do
    #   loop do
    #     client = @tcp_server.accept
    #     _data, addr = client.recvfrom
    #     puts "tcp: from #{addr[2]}:#{addr[1]}"
    #     client.close
    #   end
    # end

    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, udp_port)
    _, @udp_port, _, _ = @udp_socket.addr
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(1500)
        begin
          packet = KadPacket.new(data, @ip, @id)
        rescue Exception => e
          puts e
          raise e
        end

        puts "#{addr[2]}:#{addr[1]}, packet: #{packet.to_s}"
      end
    end
  end

  def test_nodes
    @nodes.each do |node|
      `nc -w 5 -uvz #{ip_to_s node[:ip]} #{node[:udp_port]}`
      puts $!
    end
  end
  ##
  # get global ip address at local machine
  # return value: String. e.g. '1.1.1.1'
  def self.get_local_ip
    addrs = Socket.ip_address_list.reject { |x| ! x.ipv4? || x.ipv4_loopback? }
    addrs.first.ip_address
  end

  ##
  # Wait for the kad client listeners
  def join
    @udp_thread.join
    @tcp_thread.join if @tcp_thread
  end

  def bootstrap
    @nodes.each do |node|
      @udp_socket.send KadPacket::Helpers.kad2_bootstrap_req(@id, @tcp_port, node[:ip], node[:id], node[:version]),
                       0, ip_to_s(node[:ip]), node[:udp_port]
    end
  end

  def hello
    @nodes.each do |node|
      begin
        @udp_socket.send KadPacket::Helpers.kad2_hello_req(@id, @tcp_port, node[:ip], node[:id], node[:version]),
                         0, ip_to_s(node[:ip]), node[:udp_port]
        puts "hello to #{ip_to_s node[:ip]}:#{node[:udp_port]}"
      rescue Exception => e
        puts e
        raise e
      end
    end
  end

  def keyword(w)
    @nodes.each do |node|
      begin
      @udp_socket.send(KadPacket::Helpers.kad2_keyword_req(@id, node[:ip], node[:id], node[:version], w),
                       0, ip_to_s(node[:ip]), node[:udp_port])
      puts "keyword '#{w}' to #{ip_to_s node[:ip]}:#{node[:udp_port]}"
      rescue Exception => e
        puts e
      end

    end
  end

  def ping
    @nodes.each do |node|
      begin
        @udp_socket.send KadPacket::Helpers.kad_ping(@id, @tcp_port, node[:version]),
                         0, ip_to_s(node[:ip]), node[:udp_port]
        puts "hello to #{ip_to_s node[:ip]}:#{node[:udp_port]}"
      rescue Exception => e
        puts e
        raise e
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
  raise "nodes.dat version error: version: #{version}" if version != 2 && version != 3
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
    puts node_to_s node, i if i < 10
  end
  raise 'file size error' unless number_of_contacts*contact_size+12 == bytes.size
  nodes
end

UDP_PORT = 46720
TCP_PORT = 46620
open (ARGV[0] || 'nodes.dat'), 'rb' do |f|
  @nodes = parse_nodes_dat f.read
end
@nodes1 = [
    {
        id: 'a5 21 f3 2d 63 9f a8 56 56 c6 3e c1 09 55 0f d6'.split.map {|x| x.to_i(16)} ,
        ip: ip_from_s(KadClient.get_local_ip),
        udp_port: 4672,
        tcp_port: 4662,
        version: 8,
        kad_udp_key: [0]*8,
        verified: 1
    }
]

kad_client = KadClient.new(@nodes, UDP_PORT, TCP_PORT)
# kad_client.bootstrap
#kad_client.icmp_ping_nodes
loop do
  kad_client.hello
  kad_client.keyword('abc')
  sleep 100000#0.2
end

kad_client.join
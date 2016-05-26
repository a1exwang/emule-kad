require 'socket'
require 'rc4'
require 'digest/md5'
require 'openssl'
require 'pp'
require 'json'
require_relative 'utils'

LOCAL_KAD_UDP_KEY = 0x22334455
def get_udp_verify_key(ip)
  Digest::MD5.digest([ip, LOCAL_KAD_UDP_KEY].pack('VV')).unpack('VVVV').reduce(&:^) % 0xFFFFFFFE + 1
end

LOG = Kademlia::Utils::Logger.new

class KadPacket

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
    def self.encrypt_packet(random, ip, kad_id, raw_packet)
      salt = random#0 #Random.rand(0...(2<<16))

      key = kad_id.pack('C*') + [salt].pack('v')
      receiver_verify_key = 0
      sender_verify_key = get_udp_verify_key(ip.to_i)

      # puts 'packet: ' + packet.unpack('C*').map {|x| x.to_s(16)}.join(' ')
      to_enc = [Kademlia::Constants::MAGIC_VALUE_UDP_SYNC_CLIENT,
                0,
                receiver_verify_key,
                sender_verify_key].pack('VCVV') + raw_packet
      # puts 'to enc: ' + to_enc.unpack('C*').map {|x| x.to_s(16)}.join(' ')

      # puts "key: #{key.unpack('C*').map {|x| x.to_s(16)}.join(' ')}"
      md5_key = Digest::MD5.digest(key)
      rc4 = RC4.new(md5_key)
      enc_data = rc4.encrypt(to_enc)

      [0x0C, salt].pack('Cv') + enc_data
    end
    ##
    # decrypt packet, similar to encrypt_packet
    def self.decrypt_packet(ip, id, packet, remote_ip, remote_port)
      if (packet[0] & 3) == 0
        key_part = id
      elsif (packet[0] & 3) == 2
        key_part = [get_udp_verify_key(ip_from_s(remote_ip))].pack('V').bytes
      else
        raise 'not kad and receiver key packet'
      end
      salt = packet[1..2]
      key = key_part + salt
      puts "dec key: #{key.map{|x|x.to_s(16)}.join(' ')}"
      md5_key = Digest::MD5.digest(key.pack('C*'))
      dec_packet = RC4.new(md5_key).decrypt(packet[3..-1].pack('C*'))
      magic = dec_packet[0, 4].unpack('V').first
      printf "decrypt_packet: magic = %08x\n", magic
      if magic != Kademlia::Constants::MAGIC_VALUE_UDP_SYNC_CLIENT
        raise 'wrong magic'
      end
      _sender_verify = dec_packet[4, 4].unpack('V').first
      _receiver_verify = dec_packet[8, 4].unpack('V').first
      _padding = dec_packet[12].unpack('C').first
      puts 'sender verify: %08x, receiver verify: %08x, padding: %d' % [_sender_verify, _receiver_verify, _padding]
      dec_packet[13..-1].bytes
    end

    def self.check_and_encrypt(ip, kad_id, raw_packet, version)
      return raw_packet if version < Kademlia::Constants::KAD_VERSION_MIN_ENCRYPTION

      # Random.rand(0..65535)
      self.encrypt_packet(0, ip, kad_id, raw_packet)
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
    #   +03 uint8       max_required
    #   +04 uint8[16]   +target_id+
    #   +14 uint8[16]   sender_id(+self_id+)
    def self.kad2_req(max_required, ip, contact_id, target_id, version)
      kad_packet = (kad_header(:kad2_req) +
          [max_required, *target_id, *contact_id.array]).pack('C*')
      check_and_encrypt(ip, contact_id.array, kad_packet, version)
    end

    ##
    # kad2_req by keyword
    # packet:
    # search_type = 3
    # target_id = MD4(UTF8(keyword))
    def self.kad2_keyword_req(ip, contact_id, version, keyword)
      target_id = OpenSSL::Digest::MD4.digest(keyword)
      self.kad2_req(2, ip, contact_id, target_id.bytes, version)
    end

    ##
    # kad_header
    #   +00 uint8 0xe4
    #   +01 uint8 opcode
    def self.kad_header(opcode_name)
      [Kademlia::Constants::KAD_PROTOCOL, Kademlia::Constants::GET_OPCODE[opcode_name]]
    end
  end

  attr_reader :opcode, :packet, :bytes

  def initialize(kad_client, str, ip, id, remote_ip, remote_port)
    raw_str = str
    protocol, opc = str[0..1].unpack('C2')
    if protocol != Kademlia::Constants::KAD_PROTOCOL
      puts protocol
      str = Helpers.decrypt_packet(ip, id, raw_str.bytes, remote_ip, remote_port).pack('C*')
      protocol, opc = str[0..1].unpack('C2')

      raise Kademlia::Error::InvalidKadPacket, "unknown protocol #{protocol}" unless
          protocol == Kademlia::Constants::KAD_PROTOCOL
    end

    @opcode = Kademlia::Constants::OPCODE_NAME[opc]
    raise Kademlia::Error::InvalidKadPacket, "Unknown opcode #{@opcode}" unless @opcode
    @bytes = str[2..-1].unpack('C*')
    case @opcode
      when :kad2_bootstrap_res
      when :kad2_hello_res
        hello_res = parse_hello_res(@bytes)
        puts hello_res
      when :kad2_req
        puts 'kad2_req'
      when :kad2_res
        puts "kad2_res from #{ip}"
        count = @bytes[0x10]
        contacts = []
        def parse_contact(bytes)
          begin
            {
                id: Kademlia::Utils::KadID.new(bytes[0, 16]),
                ip: Kademlia::Utils::IPAddress.from_uint32_be_byte_array(bytes[16, 4]),
                udp_port: bytes[20] + (bytes[21] << 8),
                tcp_port: bytes[22] + (bytes[23] << 8),
                version: bytes[24]
            }
          rescue Exception => e
            puts e
          end
        end
        count.times do |i|
          contacts << parse_contact(@bytes[0x11 + 25 * i, 25])
        end
        @packet = {
            target_id: Kademlia::Utils::KadID.new(@bytes[0, 0x10]),
            count: count,
            contacts: contacts
        }
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
MY_FILE_NAME = 'kad.json'
class KadClient
  attr_reader :tcp_port, :udp_port, :mtu, :id

  ##
  # add_contact(contact)
  # @param: contact, contact object or contact array
  def add_contact(contact)
    @contacts.each do |c|
      if c[:id] == contact[:id] || @id == contact[:id]
        return
      end
    end
    @contacts << contact
  end

  def init_my_kad_id
    if File.exists?(MY_FILE_NAME) && (content = File.read(MY_FILE_NAME)).size > 0
      begin
        @id = JSON.parse(content)['kad']['id']
      rescue JSON::JSONError
        @id = nil
      end
    end
    if @id == nil
      @id = Array.new(16) { Random.rand(0...(1 << 8)) }
      json = { kad: { id: @id } }
      File.write(MY_FILE_NAME, json.to_json)
    end
  end

  def initialize(udp_port, mtu = 1500)
    init_my_kad_id
    @ip = KadClient.get_local_ip
    @contacts = []
    @mtu = mtu

    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, udp_port)
    _, @udp_port, _, _ = @udp_socket.addr
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(@mtu)
        _, remote_port, _, remote_ip = addr
        #begin
          packet = KadPacket.new(self, data, @ip, @id, remote_ip, remote_port)
        #rescue Exception => e
        #  puts e
        #  raise e
        #end

        LOG.logt 'UDP thread', "received from #{addr[2]}:#{addr[1]} #{packet.size} bytes"
      end
    end
  end

  def bootstrap_from_contacts
    find_node(@contacts, @id)
  end

  # def test_nodes
  #   @nodes.each do |node|
  #     `nc -w 5 -uvz #{ip_to_s node[:ip]} #{node[:udp_port]}`
  #     puts $!
  #   end
  # end
  ##
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
  def join
    @udp_thread.join
    #@tcp_thread.join if @tcp_thread
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
        @udp_socket.send(KadPacket::Helpers.kad2_req(0xb, node[:ip], node[:id], kad_id, node[:version]),
                         0, node[:ip].to_s, node[:udp_port])
        puts "find node id '#{kad_id}' to #{node[:ip]}:#{node[:udp_port]}"
      rescue Errno::EINVAL => e
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

UDP_PORT = 46720
TCP_PORT = 46620


kad_client = KadClient.new(UDP_PORT)

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
    ip: Kademlia::Utils::IPAddress.new('183.172.144.75'),
    udp_port: 4672,
    tcp_port: 4662,
    version: 8,
    kad_udp_key: [0]*8,
    verified: 1
}

@nodes.each do |node|
  kad_client.add_contact(node)
end
kad_client.add_contact(main2)
loop do
  kad_client.bootstrap_from_contacts
  sleep 5
end

kad_client.join

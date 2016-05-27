require 'rc4'
require 'digest/md5'
require 'openssl'
require 'zlib'

def ip_from_s(str)
  ip0, ip1, ip2, ip3 = str.split('.').map {|x| x.to_i}
  (ip0 << 24) + (ip1 << 16) + (ip2 << 8) + ip3
end

LOCAL_KAD_UDP_KEY = 0x22334455
def get_udp_verify_key(ip, local_kad_udp_key)
  Digest::MD5.digest([ip, local_kad_udp_key].pack('VV')).unpack('VVVV').reduce(&:^) % 0xFFFFFFFE + 1
end

module Kademlia
  class Packet

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
        sender_verify_key = get_udp_verify_key(ip.to_i, LOCAL_KAD_UDP_KEY)

        # puts 'packet: ' + packet.unpack('C*').map {|x| x.to_s(16)}.join(' ')
        to_enc = [Kademlia::Constants::MAGIC_VALUE_UDP_SYNC_CLIENT,
                  0,
                  receiver_verify_key,
                  sender_verify_key,
                  *raw_packet].pack('VCVVC*')
        # puts 'to enc: ' + to_enc.unpack('C*').map {|x| x.to_s(16)}.join(' ')

        # puts "key: #{key.unpack('C*').map {|x| x.to_s(16)}.join(' ')}"
        md5_key = Digest::MD5.digest(key)
        rc4 = RC4.new(md5_key)
        enc_data = rc4.encrypt(to_enc)

        ([0x0C, salt].pack('Cv') + enc_data).bytes
      end

      ##
      # decrypt packet, similar to encrypt_packet
      def self.decrypt_packet(ip, id, packet, remote_ip, remote_port)
        if (packet[0] & 3) == 0
          key_part = id
        elsif (packet[0] & 3) == 2
          key_part = [get_udp_verify_key(remote_ip.to_i, LOCAL_KAD_UDP_KEY)].pack('V').bytes
        else
          raise 'not kad and receiver key packet'
        end
        salt = packet[1..2]
        key = key_part + salt
        LOG.logt 'decrypt_packet', "dec key = #{key.map{|x|x.to_s(16)}.join(' ')}"
        md5_key = Digest::MD5.digest(key.pack('C*'))
        dec_packet = RC4.new(md5_key).decrypt(packet[3..-1].pack('C*'))
        magic = dec_packet[0, 4].unpack('V').first
        # LOG.logt 'decrypt_packet', "magic = %08x\n" % magic
        if magic != Kademlia::Constants::MAGIC_VALUE_UDP_SYNC_CLIENT
          raise 'wrong magic'
        end
        _sender_verify = dec_packet[4, 4].unpack('V').first
        _receiver_verify = dec_packet[8, 4].unpack('V').first
        _padding = dec_packet[12].unpack('C').first
        # LOG.logt 'decrypt_packet', "sender verify: %08x\nreceiver verify: %08x\npadding: %d" % [_sender_verify, _receiver_verify, _padding]
        dec_packet[13..-1].bytes
      end

      def self.check_and_decrypt(ip, id, packet, remote_ip, remote_port)
        protocol = packet[0]
        if Kademlia::Constants::ALL_PROTOCOL_HEADERS.include?(protocol)
          packet
        else
          decrypt_packet(ip, id, packet, remote_ip, remote_port)
        end
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
            self_id + [tcp, version]).pack('C18vC').unpack('C*')
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
            self_id + [tcp, version, 0]).pack('C18vC2').unpack('C*')
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
        kad_packet = kad_header(:kad2_req) +
            [max_required, *target_id.kad_bytes, *contact_id.kad_bytes]
        check_and_encrypt(ip, contact_id.kad_bytes, kad_packet, version)
      end

      def self.kad2_search_key_req(ip, contact_id, keyword, version)
        enc = OpenSSL::Digest::MD4.digest(keyword).bytes
        target_id = KadID.from_md4_bytes(enc)
        kad_packet = kad_header(:kad2_search_key_req) +
            target_id.kad_bytes + [0x00, 0x80] +
            [1] + [keyword.bytes.size].pack('v').unpack('C*') +
            keyword.bytes
        logt 'kad2_search_key_req', "keyword: '#{keyword}', id: '#{target_id.to_s}'"
        check_and_encrypt(ip, contact_id.kad_bytes, kad_packet, version)
      end

      # ##
      # # kad2_req by keyword
      # # packet:
      # # search_type = 3
      # # target_id = MD4(UTF8(keyword))
      # def self.kad2_keyword_req(ip, contact_id, version, keyword)
      #   target_id = OpenSSL::Digest::MD4.digest(keyword)
      #   self.kad2_req(2, ip, contact_id, target_id.bytes, version)
      # end

      ##
      # kad_header
      #   +00 uint8 0xe4
      #   +01 uint8 opcode
      def self.kad_header(opcode_name)
        [Constants::KAD_PROTOCOL, Constants::GET_OPCODE[opcode_name]]
      end
    end

    attr_reader :opcode, :content, :bytes

    def initialize(kad_client, str, ip, id, remote_ip, remote_port)
      decrypted_bytes = Helpers.check_and_decrypt(ip, id, str.bytes, remote_ip, remote_port)
      protocol, opc = decrypted_bytes[0..1]
      content_bytes = decrypted_bytes[2..-1]

      if protocol == Constants::KAD_PACKED_PROTOCOL
        protocol = Constants::KAD_PROTOCOL
        content_bytes = Zlib::Inflate.inflate(content_bytes.pack('C*')).bytes
      elsif protocol == Constants::KAD_PROTOCOL
        # do nothing
      else
        raise Error::InvalidKadPacket, "unknown protocol byte #{protocol}"
      end

      @opcode = Constants::OPCODE_NAME[opc]
      raise Error::InvalidKadPacket, "Unknown opcode #{@opcode}" unless @opcode
      @bytes = content_bytes
      case @opcode
        when :kad2_res
          # puts "kad2_res from #{ip}"
          count = @bytes[0x10]
          contacts = []
          def parse_contact(bytes)
            begin
              {
                  id: KadID.from_kad_bytes(bytes[0, 16]),
                  ip: Utils::IPAddress.from_uint32_le_byte_array(bytes[16, 4]),
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
          @content = {
              target_id: KadID.from_kad_bytes(@bytes[0, 0x10]),
              count: count,
              contacts: contacts
          }
        when :kad2_search_res
          logt 'UDP thread', '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!kad2_research_res'
          File.write('content.txt', @bytes.pack('C*'))
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

    def to_bytes
      @bytes
    end
  end

end
require_relative 'contact'
require_relative 'kad_id'
require 'time'

module Kademlia
  module Error
    InvalidKadPacket = Class.new Exception

  end
  module Constants
    KAD_VERSION_MIN_ENCRYPTION = 6
    MAGIC_VALUE_UDP_SYNC_CLIENT = 0x395F2EC1

    module SearchType
      NODE = 0
      NODE_COMPLETE = 1
      FILE = 2
      KEYWORD = 3
      NOTES = 4
    end

    EDONKEY_PROTOCOL = 0xe3
    EDONKEY_PACKET_PROTOCOL = 0xd4
    EMULE_PROTOCOL = 0xc5
    UDP_RESERVED1_PROTOCOL = 0xa3
    UDP_RESERVED2_PROTOCOL = 0xb2
    KAD_PROTOCOL = 0xe4
    KAD_PACKED_PROTOCOL = 0xe5
    ED2K_V2_HEADER = 0xf4
    ED2K_V2_PACKET_PROTOCOL = 0xf5
    MLDONKEY_PROTOCOL = 0x00

    ALL_PROTOCOL_HEADERS = [
        EDONKEY_PROTOCOL,
        EDONKEY_PACKET_PROTOCOL,
        EMULE_PROTOCOL,
        UDP_RESERVED1_PROTOCOL,
        UDP_RESERVED2_PROTOCOL,
        KAD_PROTOCOL,
        KAD_PACKED_PROTOCOL,
        ED2K_V2_HEADER,
        ED2K_V2_PACKET_PROTOCOL,
        MLDONKEY_PROTOCOL
    ]

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
  end
  module Utils
    class Logger
      TAG_MAX_WIDTH = 16
      def initialize(target = nil, attr = 'w')
        if target.is_a?(String)
          @stream = File.open(target, attr)
        else
          @stream = STDOUT
        end
        level_map = {
            verbose: 'V',
            normal:  'N',
            debug:   'D'
        }
        # this is default formatter
        set_format do |tag, str, indent, level|
          lines = str.split("\n")
          result = ''
          lines.each_with_index do |line, index|
            # -V timestamp tag indent*' ' str
            result += "-%s %s %-#{TAG_MAX_WIDTH}s%-#{indent+4 + (index == 0 ? 0 : 2)}s%s\n" %
                [level_map[level],
                 Time.now.strftime('%H:%M:%S.%6N'),
                 tag[0, TAG_MAX_WIDTH],
                 '', # indent
                 line]
          end
          result
        end
      end
      def set_format(&block)
        raise ArgumentError unless block
        @formatter = block
      end
      def log(str, indent = 0, level = 'verbose'.to_sym)
        raise ArgumentError unless indent.is_a?(Integer) && (level.is_a?(String) || level.is_a?(Symbol))
        logt('', str, indent, level)
      end
      def logt(tag, str, indent = 0, level = 'verbose'.to_sym)
        str = @formatter.call(tag, str, indent, level)
        @stream.write(str)
        @stream.flush
      end
    end
    class IPAddress
      attr_reader :str

      ##
      # initialize with IPv4 string
      # @param: str string like '1.1.1.1'
      def initialize(str)
        @str = str
        if str.is_a?(String)
          @numbers = []
          str.split('.').each do |x|
            n = x.to_i
            raise ArgumentError, 'invalid IP format' unless n >= 0 && n < 256
            @numbers << n
          end
          raise ArgumentError, 'invalid IP format' unless @numbers.size == 4
        else
          raise ArgumentError, 'must init with an IP addr string'
        end
      end

      def to_s
        @str
      end
      def to_json(state = nil)
        '"' + to_s + '"'
      end

      def ==(other)
        to_s == other.to_s
      end

      def self.from_uint32_be_byte_array(arr)
        new(arr.map { |x| x.to_s }.join('.'))
      end
      def self.from_uint32_le_byte_array(arr)
        new(arr.reverse.map { |x| x.to_s }.join('.'))
      end

      def to_i
        (@numbers[0] << 24) + (@numbers[1] << 16) + (@numbers[2] << 8) + (@numbers[3] << 0)
      end

      def to_bytes_be
        @numbers
      end

      def to_bytes_le
        @numbers.reverse
      end

    end

    module BinaryBuilder
      class MyObject
        @fields = []
      end
      def at(offset, type, name, value, &block)

      end
      def self.build

      end

      private
      def self.build_array(offset, element_type, element_count)

      end
    end

    module BinaryParser

      class MyObject
        attr_accessor :fields
        def initialize
          @fields = []
        end
        def at(offset, type, name, constraints = nil, &block)
          @fields << [offset, type, name, constraints, block]
        end
      end

      ##
      # parse a binary file or bytes
      # @param data: file name or byte array
      # @param block: binary format
      #
      # examples
      #   parse do |field|
      #     field.at offset, type, name, constraints
      #     field.at offset, :struct, name, constraints do |inner_field|
      #       inner_field.at relative_offset, type, name, constraints
      #     end
      #     field.at offset, [:array, 100, :struct], name, constraints do |inner_field|
      #       inner_field.at relative_offset, type, name, constraints
      #     end
      #     field.at offset, [:array, :previous_integer_name, :uint8], name, constraints
      #
      #   +type+ can be
      #     uint8, uint16, uint32, default to little-endian
      #     struct, [:array, size, type]
      #
      #   +constraints+ can be
      #     :map, use the block to map the value into another one
      #     [1,2], the value must be in these values
      def self.parse(data, &block)
        if data.is_a?(String)
          bytes = File.read(data).bytes
        elsif data.is_a?(Array)
          bytes = data
        else
          raise ArgumentError
        end
        struct, _size = parse_struct({}, 'file root', bytes, 0, block)
        struct
      end

      private

      def self.parse_struct(parent, struct_name, bytes, offset, block)
        raise ArgumentError, "struct '#{struct_name}' must have a block" unless block

        my_obj = MyObject.new
        block.call(my_obj)
        ret = {}
        total_size = 0
        my_obj.fields.each do |off, type, name, constraints, blk|
          ret[name], size = parse_item(ret, name, bytes, offset + off, type, constraints, blk)
          total_size += size
        end
        [ret, total_size]
      end

      def self.parse_array(parent, array_name, bytes, offset, element_type, element_count, constraints, block)
        ret = []
        if element_count.is_a?(Symbol)
          element_count = parent[element_count]
        end

        item_size = 0

        element_count.times do |i|
          item, item_size = parse_item(parent, "#{array_name}[#{i}]", bytes, offset + i * item_size, element_type, constraints, block)
          ret << item
        end

        [ret, element_count * item_size]
      end

      def self.parse_item(parent, name, bytes, offset, type, constraints, block)
        # puts "#{name}, #{offset}"
        if constraints.is_a?(Symbol)
          case constraints
            when :reject
              item, item_size = parse_item(parent, name, bytes, offset, type, nil, nil)
              return block.call(item) ? nil : [item, item_size]
            when :map
              item, item_size = parse_item(parent, name, bytes, offset, type, nil, nil)
              return [block.call(item), item_size]
            when nil
            else
              raise ArgumentError, 'format error'
          end
        end

        is_struct = false
        if type.is_a? Array
          if type[0] == :array
            element_size, element_type = type[1..2]
            is_struct = element_type == :struct
            value, total_size = parse_array(parent, name, bytes, offset, element_type, element_size, constraints, block)
          else
            raise ArgumentError
          end
        else
          value, total_size =
              case type
                when :struct
                  is_struct = true
                  parse_struct(parent, name, bytes, offset, block)
                when :uint8
                  [bytes[offset], 1]
                when :uint16
                  [bytes[offset] + (bytes[offset + 1] << 8), 2]
                when :uint32
                  [bytes[offset, 4].pack('C*').unpack('V').first, 4]
                else
                  raise ArgumentError
              end
        end

        if constraints && !constraints.is_a?(Symbol) && !constraints.include?(value)
          raise "file format error: field #{name}, #{constraints} does not include #{value}"
        end
        if !(constraints.is_a?(Symbol)) && !is_struct && block && !block.call(value)
          raise "file format error: field #{name}, #{value} is illegal"
        end

        [value, total_size]
      end
    end

    module Helpers
      def self.parse_nodes_dat(bytes)
        nodes_dat = Kademlia::Utils::BinaryParser.parse(bytes) do |field|
          field.at +0x00, :uint32, :magic, [0]
          field.at +0x04, :uint32, :version
          field.at(+0x08, :uint32, :num_of_contacts)
          field.at +0x0c, [:array, :num_of_contacts, :struct], :contacts do |inner_field|
            inner_field.at +0x00, [:array, 16, :uint8], :id, :map do |id|
              Kademlia::KadID.from_kad_bytes(id)
            end
            inner_field.at +0x10, [:array, 4, :uint8], :ip, :map do |ip|
              Kademlia::Utils::IPAddress.from_uint32_le_byte_array(ip)
            end
            inner_field.at +0x14, :uint16, :udp_port
            inner_field.at +0x16, :uint16, :tcp_port
            inner_field.at +0x18, :uint8,  :version
            inner_field.at +0x19, [:array, 8, :uint8], :kad_udp_key
            inner_field.at +0x21, :uint8,  :verified
          end
        end
        ret = []
        nodes_dat[:contacts].each do |c|
          ret << Kademlia::Contact.new(c[:id], c[:ip], c[:udp_port], c[:tcp_port], c[:kad_udp_key], c[:version]) if c[:verified] != 0
        end
        ret
      end
    end
  end
end

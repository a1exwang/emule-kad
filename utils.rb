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
  end
  module Utils
    class MessageQueue
      module Error
        UnknownMessageError = Class.new(Exception)
        UnHandledMessageError = Class.new(Exception)
      end
      ##
      # create a message queue and set handlers with block
      # @param block
      #
      # examples:
      #   MessageQueue.new do |handler|
      #     handler.on_req(lambda) do |m|
      #       # do something
      #     end
      #     handler.on(name) do |m|
      #       # do something
      #     end
      #     handler.on(name, lambda) do |m|
      #     end
      def initialize(&block)
        @queue = Queue.new
        obj = MyObject.new
        block.call(obj)
        @handlers = obj.message_handlers
      end

      # message = { name: 'a', filter: , handler:, ... }
      def <<(message)
        @queue << message
      end

      def start_blocking
        loop do
          message = @queue.pop
          name = message[:name]
          if @handlers[name]
            handled = false
            @handlers[name].each do |handler|
              if !handler[:filter] || handler[:filter].call(message)
                handler[:handler].call(message)
                handled = true
                break
              end
            end
            raise UnHandledMessageError, "message #{message}" unless handled
          else
            raise UnknownMessageError, "message name: #{name}"
          end
        end
      end

      private
      class MyObject
        attr_reader :message_handlers
        def initialize
          @message_handlers = Hash.new { Array.new }
        end
        def on(name, lambda, &block)
          @message_handlers[name] << { filter: lambda, handler: block }
        end
        def method_missing(name, *params, &block)
          if name.to_s =~ /on_(.+)$/
            message_name = $1
            on(message_name, *params, &block)
          else
            super
          end
        end
      end
    end

    class Logger
      def initialize(target = nil, attr = 'w')
        if target.is_a?(String)
          @stream = File.open(target, attr)
        else
          @stream = STDOUT
        end
        # this is default formatter
        set_format do |str, level|
          lines = str.split("\n")
          lines.each do |line|
            '%s %s %s' %
                [level.to_s, Time.now.strftime('%H:%M:%S.%6N'), line]
          end
        end
      end
      def set_format(&block)
        raise ArgumentError unless block
        @formatter = block
      end
      def log(str, level = 'verbose'.to_sym)
        str = @formatter.call(str, level)
        @stream.write(str)
        @stream.flush
      end
      def logt(tag, str, level = 'verbose'.to_sym)
        str = @formatter.call(str, level)
        @stream.write("#{tag} #{str}")
        @stream.flush
      end
    end
    class IPAddress
      attr_reader :str

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

    class KadID
      attr_reader :array
      def initialize(arr)
        if arr.is_a?(Array) && arr.size == 16
          arr.each do |x|
            raise ArgumentError, 'invalid uint8 array' unless x >= 0 && x < 256
          end
          @array = arr
        else
          raise ArgumentError, 'parameter must be an uint8 array'
        end
      end

      def ==(other)
        self.array == other.array
      end

      def to_s
        @array.map { |x| '%02x ' % x }.join(' ')
      end
    end

    class Node
      attr_reader :id, :ip, :udp_port, :tcp_port, :udp_key, :version
      def initialize(id, ip, udp_port, tcp_port, udp_key, version)
        @id = id
        @ip = ip
        @udp_port = udp_port
        @tcp_port = tcp_port
        @udp_key = udp_key
        @version = version
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
              Kademlia::Utils::KadID.new(id)
            end
            inner_field.at +0x10, [:array, 4,  :uint8], :ip, :map do |ip|
              Kademlia::Utils::IPAddress.from_uint32_le_byte_array(ip)
            end
            inner_field.at +0x14, :uint16, :udp_port
            inner_field.at +0x16, :uint16, :tcp_port
            inner_field.at +0x18, :uint8,  :version
            inner_field.at +0x19, [:array, 8, :uint8], :kad_udp_key
            inner_field.at +0x21, :uint8,  :verified
          end
        end
        nodes_dat[:contacts]
      end
    end
  end
end
